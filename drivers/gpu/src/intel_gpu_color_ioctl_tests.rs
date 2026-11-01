//! Decoded UAPI -> owned production FIFO -> real Device/Guard/CSC IO path.
//! Only PCI/power and the native register clock are substituted.
use super::*;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_kms::{tests::MockPlatform, Device};
use narf_filesystem::DrmFence;

struct Worker {
    device: Arc<Device<MockPlatform>>,
}
impl queue::Worker for Worker {
    fn lost(&self) -> bool {
        self.device.reset_lost()
    }
    fn epoch(&self) -> u64 {
        1
    }
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        _epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        Box::pin(async move {
            let mut session = self.device.session().await?;
            execute_plan(&mut session, mode, open, plan, reservation).await
        })
    }
}
fn color_mode() -> ModeState {
    let mode = mode();
    {
        let mut card = mode.lock();
        card.intel_ctm = true;
        card.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    mode
}
fn blob(mode: &ModeState) -> u32 {
    let coefficients: [u64; 9] = [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];
    mode.lock()
        .create_property_blob(coefficients.iter().flat_map(|c| c.to_le_bytes()).collect())
        .unwrap()
}
fn request(cpu: &Cpu, id: u32, flags: u32) {
    let mut header = [0; 56];
    header[0..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    header[8..16].copy_from_slice(&128u64.to_le_bytes());
    header[16..24].copy_from_slice(&144u64.to_le_bytes());
    header[24..32].copy_from_slice(&160u64.to_le_bytes());
    header[32..40].copy_from_slice(&192u64.to_le_bytes());
    header[48..56].copy_from_slice(&0xc7c7u64.to_le_bytes());
    cpu.write(64, &header).unwrap();
    cpu.write(128, &1u32.to_le_bytes()).unwrap();
    cpu.write(144, &2u32.to_le_bytes()).unwrap();
    cpu.write(160, &CRTC_CTM_PROP_ID.to_le_bytes()).unwrap();
    cpu.write(164, &CRTC_OUT_FENCE_PTR_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(192, &u64::from(id).to_le_bytes()).unwrap();
    cpu.write(200, &512u64.to_le_bytes()).unwrap();
}
fn submit(queue: &queue::Queue, cpu: &Cpu, events: &Events) -> Arc<queue::Completion> {
    let mut future = Box::pin(admit(
        queue,
        7,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        64,
        cpu,
        Some(events),
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        },
        1,
    ));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(Some((completion, _, true)))) => completion,
        _ => panic!("NONBLOCK foreground admission waited for CSC hardware"),
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..128 {
        if let Poll::Ready(output) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return output;
        }
    }
    panic!("production color worker did not finish")
}
fn smoke_intel_ctm_uapi_nonblock_blob_pin_and_native_latch_completion() -> TestResult {
    let mode = color_mode();
    let id = blob(&mode);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, id, NONBLOCK | EVENT);
    let completion = submit(&queue, &cpu, &events);
    assert_eq!(&cpu.bytes.lock()[512..516], &41i32.to_le_bytes());
    let fence = cpu.exported.lock()[0].clone();
    assert_eq!(fence.status(), 0);
    drop(cpu); // no retained user context or nested UAPI pointer
    assert!(mode.lock().destroy_property_blob(id));
    assert!(mode.lock().property_blob(id).is_some()); // queued reference
    let platform = MockPlatform::new();
    let device = Arc::new(platform.meteor());
    let mut worker = Worker {
        device: device.clone(),
    };
    let mut future = Box::pin(queue.run(&mut worker));
    assert!(future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 31);
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
    assert_eq!(completion.status(), 0);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    run(future);
    assert_eq!(completion.status(), 1);
    assert_eq!(fence.timestamp_ns(), Some(251000));
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, id);
    assert!(mode.lock().property_blob(id).is_some()); // committed reference
    let mut event = [0; 32];
    assert_eq!(
        events.lock().read_deliverable_event(u64::MAX, &mut event),
        Some(32)
    );
    assert_eq!(u32::from_le_bytes(event[24..28].try_into().unwrap()), 41);
    assert_eq!(u64::from_le_bytes(event[8..16].try_into().unwrap()), 0xc7c7);
    // Explicit clear is another actual queued color arm. It retires the
    // destroyed blob only after baseline CSC restoration has been witnessed.
    let cpu = Cpu::new();
    request(&cpu, 0, NONBLOCK);
    let cleared = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(cleared.status(), 1);
    assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
    assert!(mode.lock().property_blob(id).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_ctm_uapi_nonblock_blob_pin_and_native_latch_completion
);
fn smoke_intel_ctm_fifo_projects_color_and_close_restores_without_success() -> TestResult {
    for closed in [false, true] {
        let mode = color_mode();
        let a = blob(&mode);
        let b = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        request(&cpu, a, NONBLOCK | EVENT);
        let first = submit(&queue, &cpu, &events);
        request(&cpu, b, NONBLOCK | EVENT);
        let second = submit(&queue, &cpu, &events);
        mode.lock().destroy_property_blob(a);
        mode.lock().destroy_property_blob(b);
        let platform = MockPlatform::new();
        let device = Arc::new(platform.meteor());
        let mut worker = Worker {
            device: device.clone(),
        };
        let mut future = Box::pin(queue.run(&mut worker));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        if closed {
            events.lock().close();
            mode.lock().master_release(7);
        }
        run(future);
        assert_eq!(first.status() > 0, !closed);
        assert_eq!(second.status() > 0, !closed);
        assert_eq!(
            mode.lock().crtc_color(1).unwrap().ctm,
            if closed { 0 } else { b }
        );
        if closed {
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
            assert!(
                mode.lock().property_blob(a).is_none() && mode.lock().property_blob(b).is_none()
            );
            assert!(events.lock().ensure_flip_event_space(128).is_ok());
        } else {
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 31);
            let mut session = run(device.session()).unwrap();
            run(session.restore_console()).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_ctm_fifo_projects_color_and_close_restores_without_success
);
fn smoke_intel_ctm_advertisement_test_only_and_combined_updates_refuse() -> TestResult {
    let mode = color_mode();
    let id = blob(&mode);
    assert_eq!(
        crtc_color_properties(&mode.lock(), 1),
        (vec![CRTC_CTM_PROP_ID], vec![0])
    );
    let mut change = CrtcColorChange::default();
    assert_eq!(
        crtc_color_property(&mode.lock(), 1, CRTC_GAMMA_LUT_PROP_ID, 0, &mut change),
        Err(FsError::Unsupported)
    );
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, id, NONBLOCK | TEST_ONLY);
    assert!(matches!(
        run(admit(
            &queue,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1
        )),
        Ok(None)
    ));
    assert!(cpu.exported.lock().is_empty());
    for property in [
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_X_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
    ] {
        let request = Request::Atomic(OwnedAtomic {
            flags: NONBLOCK,
            cookie: 0,
            objects: vec![1, PLANE_ID_BASE],
            counts: vec![1, 1],
            props: vec![CRTC_CTM_PROP_ID, property],
            values: vec![u64::from(id), 0],
        });
        assert!(matches!(
            Plan::stage(
                &mode.lock(),
                request,
                Geometry {
                    width: 64,
                    height: 32,
                    pitch: 256
                }
            ),
            Err(FsError::Unsupported)
        ));
    }
    // No TEST_ONLY lease remains; destroying the unused blob really collects.
    assert!(mode.lock().destroy_property_blob(id));
    assert!(mode.lock().property_blob(id).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_ctm_advertisement_test_only_and_combined_updates_refuse
);

fn smoke_intel_ctm_uapi_inherited_refusal_and_reset_loss_fail_native_fence() -> TestResult {
    for reset in [false, true] {
        let mode = color_mode();
        let id = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        request(&cpu, id, NONBLOCK | EVENT);
        let completion = submit(&queue, &cpu, &events);
        mode.lock().destroy_property_blob(id);
        let platform = MockPlatform::new();
        let device = Arc::new(platform.meteor());
        if !reset {
            platform.set(crate::intel_gpu_color::MODE, 1 << 30);
        }
        let mut worker = Worker {
            device: device.clone(),
        };
        let mut future = Box::pin(queue.run(&mut worker));
        if reset {
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            platform.poison();
        }
        run(future);
        assert!(completion.status() < 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
        assert!(mode.lock().property_blob(id).is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
        if reset {
            assert!(run(device.session()).is_err());
            assert!(device.legacy().is_err());
        } else {
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 30);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_ctm_uapi_inherited_refusal_and_reset_loss_fail_native_fence
);

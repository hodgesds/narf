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
        card.intel_display = true;
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
        (
            vec![
                CRTC_CTM_PROP_ID,
                CRTC_GAMMA_LUT_PROP_ID,
                CRTC_GAMMA_LUT_SIZE_PROP_ID
            ],
            vec![0, 0, 1024]
        )
    );
    let mut change = CrtcColorChange::default();
    assert_eq!(
        crtc_color_property(&mode.lock(), 1, CRTC_GAMMA_LUT_PROP_ID, 0, &mut change),
        Ok(true)
    );
    assert_eq!(change.gamma_lut, Some(0));
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

fn gamma_blob(mode: &ModeState, reverse: bool) -> u32 {
    let bytes: Vec<u8> = (0..1024u32)
        .flat_map(|i| {
            let v = ((if reverse { 1023 - i } else { i }) * 65535 / 1023) as u16;
            [v.to_le_bytes(), v.to_le_bytes(), v.to_le_bytes(), [0, 0]].concat()
        })
        .collect();
    mode.lock().create_property_blob(bytes).unwrap()
}
fn gamma_request(cpu: &Cpu, id: u32, flags: u32) {
    request(cpu, id, flags);
    cpu.write(160, &CRTC_GAMMA_LUT_PROP_ID.to_le_bytes())
        .unwrap();
}
fn smoke_intel_gamma_uapi_nonblock_pin_latch_and_same_lut_ctm_preservation() -> TestResult {
    let mode = color_mode();
    let gamma = gamma_blob(&mode, false);
    let ctm = blob(&mode);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    gamma_request(&cpu, gamma, NONBLOCK | EVENT);
    let completion = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    assert_eq!(fence.status(), 0);
    assert!(mode.lock().destroy_property_blob(gamma));
    drop(cpu);
    let platform = MockPlatform::new();
    let device = Arc::new(platform.meteor());
    let mut worker = Worker {
        device: device.clone(),
    };
    let mut work = Box::pin(queue.run(&mut worker));
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(platform.palette_writes(), 1024);
    assert_eq!(
        platform.read32(crate::intel_gpu_color::GAMMA),
        (1 << 30) | 1
    );
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
    assert_eq!(fence.status(), 0);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    run(work);
    assert_eq!(completion.status(), 1);
    assert_eq!(fence.timestamp_ns(), Some(251000));
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    let mut event = [0; 32];
    assert_eq!(
        events.lock().read_deliverable_event(u64::MAX, &mut event),
        Some(32)
    );
    assert_eq!(u32::from_le_bytes(event[24..28].try_into().unwrap()), 41);
    let cpu = Cpu::new();
    request(&cpu, ctm, NONBLOCK);
    let changed = submit(&queue, &cpu, &events);
    mode.lock().destroy_property_blob(ctm);
    run(queue.run(&mut worker));
    assert_eq!(changed.status(), 1);
    assert_eq!(platform.palette_writes(), 1024);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    let mut session = run(device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(platform.palette_writes(), 2048);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gamma_uapi_nonblock_pin_latch_and_same_lut_ctm_preservation
);

fn smoke_intel_gamma_projected_dsb_replacement_and_explicit_disable_transition() -> TestResult {
    let mode = color_mode();
    let first = gamma_blob(&mode, false);
    let second = gamma_blob(&mode, true);
    let ctm = blob(&mode);
    for flags in [NONBLOCK, NONBLOCK | TEST_ONLY] {
        let request = Request::Atomic(OwnedAtomic {
            flags,
            cookie: 0,
            objects: vec![1],
            counts: vec![2],
            props: vec![CRTC_CTM_PROP_ID, CRTC_GAMMA_LUT_PROP_ID],
            values: vec![u64::from(ctm), u64::from(first)],
        });
        let plan = Plan::stage(
            &mode.lock(),
            request,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
        )
        .unwrap();
        assert!(matches!(plan.action, Action::Color { dsb: Some(_), .. }));
    }
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    gamma_request(&cpu, first, NONBLOCK);
    let installed = submit(&queue, &cpu, &events);
    let platform = MockPlatform::new();
    let device = Arc::new(platform.meteor());
    let mut worker = Worker {
        device: device.clone(),
    };
    // Projected and committed active replacement select the DSB path.
    // TEST_ONLY does no MMIO, waits, descriptor allocation, or queue mutation.
    for committed in [false, true] {
        if committed {
            run(queue.run(&mut worker));
            assert_eq!(installed.status(), 1);
        }
        let writes = platform.palette_writes();
        let cpu = Cpu::new();
        gamma_request(&cpu, second, NONBLOCK | TEST_ONLY);
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
        assert_eq!(platform.palette_writes(), writes);
    }
    gamma_request(&cpu, 0, NONBLOCK | EVENT);
    let disabled = submit(&queue, &cpu, &events);
    gamma_request(&cpu, second, NONBLOCK | EVENT);
    let replaced = submit(&queue, &cpu, &events); // projected gamma0 permits preload
    mode.lock().destroy_property_blob(first);
    mode.lock().destroy_property_blob(second);
    let mut work = Box::pin(queue.run(&mut worker));
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
    assert_eq!(
        platform.palette_writes(),
        1024,
        "disable arm must precede original palette restore"
    );
    assert_eq!(disabled.status(), 0);
    assert_eq!(replaced.status(), 0);
    run(work);
    assert_eq!(disabled.status(), 1);
    assert_eq!(replaced.status(), 1);
    assert_eq!(platform.palette_writes(), 3072);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, second);
    assert!(mode.lock().property_blob(first).is_none());
    let mut session = run(device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gamma_projected_dsb_replacement_and_explicit_disable_transition
);

fn smoke_intel_gamma_worker_close_cancel_fault_and_reset_never_publish_success() -> TestResult {
    for failure in 0..5 {
        let mode = color_mode();
        let id = gamma_blob(&mode, true);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        gamma_request(&cpu, id, NONBLOCK | EVENT);
        let completion = submit(&queue, &cpu, &events);
        mode.lock().destroy_property_blob(id);
        let platform = MockPlatform::new();
        let device = Arc::new(platform.meteor());
        let mut worker = Worker {
            device: device.clone(),
        };
        if failure == 2 {
            platform.refuse_palette(true);
        }
        let mut work = Box::pin(queue.run(&mut worker));
        let first = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if failure == 2 {
            assert!(first.is_ready());
            drop(work);
        } else {
            assert!(first.is_pending());
            if failure == 0 {
                events.lock().close();
                mode.lock().master_release(7);
                run(work);
            } else if failure == 1 {
                drop(work); // real worker cancellation, no user pointer remains
                let mut session = run(device.session()).unwrap();
                run(session.restore_console()).unwrap();
            } else {
                if failure == 3 {
                    platform.poison();
                } else {
                    platform.set(crate::intel_gpu_color::GAMMA, 0);
                }
                run(work);
            }
        }
        assert!(completion.status() < 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        if failure >= 2 {
            platform.refuse_palette(false);
            platform.poison();
            run(device.recover()).unwrap();
        }
        assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
        for i in [0, 13, 511, 1023] {
            platform.write32(0x4a400, i);
            assert_eq!(platform.read32(0x4a404), i);
        }
        platform.write32(0x4a400, 0);
        assert!(device.legacy().is_ok());
        assert!(mode.lock().property_blob(id).is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gamma_worker_close_cancel_fault_and_reset_never_publish_success
);

fn smoke_intel_gamma_native_advertisement_sizes_and_inherited_refusal() -> TestResult {
    let mode = color_mode();
    assert_eq!(crtc_color_properties(&mode.lock(), 1).1, vec![0, 0, 1024]);
    for entries in [256, 1023, 1025, 4096] {
        let id = mode
            .lock()
            .create_property_blob(vec![0; entries * 8])
            .unwrap();
        assert_eq!(
            crtc_color_property(
                &mode.lock(),
                1,
                CRTC_GAMMA_LUT_PROP_ID,
                u64::from(id),
                &mut CrtcColorChange::default()
            ),
            Err(FsError::InvalidData)
        );
        mode.lock().destroy_property_blob(id);
    }
    mode.lock().intel_ctm = false;
    assert_eq!(crtc_color_properties(&mode.lock(), 1).1, vec![0, 0, 4096]);
    mode.lock().intel_ctm = true;
    let id = gamma_blob(&mode, false);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    gamma_request(&cpu, id, NONBLOCK | EVENT);
    let completion = submit(&queue, &cpu, &events);
    let platform = MockPlatform::new();
    platform.set(crate::intel_gpu_color::GAMMA, 1 << 31); // inherited pre-CSC stage
    let device = Arc::new(platform.meteor());
    let mut worker = Worker {
        device: device.clone(),
    };
    run(queue.run(&mut worker));
    assert!(completion.status() < 0);
    assert_eq!(platform.palette_writes(), 0);
    assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 1 << 31);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gamma_native_advertisement_sizes_and_inherited_refusal
);

fn smoke_intel_gamma_cancelled_owner_replacement_refusal_allows_explicit_clear() -> TestResult {
    let mode = color_mode();
    let first = gamma_blob(&mode, false);
    let second = gamma_blob(&mode, true);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    gamma_request(&cpu, first, NONBLOCK | EVENT);
    let cancelled = submit(&queue, &cpu, &events);
    mode.lock().destroy_property_blob(first);
    let platform = MockPlatform::new();
    let device = Arc::new(platform.meteor());
    let mut worker = Worker {
        device: device.clone(),
    };
    let mut work = Box::pin(queue.run(&mut worker));
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    drop(work);
    assert!(cancelled.status() < 0);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
    assert_eq!(platform.palette_writes(), 1024);
    // Card still says bypass: foreground may admit a different LUT. The real
    // owner finishes the abandoned latch, then refuses before any new writes.
    gamma_request(&cpu, second, NONBLOCK | EVENT);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(refused.status() < 0);
    assert_eq!(platform.palette_writes(), 1024);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(
        run(device.session()).is_ok(),
        "pre-write Unsupported must not poison the owner"
    );
    gamma_request(&cpu, 0, NONBLOCK);
    let cleared = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(cleared.status(), 1);
    assert_eq!(platform.palette_writes(), 2048);
    assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
    assert!(device.legacy().is_ok());
    gamma_request(&cpu, second, NONBLOCK);
    let installed = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(installed.status(), 1);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, second);
    assert_eq!(platform.palette_writes(), 3072);
    let mut session = run(device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gamma_cancelled_owner_replacement_refusal_allows_explicit_clear
);

fn submit_as(
    queue: &queue::Queue,
    open: u64,
    command: u32,
    cpu: &Cpu,
    events: &Events,
) -> Arc<queue::Completion> {
    match run(admit(
        queue,
        open,
        command,
        64,
        cpu,
        Some(events),
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        },
        1,
    ))
    .unwrap()
    {
        Some((completion, _, _)) => completion,
        None => panic!("expected an owned KMS transaction"),
    }
}
fn observe() -> Request {
    Request::Atomic(OwnedAtomic {
        flags: NONBLOCK,
        cookie: 0,
        objects: vec![1],
        counts: vec![1],
        props: vec![CRTC_OUT_FENCE_PTR_PROP_ID],
        values: vec![512],
    })
}
fn smoke_intel_color_replacement_master_restores_before_flip_and_stale_close_is_noop() -> TestResult
{
    for implicit in [false, true] {
        for close_first in [false, true] {
            let mode = color_mode();
            let ctm = blob(&mode);
            let gamma = gamma_blob(&mode, false);
            let queue = queue::Queue::new(mode.clone());
            let cpu = Cpu::new();
            let old_events = Events::new(IrqSafeSpinLock::new(Default::default()));
            let events = Events::new(IrqSafeSpinLock::new(Default::default()));
            let platform = MockPlatform::new();
            let device = Arc::new(platform.meteor());
            let mut worker = Worker {
                device: device.clone(),
            };
            request(&cpu, ctm, NONBLOCK);
            let a = submit(&queue, &cpu, &old_events);
            run(queue.run(&mut worker));
            gamma_request(&cpu, gamma, NONBLOCK);
            let b = submit(&queue, &cpu, &old_events);
            run(queue.run(&mut worker));
            assert_eq!((a.status(), b.status()), (1, 1));
            assert_eq!(
                platform.read32(crate::intel_gpu_color::GAMMA),
                (1 << 30) | 1
            );
            if !implicit {
                mode.lock().master_open(8);
            } // already-open non-master
            old_events.lock().close();
            mode.lock().release_file_framebuffers(7);
            mode.lock().master_release(7);
            assert!(mode.lock().intel_master_restore_pending());
            if implicit {
                mode.lock().master_open(8);
            }
            // Simulate the actual lastclose task after B has opened. The task
            // may run first or after B's worker; both use the same Session and
            // pending marker rather than checking only has_master().
            if close_first {
                let mut session = run(device.session()).unwrap();
                run(restore_released_master(&mut session, &mode)).unwrap();
                assert!(!mode.lock().intel_master_restore_pending());
            }
            if !implicit {
                let acquired = submit_as(
                    &queue,
                    8,
                    drm_uapi::io(u32::from(b'd'), 0x1e),
                    &cpu,
                    &events,
                );
                run(queue.run(&mut worker));
                assert_eq!(acquired.status(), 1);
                assert!(mode.lock().is_master(8));
            }
            // Real public WC primary flip on x86; WC is deliberately refused
            // on aarch64, where the same worker observes actual console vblank.
            #[cfg(target_arch = "x86_64")]
            let presentation = atomic_frame(framebuffer(&mode, 8, true).unwrap(), NONBLOCK);
            #[cfg(not(target_arch = "x86_64"))]
            let presentation = observe();
            let (flipped, _, _) = run(queue.submit(
                8,
                presentation,
                Geometry {
                    width: 64,
                    height: 32,
                    pitch: 256,
                },
                1,
                &cpu,
                Some(&events),
            ))
            .unwrap()
            .unwrap();
            run(queue.run(&mut worker));
            assert_eq!(flipped.status(), 1);
            assert!(!mode.lock().intel_master_restore_pending());
            assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
            assert_eq!(
                mode.lock().crtc_color(1).map(|c| (c.ctm, c.gamma_lut)),
                Some((0, 0))
            );
            assert_eq!(platform.palette_writes(), 2048);
            // B's independently confirmed color must survive A's late close.
            request(&cpu, ctm, NONBLOCK);
            let c = submit_as(&queue, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC, &cpu, &events);
            run(queue.run(&mut worker));
            gamma_request(&cpu, gamma, NONBLOCK);
            let g = submit_as(&queue, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC, &cpu, &events);
            run(queue.run(&mut worker));
            assert_eq!((c.status(), g.status()), (1, 1));
            let writes = platform.palette_writes();
            {
                let mut session = run(device.session()).unwrap();
                run(restore_released_master(&mut session, &mode)).unwrap();
            }
            assert_eq!(
                platform.read32(crate::intel_gpu_color::GAMMA),
                (1 << 30) | 1
            );
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 31);
            assert_eq!(platform.palette_writes(), writes);
            assert_eq!(
                mode.lock().crtc_color(1).map(|c| (c.ctm, c.gamma_lut)),
                Some((ctm, gamma))
            );
            let dropped = submit_as(
                &queue,
                8,
                drm_uapi::io(u32::from(b'd'), 0x1f),
                &cpu,
                &events,
            );
            run(queue.run(&mut worker));
            assert_eq!(dropped.status(), 1);
            assert!(!mode.lock().has_master());
            assert!(!mode.lock().intel_master_restore_pending());
            assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
            assert_eq!(
                mode.lock().crtc_color(1).map(|c| (c.ctm, c.gamma_lut)),
                Some((0, 0))
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_color_replacement_master_restores_before_flip_and_stale_close_is_noop
);

fn smoke_intel_color_master_restore_marker_survives_test_only_cancellation_and_failure(
) -> TestResult {
    for failure in [false, true] {
        let mode = color_mode();
        let id = gamma_blob(&mode, false);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        let device = Arc::new(platform.meteor());
        let mut worker = Worker {
            device: device.clone(),
        };
        gamma_request(&cpu, id, NONBLOCK);
        let completed = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(completed.status(), 1);
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        gamma_request(&cpu, 0, NONBLOCK | TEST_ONLY);
        assert!(run(admit(
            &queue,
            8,
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
        ))
        .unwrap()
        .is_none());
        assert!(mode.lock().intel_master_restore_pending());
        assert_eq!(
            platform.read32(crate::intel_gpu_color::GAMMA),
            (1 << 30) | 1
        );
        assert_eq!(platform.palette_writes(), 1024);
        {
            let mut session = run(device.session()).unwrap();
            let mut close = Box::pin(restore_released_master(&mut session, &mode));
            assert!(close
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert!(mode.lock().intel_master_restore_pending());
            assert_eq!(platform.palette_writes(), 1024);
            if failure {
                platform.set(crate::intel_gpu_color::GAMMA, 1 << 30);
                assert_eq!(run(close), Err(FsError::NoDevice));
            } else {
                drop(close);
            }
        }
        assert!(mode.lock().intel_master_restore_pending());
        assert!(device.legacy().is_err());
        if failure {
            assert!(run(device.session()).is_err());
            platform.poison();
            run(device.recover()).unwrap();
        }
        let (observed, _, _) = run(queue.submit(
            8,
            observe(),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            Some(&events),
        ))
        .unwrap()
        .unwrap();
        run(queue.run(&mut worker));
        assert_eq!(observed.status(), 1);
        assert!(!mode.lock().intel_master_restore_pending());
        assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(platform.palette_writes(), 2048);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        assert!(device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_color_master_restore_marker_survives_test_only_cancellation_and_failure
);

fn smoke_intel_native_non_color_close_restores_and_retires_owned_front() -> TestResult {
    // native_atomic is shared with AMD/virtio and must not opt unrelated
    // cards into Intel close-time ownership or pending-restoration state.
    let unrelated = mode();
    unrelated.lock().master_release(7);
    assert!(!unrelated.lock().intel_master_restore_pending());
    let mode = mode();
    mode.lock().intel_display = true;
    assert!(!mode.lock().intel_ctm);
    let platform = MockPlatform::new();
    let device = Arc::new(platform.tiger());
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let mut worker = Worker {
        device: device.clone(),
    };
    #[cfg(target_arch = "x86_64")]
    let retained = {
        let fb = framebuffer(&mode, 7, true).unwrap();
        let weak = Arc::downgrade(
            &mode
                .lock()
                .framebuffer(fb)
                .unwrap()
                .intel
                .as_ref()
                .unwrap()
                .object,
        );
        let (presented, _, _) = run(queue.submit(
            7,
            atomic_frame(fb, NONBLOCK),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            Some(&events),
        ))
        .unwrap()
        .unwrap();
        run(queue.run(&mut worker));
        assert_eq!(presented.status(), 1);
        assert_ne!(platform.read32(0x701ac), 0x01000000);
        assert!(device.legacy().is_err());
        Some(weak)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let retained: Option<alloc::sync::Weak<crate::intel_gpu_gem::GemObject>> = {
        let (observed, _, _) = run(queue.submit(
            7,
            observe(),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            Some(&events),
        ))
        .unwrap()
        .unwrap();
        run(queue.run(&mut worker));
        assert_eq!(observed.status(), 1);
        None
    };
    events.lock().close();
    mode.lock().release_file_framebuffers(7);
    mode.lock().master_release(7);
    mode.lock().master_open(8); // replacement exists before the close task runs
    assert!(mode.lock().intel_master_restore_pending());
    if let Some(weak) = &retained {
        assert!(weak.upgrade().is_some());
    }
    {
        let mut session = run(device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
    }
    assert!(!mode.lock().intel_master_restore_pending());
    assert_eq!(platform.read32(0x701ac), 0x01000000);
    assert_eq!(platform.palette_writes(), 0);
    if let Some(weak) = retained {
        assert!(weak.upgrade().is_none());
    }
    assert!(device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_native_non_color_close_restores_and_retires_owned_front
);

fn combined_color_request(cpu: &Cpu, ctm: u32, gamma: u32, flags: u32) {
    request(cpu, ctm, flags);
    cpu.write(144, &3u32.to_le_bytes()).unwrap();
    cpu.write(164, &CRTC_GAMMA_LUT_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(168, &CRTC_OUT_FENCE_PTR_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(200, &u64::from(gamma).to_le_bytes()).unwrap();
    cpu.write(208, &512u64.to_le_bytes()).unwrap();
}
struct DsbSetup {
    mode: ModeState,
    queue: queue::Queue,
    cpu: Cpu,
    events: Events,
    platform: MockPlatform,
    worker: Worker,
    first: u32,
    second: u32,
    ctm: u32,
}
fn dsb_setup() -> DsbSetup {
    let mode = color_mode();
    let first = gamma_blob(&mode, false);
    let second = gamma_blob(&mode, true);
    let ctm = blob(&mode);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    platform.dsb_timing();
    let mut worker = Worker {
        device: Arc::new(platform.meteor()),
    };
    gamma_request(&cpu, first, NONBLOCK);
    let initial = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(initial.status(), 1);
    DsbSetup {
        mode,
        queue,
        cpu,
        events,
        platform,
        worker,
        first,
        second,
        ctm,
    }
}
fn smoke_intel_dsb_uapi_combined_active_gamma_nonblock_native_leaf_and_flip_preservation(
) -> TestResult {
    // Safe first-use refusal releases untouched baseline ownership and
    // resumes console; refusing a replacement retains confirmed color.
    let baseline = color_mode();
    let baseline_gamma = gamma_blob(&baseline, false);
    let baseline_ctm = blob(&baseline);
    let baseline_queue = queue::Queue::new(baseline.clone());
    let baseline_cpu = Cpu::new();
    let baseline_events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let baseline_platform = MockPlatform::new();
    baseline_platform.dsb_timing();
    baseline_platform.set(0x60420, 1 << 31);
    let mut baseline_worker = Worker {
        device: Arc::new(baseline_platform.meteor()),
    };
    combined_color_request(
        &baseline_cpu,
        baseline_ctm,
        baseline_gamma,
        NONBLOCK | EVENT,
    );
    let refused = submit(&baseline_queue, &baseline_cpu, &baseline_events);
    run(baseline_queue.run(&mut baseline_worker));
    assert!(refused.status() < 0);
    assert_eq!(baseline_platform.palette_writes(), 0);
    assert_eq!(baseline_platform.console_resumes(), 1);
    assert!(baseline_worker.device.legacy().is_ok());
    assert!(baseline_platform.dsb_mappings().is_empty());
    let DsbSetup {
        mode,
        queue,
        cpu,
        events,
        platform,
        mut worker,
        first,
        second,
        ctm,
    } = dsb_setup();
    platform.set(0x60420, 1 << 31);
    combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(refused.status() < 0);
    assert_eq!(platform.palette_writes(), 1024);
    assert_eq!(platform.console_resumes(), 0);
    assert!(worker.device.legacy().is_err());
    platform.set(0x60420, 0);
    combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
    let changed = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock().last().unwrap().clone();
    assert_eq!(changed.status(), 0);
    assert_eq!(fence.status(), 0);
    assert_eq!(platform.palette_writes(), 1024);
    assert!(mode.lock().destroy_property_blob(second));
    assert!(mode.lock().destroy_property_blob(ctm));
    let mut work = Box::pin(queue.run(&mut worker));
    if cfg!(target_arch = "aarch64") {
        run(work);
        assert!(changed.status() < 0);
        assert!(platform.dsb_mappings().is_empty());
        assert_eq!(platform.palette_writes(), 1024);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, first);
        return TestResult::Pass;
    }
    {
        for poll in 0..3 {
            assert!(work
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert_eq!(changed.status(), 0);
            assert_eq!(fence.status(), 0);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, first);
            assert_eq!(
                platform.palette_writes(),
                if poll == 2 { 2048 } else { 1024 }
            );
        }
        run(work);
        assert_eq!(changed.status(), 1);
        assert_eq!(fence.status(), 1);
        let state = {
            let card = mode.lock();
            let color = card.crtc_color(1).unwrap();
            (color.ctm, color.gamma_lut)
        };
        assert_eq!(state, (ctm, second));
        let mappings = platform.dsb_mappings();
        assert_eq!(mappings.len(), 8);
        let mut event = [0; 32];
        assert_eq!(
            events.lock().read_deliverable_event(u64::MAX, &mut event),
            Some(32)
        );
        assert_eq!(
            u32::from_le_bytes(event[24..28].try_into().unwrap()),
            platform.read32(0x70040)
        );
        // A real ordinary primary flip leaves confirmed combined color intact.
        let fb = framebuffer(&mode, 7, true).unwrap();
        let (flipped, _, _) = run(queue.submit(
            7,
            atomic_frame(fb, NONBLOCK),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            Some(&events),
        ))
        .unwrap()
        .unwrap();
        run(queue.run(&mut worker));
        assert_eq!(flipped.status(), 1);
        assert_eq!(platform.palette_writes(), 2048);
        assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 31);
        assert_eq!(
            platform.read32(crate::intel_gpu_color::GAMMA),
            (1 << 30) | 1
        );
        assert_eq!(platform.dsb_mappings(), mappings);
        let mut session = run(worker.device.session()).unwrap();
        run(session.restore_console()).unwrap();
        assert_eq!(platform.palette_writes(), 3072);
        assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(platform.dsb_mappings(), mappings);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_dsb_uapi_combined_active_gamma_nonblock_native_leaf_and_flip_preservation
);

fn smoke_intel_dsb_cancel_close_replacement_drains_before_original_palette_and_stale_close(
) -> TestResult {
    let DsbSetup {
        mode,
        queue,
        cpu,
        events,
        platform,
        mut worker,
        first: _,
        second,
        ctm,
    } = dsb_setup();
    combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
    let changed = submit(&queue, &cpu, &events);
    let mut work = Box::pin(queue.run(&mut worker));
    if cfg!(target_arch = "aarch64") {
        run(work);
        assert!(changed.status() < 0);
        return TestResult::Pass;
    }
    {
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(work);
        assert!(changed.status() < 0);
        let mappings = platform.dsb_mappings();
        assert_eq!(platform.palette_writes(), 1024);
        events.lock().close();
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        assert!(mode.lock().intel_master_restore_pending());
        platform.stall_dsb(1, true);
        let replacement_events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let (replacement, _, _) = run(queue.submit(
            8,
            observe(),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            Some(&replacement_events),
        ))
        .unwrap()
        .unwrap();
        let mut work = Box::pin(queue.run(&mut worker));
        for _ in 0..3 {
            assert!(work
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(replacement.status(), 0);
        assert_eq!(platform.palette_writes(), 1024);
        assert!(mode.lock().intel_master_restore_pending());
        assert_eq!(platform.dsb_mappings(), mappings);
        platform.stall_dsb(1, false);
        run(work);
        assert_eq!(replacement.status(), 1);
        assert_eq!(platform.palette_writes(), 3072);
        assert!(!mode.lock().intel_master_restore_pending());
        assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
        assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(platform.dsb_mappings(), mappings);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        // B's later confirmed color survives the delayed old close task.
        request(&cpu, ctm, NONBLOCK);
        let b = submit_as(
            &queue,
            8,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            &cpu,
            &replacement_events,
        );
        run(queue.run(&mut worker));
        assert_eq!(b.status(), 1);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 1 << 31);
        run(session.restore_console()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_dsb_cancel_close_replacement_drains_before_original_palette_and_stale_close
);

fn smoke_intel_dsb_reset_and_fault_quarantine_before_fresh_console_or_color_writes() -> TestResult {
    for stalled in [0, 1] {
        let DsbSetup {
            mode: _,
            queue,
            cpu,
            events,
            platform,
            mut worker,
            first: _,
            second,
            ctm,
        } = dsb_setup();
        combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
        let changed = submit(&queue, &cpu, &events);
        let mut work = Box::pin(queue.run(&mut worker));
        if cfg!(target_arch = "aarch64") {
            run(work);
            assert!(changed.status() < 0);
            return TestResult::Pass;
        }
        {
            platform.stall_dsb(stalled, true);
            assert!(work
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert!(work
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let mappings = platform.dsb_mappings();
            let writes = platform.palette_writes();
            let arms = platform.primary_arms();
            platform.poison();
            run(work);
            assert!(changed.status() < 0);
            let mut recovery = Box::pin(worker.device.recover());
            for _ in 0..3 {
                assert!(recovery
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
            assert_eq!(platform.primary_arms(), arms);
            assert_eq!(platform.palette_writes(), writes);
            assert_eq!(platform.dsb_mappings(), mappings);
            drop(recovery);
            assert!(run(worker.device.session()).is_err());
            platform.stall_dsb(stalled, false);
            run(worker.device.recover()).unwrap();
            assert!(run(worker.device.session()).is_ok());
            assert_eq!(platform.read32(crate::intel_gpu_color::MODE), 0);
            assert_eq!(platform.read32(crate::intel_gpu_color::GAMMA), 0);
            assert_eq!(platform.palette_writes(), 3072);
            assert_eq!(platform.dsb_mappings(), mappings);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            // Recovery's privileged IO view must not stay in the retained
            // DSB. Inject a second reset after outer session validity checks,
            // exactly at the next engine-control read before rearming.
            let writes = platform.dsb_writes().len();
            platform.poison_next_dsb_read();
            combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
            let again = submit(&queue, &cpu, &events);
            run(queue.run(&mut worker));
            assert!(again.status() < 0);
            assert_eq!(
                platform.dsb_writes().len(),
                writes,
                "retained recovery IO bypassed the next reset poison"
            );
            assert_eq!(platform.dsb_mappings(), mappings);
            assert_eq!(platform.palette_writes(), 3072);
            assert!(run(worker.device.session()).is_err());
            run(worker.device.recover()).unwrap();
            assert!(run(worker.device.session()).is_ok());
            assert_eq!(platform.dsb_mappings(), mappings);
        }
    }
    // The MTL ATS fault bit is a hard DMA failure, never a successful fence.
    let DsbSetup {
        mode: _,
        queue,
        cpu,
        events,
        platform,
        mut worker,
        first: _,
        second,
        ctm,
    } = dsb_setup();
    combined_color_request(&cpu, ctm, second, NONBLOCK | EVENT);
    let changed = submit(&queue, &cpu, &events);
    let mut work = Box::pin(queue.run(&mut worker));
    if cfg!(target_arch = "aarch64") {
        run(work);
        assert!(changed.status() < 0);
        return TestResult::Pass;
    }
    {
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        // Source initialization legitimately W1C-clears pre-existing leaf
        // status. Inject only after this stream has started its actual leaf.
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(platform.read32(0x70c08) & 1, 1);
        let mappings = platform.dsb_mappings();
        platform.set(0x70c28, 1 << 4);
        run(work);
        assert!(changed.status() < 0);
        assert!(run(worker.device.session()).is_err());
        assert_eq!(platform.dsb_mappings(), mappings);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_dsb_reset_and_fault_quarantine_before_fresh_console_or_color_writes
);

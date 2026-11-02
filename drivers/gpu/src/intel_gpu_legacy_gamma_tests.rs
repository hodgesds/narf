//! Actual legacy UAPI foreground copies -> owned color FIFO -> real palette
//! CPU/DSB IO. Linux b90c984d drm_color_mgmt.c and intel_color.c legacy mode.
use super::*;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_kms::{tests::MockPlatform, Device};
use narf_filesystem::DrmFence;
const SET: u32 = drm_uapi::iowr(b'd' as u32, 0xa5, 32);
struct Worker(Arc<Device<MockPlatform>>);
impl queue::Worker for Worker {
    fn lost(&self) -> bool {
        self.0.reset_lost()
    }
    fn epoch(&self) -> u64 {
        1
    }
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        _: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        Box::pin(async move {
            let mut guard = self.0.session().await?;
            execute_plan(&mut guard, mode, open, plan, reservation).await
        })
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..256 {
        if let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
    }
    panic!("legacy gamma worker failed to finish")
}
fn fixture() -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu) {
    let platform = MockPlatform::new();
    platform.dsb_timing();
    let mode = mode();
    {
        let mut card = mode.lock();
        card.intel_display = true;
        card.intel_ctm = true;
        card.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    let queue = queue::Queue::new(mode.clone());
    let worker = Worker(Arc::new(platform.meteor()));
    (platform, mode, queue, worker, Cpu::new())
}
fn values(seed: u16) -> Vec<u16> {
    (0..3)
        .flat_map(|channel| {
            (0..256u16).map(move |i| {
                (if channel == 1 { 255 - i } else { i })
                    .wrapping_mul(257)
                    .wrapping_add(seed)
            })
        })
        .collect()
}
fn header(cpu: &Cpu, crtc: u32, size: u32) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&crtc.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    for pointer in [512u64, 1024, 1536] {
        bytes.extend_from_slice(&pointer.to_le_bytes());
    }
    cpu.write(64, &bytes).unwrap();
}
fn request(cpu: &Cpu, store: &[u16]) {
    header(cpu, 1, 256);
    for (channel, pointer) in [512, 1024, 1536].into_iter().enumerate() {
        let bytes: Vec<u8> = store[channel * 256..(channel + 1) * 256]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        cpu.write(pointer, &bytes).unwrap();
    }
}
fn read_store(mode: &ModeState, cpu: &Cpu) -> Vec<u16> {
    header(cpu, 1, 256);
    assert_eq!(get_legacy_gamma(mode, 64, cpu), Ok(0));
    let mut store = Vec::new();
    for pointer in [512, 1024, 1536] {
        let mut bytes = [0; 512];
        cpu.read(pointer, &mut bytes).unwrap();
        store.extend(
            bytes
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]])),
        );
    }
    store
}
fn submit(queue: &queue::Queue, cpu: &Cpu, open: u64) -> Arc<queue::Completion> {
    run(admit(
        queue,
        open,
        SET,
        64,
        cpu,
        None,
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        },
        1,
    ))
    .unwrap()
    .unwrap()
    .0
}
fn packed(store: &[u16], i: usize) -> u32 {
    let channel = |at| (u32::from(store[at]) * 255 + 32767) / 65535;
    channel(i) << 16 | channel(256 + i) << 8 | channel(512 + i)
}
fn smoke_intel_legacy_gamma_real_set_get_copies_once_and_waits_latch() -> TestResult {
    let (p, mode, queue, mut worker, cpu) = fixture();
    let initial: Vec<u16> = (0..3).flat_map(|_| (0..256u16).map(|i| i << 8)).collect();
    assert_eq!(read_store(&mode, &cpu), initial);
    let expected = values(129);
    request(&cpu, &expected);
    let done = submit(&queue, &cpu, 7);
    assert_eq!(done.status(), 0);
    assert_eq!(read_store(&mode, &cpu), initial);
    // Overwrite every input after foreground admission. The worker owns the
    // original three ramps and internal blob, with no user pointer retained.
    request(&cpu, &values(65535));
    let mut task = Box::pin(queue.run(&mut worker));
    assert!(task
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(done.status(), 0);
    assert_eq!(p.read32(0x4a480), 1 << 30); // real 8-bit post-CSC mode, not mode1
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_store, initial);
    run(task);
    assert_eq!(done.status(), 1);
    assert_eq!(read_store(&mode, &cpu), expected);
    for i in 0..256 {
        assert_eq!(p.read32(0x4a000 + i as u64 * 4), packed(&expected, i));
    }
    assert_eq!(crtc_color_properties(&mode.lock(), 1).1[2], 1024);
    assert_eq!(p.legacy_posted(), 0);
    run(worker.0.quiesce()).unwrap();
    assert_eq!(p.read32(0x4a480), 0);
    for i in 0..256 {
        assert_eq!(p.read32(0x4a000 + i * 4), 0);
    }
    assert_eq!(
        read_store(&mode, &cpu),
        expected,
        "GET returns legacy store, not current hardware palette"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_legacy_gamma_real_set_get_copies_once_and_waits_latch
);

fn smoke_intel_legacy_gamma_dsb_duplicate_posted_replacement_and_native_roundtrip() -> TestResult {
    let (p, mode, queue, mut worker, cpu) = fixture();
    request(&cpu, &values(0));
    let first = submit(&queue, &cpu, 7);
    run(queue.run(&mut worker));
    assert_eq!(first.status(), 1);
    p.legacy_collisions(true);
    request(&cpu, &values(1024));
    let next = submit(&queue, &cpu, 7);
    run(queue.run(&mut worker));
    #[cfg(target_arch = "aarch64")]
    {
        assert!(next.status() < 0);
        assert_eq!(read_store(&mode, &cpu), values(0));
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(next.status(), 1);
        assert_eq!(p.legacy_posted(), 512);
        let stream = p.dsb_stream(1);
        let writes: Vec<_> = stream
            .into_iter()
            .filter(|&(_, high)| high >> 24 == 1 && (0x4a000..0x4a400).contains(&(high & 0xfffff)))
            .collect();
        assert_eq!(writes.len(), 512);
        for (i, pair) in writes.chunks_exact(2).enumerate() {
            assert_eq!(pair[0], pair[1]);
            assert_eq!(pair[0].1 & 0xfffff, 0x4a000 + i as u32 * 4);
            assert_eq!(pair[0].0, packed(&values(1024), i));
        }
        // Native atomic1024 and a CTM can replace a live legacy LUT; the
        // following real legacy SET resets CTM and selects legacy mode again.
        let native = mode
            .lock()
            .create_property_blob(vec![0xff; 1024 * 8])
            .unwrap();
        let ctm = mode
            .lock()
            .create_property_blob(
                [1u64 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        let changed = run(queue.submit(
            7,
            Request::Atomic(OwnedAtomic {
                flags: 0,
                cookie: 0,
                objects: vec![1],
                counts: vec![2],
                props: vec![CRTC_CTM_PROP_ID, CRTC_GAMMA_LUT_PROP_ID],
                values: vec![u64::from(ctm), u64::from(native)],
            }),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            None,
        ))
        .unwrap()
        .unwrap()
        .0;
        run(queue.run(&mut worker));
        assert_eq!(changed.status(), 1);
        assert_eq!(p.read32(0x4a480), (1 << 30) | 1);
        assert_ne!(p.read32(0x49028), 0);
        assert_eq!(read_store(&mode, &cpu), values(1024));
        request(&cpu, &values(4096));
        let restored = submit(&queue, &cpu, 7);
        run(queue.run(&mut worker));
        assert_eq!(restored.status(), 1);
        assert_eq!(p.read32(0x4a480), 1 << 30);
        assert_eq!(p.read32(0x49028), 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
    }
    run(worker.0.quiesce()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_legacy_gamma_dsb_duplicate_posted_replacement_and_native_roundtrip
);

fn smoke_intel_legacy_gamma_foreground_errors_and_test_only_leave_hardware_untouched() -> TestResult
{
    let (p, mode, queue, _worker, cpu) = fixture();
    let mut native_header = [0u8; 32];
    native_header[..4].copy_from_slice(&1u32.to_le_bytes());
    native_header[4..8].copy_from_slice(&256u32.to_le_bytes());
    native_header[8..].fill(0xff); // refuse before reading any ramps
    assert_eq!(
        crate::drm_ioctl_bridge::handle_gamma(
            0,
            &mode,
            native_header.as_ptr() as usize,
            &crate::drm::render_node::DrmFileCtx::primary(true),
            true,
        ),
        Err(FsError::Unsupported),
    );
    assert_eq!(
        crate::drm_ioctl_bridge::handle_gamma(
            0,
            &mode,
            0,
            &crate::drm::render_node::DrmFileCtx::render_client(),
            false,
        ),
        Err(FsError::PermissionDenied),
    );
    let mut crtc = [0u8; 104];
    crtc[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        crate::drm_ioctl_bridge::handle_getcrtc(
            &mode,
            crtc.as_mut_ptr() as usize,
            &crate::drm::render_node::DrmFileCtx::primary(false),
        ),
        Ok(0)
    );
    assert_eq!(u32::from_le_bytes(crtc[28..32].try_into().unwrap()), 256);
    header(&cpu, 999, 0);
    assert!(matches!(
        run(admit(
            &queue,
            7,
            SET,
            64,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1
        )),
        Err(queue::SubmitError::Io(FsError::NotFound))
    ));
    assert!(matches!(
        run(admit(
            &queue,
            8,
            SET,
            0,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1
        )),
        Err(queue::SubmitError::Io(FsError::PermissionDenied))
    ));
    header(&cpu, 1, 255);
    assert_eq!(get_legacy_gamma(&mode, 64, &cpu), Err(FsError::InvalidData));
    assert!(matches!(
        run(admit(
            &queue,
            7,
            SET,
            64,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1
        )),
        Err(queue::SubmitError::Io(FsError::InvalidData))
    ));
    header(&cpu, 1, 256);
    cpu.write(16 + 64, &u64::MAX.to_le_bytes()).unwrap();
    assert!(matches!(
        run(admit(
            &queue,
            7,
            SET,
            64,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1
        )),
        Err(queue::SubmitError::Io(FsError::BadAddress))
    ));
    let blob = mode.lock().create_property_blob(vec![0; 256 * 8]).unwrap();
    assert!(run(queue.submit(
        7,
        Request::Atomic(OwnedAtomic {
            flags: TEST_ONLY,
            cookie: 0,
            objects: vec![1],
            counts: vec![1],
            props: vec![CRTC_GAMMA_LUT_PROP_ID],
            values: vec![u64::from(blob)]
        }),
        Geometry {
            width: 64,
            height: 32,
            pitch: 256
        },
        1,
        &cpu,
        None
    ))
    .unwrap()
    .is_none());
    assert_eq!(p.read32(0x4a480), 0);
    assert_eq!(p.palette_writes(), 0);
    assert!(p.dsb_mappings().is_empty());
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_legacy_gamma_foreground_errors_and_test_only_leave_hardware_untouched
);

fn smoke_intel_legacy_gamma_cancel_master_reset_and_failed_palette_keep_confirmed_store(
) -> TestResult {
    let (p, mode, queue, mut worker, cpu) = fixture();
    request(&cpu, &values(0));
    let first = submit(&queue, &cpu, 7);
    run(queue.run(&mut worker));
    assert_eq!(first.status(), 1);
    request(&cpu, &values(8192));
    let pending = submit(&queue, &cpu, 7);
    #[cfg(target_arch = "x86_64")]
    {
        p.stall_dsb(0, true);
        let mut task = Box::pin(queue.run(&mut worker));
        assert!(task
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(task);
        assert!(pending.status() < 0);
        assert_eq!(read_store(&mode, &cpu), values(0));
        let mapping = p.dsb_mappings();
        assert!(!mapping.is_empty());
        p.poison();
        p.stall_dsb(0, false);
        run(worker.0.recover()).unwrap();
        assert_eq!(p.read32(0x4a480), 0);
        assert_eq!(p.dsb_mappings(), mapping);
        assert_eq!(read_store(&mode, &cpu), values(0));
    }
    #[cfg(target_arch = "aarch64")]
    {
        run(queue.run(&mut worker));
        assert!(pending.status() < 0);
    }
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    request(&cpu, &values(16384));
    let replacement = submit(&queue, &cpu, 8);
    run(queue.run(&mut worker));
    assert_eq!(replacement.status(), 1);
    assert_eq!(read_store(&mode, &cpu), values(16384));
    let mut guard = run(worker.0.session()).unwrap();
    run(restore_released_master(&mut guard, &mode)).unwrap();
    assert_eq!(p.read32(0x4a480), 1 << 30);
    drop(guard);
    p.refuse_palette(true);
    request(&cpu, &values(32768));
    let failed = submit(&queue, &cpu, 8);
    run(queue.run(&mut worker));
    assert!(failed.status() < 0);
    assert_eq!(read_store(&mode, &cpu), values(16384));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_legacy_gamma_cancel_master_reset_and_failed_palette_keep_confirmed_store
);

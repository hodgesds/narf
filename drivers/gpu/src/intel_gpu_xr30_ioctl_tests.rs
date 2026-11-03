// Actual raw atomic/FIFO -> Device/Guard -> WC GGTT command pages -> native
// source0/leaf1 DSB and primary latch. Linux b90c984d independent literals:
// XR30 30335258 / enabled primary82000000; XR24 34325258 /84000000.
use super::*;
use crate::intel_gpu_scanout::{InputFormat, View};

const XR30: u32 = 0x30335258;
const XR24: u32 = 0x34325258;
const CTL: u64 = 0x70180;
const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const OFFSET: u64 = 0x701a4;
const CONSOLE: u32 = 0x1000000;
struct Worker {
    device: Arc<Device<MockPlatform>>,
    platform: MockPlatform,
}
impl queue::Worker for Worker {
    fn lost(&self) -> bool {
        self.device.reset_lost()
    }
    fn epoch(&self) -> u64 {
        crate::intel_gpu_kms::Platform::published_epoch(&self.platform).unwrap_or(0)
    }
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        Box::pin(async move {
            let mut owner = self.device.session().await?;
            // Mirror DisplayWorker: the admitted epoch must still be current
            // after waiting for the retained Device session, before execution.
            if self.device.reset_lost() || queue::Worker::epoch(self) != epoch {
                return Err(FsError::NoDevice);
            }
            if owner.console_geometry().width != plan.geometry.width
                || owner.console_geometry().height != plan.geometry.height
            {
                return Err(FsError::Busy);
            }
            execute_plan(&mut owner, mode, open, plan, reservation).await
        })
    }
}
struct NoLegacyWait(AtomicBool);
impl DrmFence for NoLegacyWait {
    fn is_signalled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn wait(&self, _: u64) -> bool {
        panic!("XR30 reached the legacy writer-fence wait")
    }
}
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 512,
    }
}
fn fixture() -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu, Events) {
    let p = MockPlatform::new();
    let timing = p.cursor_resources();
    let device = Arc::new(p.meteor_pitch(512));
    p.xr30_source(Some(0x7d40));
    let mode = color_mode();
    {
        let mut card = mode.lock();
        // Real installation publishes this shared source-qualified result;
        // the fixture substitutes PCI/power/clock, not the capability check.
        card.intel_xr30 = crate::intel_gpu_kms::xr30_discovery_profile(&p, geometry(), timing);
        assert!(card.intel_xr30);
        let fixed = card.crtcs[0].mode.unwrap();
        card.encoders.push(crate::drm::card::Encoder {
            id: 2,
            encoder_type: crate::drm::card::EncoderType::Tmds,
            possible_crtcs: 1,
            possible_clones: 0,
            crtc_id: Some(1),
        });
        card.connectors.push(crate::drm::card::Connector {
            id: 3,
            connector_type: crate::drm::card::ConnectorType::Edp,
            connector_type_id: 1,
            status: crate::drm::card::ConnectorStatus::Connected,
            encoder_id: Some(2),
            modes: vec![fixed],
        });
    }
    let q = queue::Queue::new(mode.clone());
    (
        p.clone(),
        mode,
        q,
        Worker {
            device,
            platform: p.clone(),
        },
        Cpu::new(),
        Events::new(IrqSafeSpinLock::new(Default::default())),
    )
}
fn object(wc: bool) -> Result<Arc<crate::intel_gpu_gem::GemObject>, FsError> {
    let gem = crate::intel_gpu_gem::GemState::new();
    let h = gem.create_placed(
        65536,
        None,
        if wc {
            crate::intel_gpu_gem::Placement::SystemWc
        } else {
            crate::intel_gpu_gem::Placement::System
        },
        |_, _| Ok(()),
    )?;
    gem.object(h)
}
fn fb(
    mode: &ModeState,
    object: Arc<crate::intel_gpu_gem::GemObject>,
    format: u32,
    owner: u64,
) -> u32 {
    mode.lock()
        .addfb2_intel(
            &crate::drm::fb_cmd::FbCmd {
                width: 128,
                height: 96,
                pixel_format: format,
                handles: [1, 0, 0, 0],
                pitches: [512, 0, 0, 0],
                flags: 2,
                ..Default::default()
            },
            object,
            owner,
            true,
        )
        .unwrap()
}
fn wc_object() -> Option<Arc<crate::intel_gpu_gem::GemObject>> {
    match object(true) {
        Ok(o) => Some(o),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(e) => panic!("XR30 WC allocation: {e:?}"),
    }
}
fn request(cpu: &Cpu, framebuffer: u32, x: u32, y: u32, flags: u32, color: Option<(u32, u32)>) {
    let mut header = [0; 56];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (at, value) in [
        (8, 128u64),
        (16, 144),
        (24, 160),
        (32, 256),
        (48, 0x58523330),
    ] {
        header[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    cpu.write(64, &header).unwrap();
    for (at, value) in [
        (128, PLANE_ID_BASE),
        (132, 1),
        (144, 4),
        (148, if color.is_some() { 3 } else { 1 }),
    ] {
        cpu.write(at, &value.to_le_bytes()).unwrap();
    }
    let mut props = vec![
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
        PLANE_SRC_X_PROP_ID,
        PLANE_SRC_Y_PROP_ID,
        CRTC_OUT_FENCE_PTR_PROP_ID,
    ];
    let mut values = vec![
        u64::from(framebuffer),
        1,
        u64::from(x) << 16,
        u64::from(y) << 16,
        512,
    ];
    if let Some((ctm, gamma)) = color {
        props.extend([CRTC_CTM_PROP_ID, CRTC_GAMMA_LUT_PROP_ID]);
        values.extend([u64::from(ctm), u64::from(gamma)]);
    }
    for (i, v) in props.iter().enumerate() {
        cpu.write(160 + i as u64 * 4, &v.to_le_bytes()).unwrap();
    }
    for (i, v) in values.iter().enumerate() {
        cpu.write(256 + i as u64 * 8, &v.to_le_bytes()).unwrap();
    }
}
fn admission(
    q: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    open: u64,
    cmd: u32,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(q, open, cmd, 64, cpu, Some(events), geometry(), 1))
}
fn submit(q: &queue::Queue, cpu: &Cpu, events: &Events) -> Arc<queue::Completion> {
    let admitted = admission(q, cpu, events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap();
    assert!(admitted.2);
    admitted.0
}
fn pending<F: Future>(f: core::pin::Pin<&mut F>) {
    assert!(f.poll(&mut Context::from_waker(Waker::noop())).is_pending());
}
fn wait_ctl<F: Future>(mut f: core::pin::Pin<&mut F>, p: &MockPlatform, ctl: u32) {
    for _ in 0..128 {
        pending(f.as_mut());
        if p.read32(CTL) == ctl {
            return;
        }
    }
    panic!("actual DSB did not reach retained XR30 primary arm");
}
fn restore(worker: &Worker, p: &MockPlatform) {
    let mut owner = run(worker.device.session()).unwrap();
    run(owner.restore_console()).unwrap();
    assert_eq!(
        (
            p.read32(CTL),
            p.read32(0x70188),
            p.read32(OFFSET),
            p.read32(SURF),
            p.read32(LIVE)
        ),
        (0x84000000, 8, 0, CONSOLE, CONSOLE)
    );
    assert!(p.primary_mappings().is_empty());
}
fn smoke_mtl_xr30_discovery_addfb_and_copy_boundaries() -> TestResult {
    let (p, mode, q, mut worker, cpu, events) = fixture();
    assert_eq!(mode.lock().intel_primary_formats(), Some(&[XR24, XR30][..]));
    assert!(mode.lock().plane_formats.is_none()); // legacy fallback is not narrowed
    let bytes = intel_primary_formats_blob(&mode.lock(), INTEL_PRIMARY_FORMATS_BLOB).unwrap();
    assert_eq!(&bytes[8..16], &[2, 0, 0, 0, 24, 0, 0, 0]);
    assert_eq!(
        &bytes[24..32],
        &[0x58, 0x52, 0x32, 0x34, 0x58, 0x52, 0x33, 0x30]
    );
    assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 0);
    // The cached XR30 format coexists with the old tiled capabilities, but
    // only LINEAR may reference both formats. These are passive blob bytes.
    assert!(crate::intel_gpu_kms::tile4_profile(&p, geometry(), p.dsb_timing()).is_ok());
    {
        let mut card = mode.lock();
        card.intel_x_tiled = true;
        card.intel_tile4 = true;
    }
    let tiled = intel_primary_formats_blob(&mode.lock(), INTEL_PRIMARY_FORMATS_BLOB).unwrap();
    assert_eq!(&tiled[8..16], &[2, 0, 0, 0, 24, 0, 0, 0]);
    assert_eq!(&tiled[16..24], &[3, 0, 0, 0, 32, 0, 0, 0]);
    assert_eq!(&tiled[24..32], &bytes[24..32]);
    assert_eq!(tiled.len(), 104);
    for (row, (mask, modifier)) in [
        (3u64, 0u64),
        (1, 0x0100000000000001),
        (1, 0x0100000000000009),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 32 + row * 24;
        assert_eq!(
            u64::from_le_bytes(tiled[at..at + 8].try_into().unwrap()),
            mask
        );
        assert_eq!(&tiled[at + 8..at + 16], &[0; 8]);
        assert_eq!(
            u64::from_le_bytes(tiled[at + 16..at + 24].try_into().unwrap()),
            modifier
        );
    }
    {
        let mut card = mode.lock();
        card.intel_x_tiled = false;
        card.intel_tile4 = false;
    }
    cpu.write(64, &0x10u64.to_le_bytes()).unwrap();
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, 64, &cpu),
        Some(Ok(0))
    );
    assert_eq!(&cpu.bytes.lock()[72..80], &1u64.to_le_bytes());
    // Unqualified/WB source refuses before Xe mark_scanout or FB publication.
    let wb = object(false).unwrap();
    let count = mode.lock().framebuffers.len();
    let bad = crate::drm::fb_cmd::FbCmd {
        width: 128,
        height: 96,
        pixel_format: XR30,
        handles: [1, 0, 0, 0],
        pitches: [512, 0, 0, 0],
        flags: 2,
        ..Default::default()
    };
    assert!(mode.lock().addfb2_intel(&bad, wb.clone(), 7, true).is_err());
    assert!(!wb.scanout());
    assert_eq!(mode.lock().framebuffers.len(), count);
    let Some(o) = wc_object() else {
        return TestResult::Pass;
    };
    for malformed in 0..5 {
        let mut cmd = bad;
        match malformed {
            0 => cmd.modifier[0] = 0x0100000000000001,
            1 => cmd.offsets[0] = 4,
            2 => cmd.flags |= 1,
            3 => cmd.pixel_format = 0x30335241,
            _ => cmd.modifier[1] = 1,
        }
        assert!(mode.lock().addfb2_intel(&cmd, o.clone(), 7, true).is_err());
        assert!(!o.scanout());
        assert_eq!(mode.lock().framebuffers.len(), count);
    }
    let id = fb(&mode, o, XR30, 7);
    let frame = mode.lock().framebuffer(id).unwrap().clone();
    let intel = intel_frame(&frame).unwrap();
    let no_wait = Arc::new(NoLegacyWait(AtomicBool::new(false)));
    intel.object.dma_buf.resv.add_fence(
        no_wait.clone(),
        narf_filesystem::dma_buf::DmaResvUsage::Write,
    );
    // The real legacy helper rejects at entry, including before WRITE waits.
    assert_eq!(present_intel_frame(&intel), Err(FsError::Unsupported));
    no_wait.0.store(true, Ordering::Release);
    let touched = AtomicUsize::new(0);
    assert_eq!(
        run(copy_frame_to_query(
            &frame,
            &mode,
            narf_graphics_driver::generic::GenericFb::new(0, 64, 32, 512, 32),
            || {
                touched.fetch_add(1, Ordering::Relaxed);
                None
            },
            || {
                touched.fetch_add(1, Ordering::Relaxed);
            }
        )),
        Err(FsError::Unsupported)
    );
    assert_eq!(touched.load(Ordering::Relaxed), 0);
    request(&cpu, id, 0, 0, NONBLOCK | TEST_ONLY, None);
    assert!(
        admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
    request(&cpu, id, 0, 0, NONBLOCK, None);
    let done = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(done.status(), 1);
    assert_eq!(p.read32(CTL), 0x82000000);
    restore(&worker, &p);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_discovery_addfb_and_copy_boundaries
);

fn smoke_mtl_xr30_raw_fifo_formats_and_projection() -> TestResult {
    let (p, mode, q, mut worker, cpu, events) = fixture();
    let Some(a) = wc_object() else {
        return TestResult::Pass;
    };
    let xr30 = fb(&mode, a, XR30, 7);
    let xr24 = fb(&mode, wc_object().unwrap(), XR24, 7);
    request(&cpu, xr30, 0, 0, NONBLOCK | EVENT, None);
    let first = submit(&q, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    p.allow_flips(false);
    let mut work = Box::pin(q.run(&mut worker));
    pending(work.as_mut());
    #[cfg(target_arch = "x86_64")]
    {
        let commands = p.dsb_commands();
        let ctl = commands
            .iter()
            .position(|&(v, h)| v == 0x82000000 && h >> 24 == 1 && h & 0xfffff == 0x70180)
            .unwrap();
        let offset = commands
            .iter()
            .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == 0x701a4)
            .unwrap();
        let surf = commands
            .iter()
            .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == 0x7019c)
            .unwrap();
        let evade = commands.iter().position(|&(_, h)| h >> 24 == 6).unwrap();
        assert!(evade < offset && offset < ctl && ctl < surf);
    }
    wait_ctl(work.as_mut(), &p, 0x82000000);
    assert_eq!(p.read32(LIVE), CONSOLE);
    assert_eq!((first.status(), fence.status()), (0, 0));
    assert!(mode.lock().crtcs[0].primary_fb.is_none());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    // The previous *queued* format isXR30 even though Card has not published it.
    let flip = [1u32, xr24, 0, 0, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    cpu.write(64, &flip).unwrap();
    assert!(matches!(
        admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP),
        Err(queue::SubmitError::Io(FsError::InvalidData))
    ));
    request(&cpu, xr24, 0, 0, NONBLOCK | EVENT, None);
    let second = submit(&q, &cpu, &events);
    p.allow_flips(true);
    run(work);
    assert_eq!((first.status(), second.status()), (1, 1));
    assert_eq!(p.read32(CTL), 0x84000000);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(xr24));
    assert_eq!(
        p.primary_mappings()
            .iter()
            .filter(|(r, _)| r % 8 == 0)
            .count(),
        4
    );
    restore(&worker, &p);
    // Same-format PAGE_FLIP is an actual raw foreground/FIFO/DSB operation;
    // the projected cross-format refusal above must not reject this old ABI.
    {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let a = fb(&mode, wc_object().unwrap(), XR30, 7);
        let b = fb(&mode, wc_object().unwrap(), XR30, 7);
        request(&cpu, a, 0, 0, NONBLOCK, None);
        let first = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        let old_surface = p.read32(LIVE);
        let old_arms = p.primary_arms();
        let old_dsb_writes = p.dsb_writes().len();
        let flip = [1u32, b, EVENT, 0, 0x30303030, 0x58523330]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cpu.write(64, &flip).unwrap();
        let (done, _, nonblock) =
            admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
                .unwrap()
                .unwrap();
        assert!(!nonblock);
        p.allow_flips(false);
        let mut work = Box::pin(q.run(&mut worker));
        for _ in 0..128 {
            pending(work.as_mut());
            if p.primary_arms() > old_arms {
                break;
            }
        }
        assert!(p.primary_arms() > old_arms);
        assert!(p.dsb_writes().len() > old_dsb_writes);
        assert_eq!(p.read32(CTL), 0x82000000);
        assert_ne!(p.read32(SURF), old_surface);
        assert_eq!(p.read32(LIVE), old_surface);
        assert_eq!(done.status(), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        p.allow_flips(true);
        run(work);
        assert_eq!(done.status(), 1);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
        assert_eq!(p.read32(SURF), p.read32(LIVE));
        let mut event = [0; 32];
        assert_eq!(
            events.lock().read_deliverable_event(u64::MAX, &mut event),
            Some(32)
        );
        assert_eq!(
            u64::from_le_bytes(event[8..16].try_into().unwrap()),
            0x5852333030303030
        );
        restore(&worker, &p);
    }
    for transport in [0, 1] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let b = fb(&mode, wc_object().unwrap(), XR30, 7);
        let gamma = gamma_blob(&mode, false);
        // A LUT update makes the production DSB owner build a real leaf,
        // unlike a format-only main stream with chain=false.
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, Some((0, gamma)));
        let done = submit(&q, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        p.stall_dsb(transport, true);
        let mut work = Box::pin(q.run(&mut worker));
        for _ in 0..8 {
            pending(work.as_mut());
        }
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        if transport == 0 {
            // Only source0 is stalled here; it has not yet started leaf1.
            assert_eq!(p.read32(0x70b08) & 0x80000001, 0x80000001);
            assert_eq!(p.read32(0x70c08) & 0x80000001, 0);
            // Catch the real source-triggered leaf before it can complete.
            p.stall_dsb(1, true);
            p.stall_dsb(0, false);
            for _ in 0..128 {
                pending(work.as_mut());
                if p.read32(0x70c08) & 1 != 0 {
                    break;
                }
            }
        }
        // Source0 actually wrote leaf1's ENABLE/HEAD/TAIL. Its command memory
        // remains reached through the real published GGTT command mappings.
        assert_eq!(p.read32(0x70c08) & 0x80000001, 0x80000001);
        assert!(p.read32(0x70c04) > p.read32(0x70c00));
        assert!(!p.dsb_mappings().is_empty());
        #[cfg(target_arch = "x86_64")]
        {
            assert!(p
                .dsb_stream(0)
                .iter()
                .any(|&(v, h)| v == 0x90000000 && h >> 24 == 1 && h & 0xfffff == 0x70c08));
            // Independent literal: indexed post-CSC precision palette stream.
            assert!(p
                .dsb_stream(1)
                .iter()
                .any(|&(v, h)| v == 1024 && h == (9 << 24) | 0x4a404));
        }
        for _ in 0..8 {
            pending(work.as_mut());
        }
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        p.stall_dsb(1, false);
        run(work);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(p.read32(CTL), 0x82000000);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
        assert_eq!(p.read32(0x70b08) & 0x80000001, 0);
        assert_eq!(p.read32(0x70c08) & 0x80000001, 0);
        restore(&worker, &p);
    }
    {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let b = fb(&mode, wc_object().unwrap(), XR30, 7);
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, None);
        let done = submit(&q, &cpu, &events);
        p.allow_frames(false);
        let mut work = Box::pin(q.run(&mut worker));
        for _ in 0..8 {
            pending(work.as_mut());
        }
        assert_eq!(done.status(), 0);
        p.tear_visible_frame(true);
        p.allow_frames(true);
        for _ in 0..12 {
            pending(work.as_mut());
        }
        assert_eq!(done.status(), 0);
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        p.tear_visible_frame(false);
        run(work);
        assert_eq!(done.status(), 1);
        restore(&worker, &p);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_raw_fifo_formats_and_projection
);

fn smoke_mtl_xr30_same_bo_panning_and_color() -> TestResult {
    let (p, mode, q, mut worker, cpu, events) = fixture();
    let Some(o) = wc_object() else {
        return TestResult::Pass;
    };
    let a = fb(&mode, o.clone(), XR24, 7);
    let b = fb(&mode, o, XR30, 7);
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, false);
    let resources = [
        0x70240, 0x70244, 0x70248, 0x7024c, 0x70250, 0x70254, 0x70268, 0x7017c, 0x7027c, 0x45000,
        0x45004, 0x45230, 0x45234, 0x60400, 0x46140, 0x60540, 0x64000, 0x64004,
    ];
    let saved = resources.map(|r| p.read32(r));
    request(&cpu, a, 0, 0, NONBLOCK, Some((ctm, gamma)));
    let d = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(d.status(), 1);
    let palette = p.precision();
    let writes = p.palette_writes();
    request(&cpu, b, 3, 9, NONBLOCK, None);
    let d = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(d.status(), 1);
    assert_eq!(p.read32(CTL), 0x82000000);
    assert_eq!(p.read32(OFFSET), 0x10003); //4608+12 ->SURF4096+OFFSET(y1,x3)
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, ctm);
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    assert_eq!(p.precision(), palette);
    assert_eq!(p.palette_writes(), writes);
    assert_eq!(resources.map(|r| p.read32(r)), saved);
    request(&cpu, b, 3, 9, NONBLOCK, Some((0, 0)));
    let d = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(d.status(), 1);
    // Repeated allNone XR30 cannot recapture XR24 or erase its format lease.
    let arms = p.primary_arms();
    request(&cpu, b, 3, 9, NONBLOCK, None);
    let d = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(d.status(), 1);
    assert!(p.primary_arms() > arms);
    let gem = crate::intel_gpu_gem::GemState::new();
    let h = gem.create(16384, |_, _| Ok(())).unwrap();
    gem.object(h).unwrap().write(0, &vec![0x7a; 16384]).unwrap();
    for (flags, handle, x, y) in [(3u32, h, 2i32, 3i32), (2, 0, 7, -2), (1, 0, 0, 0)] {
        let wire = [flags, 1, x as u32, y as u32, 64, 64, handle, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cpu.write(64, &wire).unwrap();
        let done = run(admit_with_gem(
            &q,
            7,
            drm_uapi::iowr(u32::from(b'd'), 0xbb, 36),
            64,
            &cpu,
            None,
            geometry(),
            1,
            Some(&gem),
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(CTL), 0x82000000);
        assert_eq!(
            p.read32(0x70080) & 0x27,
            if handle == h || flags == 2 { 0x27 } else { 0 }
        );
    }
    let dirty = [b, 0, 0, 0, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    cpu.write(64, &dirty).unwrap();
    let done = admission(
        &q,
        &cpu,
        &events,
        7,
        drm_uapi::iowr(u32::from(b'd'), 0xb1, 24),
    )
    .unwrap()
    .unwrap()
    .0;
    run(q.run(&mut worker));
    assert_eq!(done.status(), 1);
    assert_eq!(p.read32(CTL), 0x82000000);
    request(&cpu, a, 0, 0, NONBLOCK, None);
    let d = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(d.status(), 1);
    assert_eq!(p.read32(CTL), 0x84000000);
    restore(&worker, &p);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_same_bo_panning_and_color
);

fn smoke_mtl_xr30_unsupported_profiles_before_exposure() -> TestResult {
    // Exact observed source identity, no speculative broad-generation admit.
    let (p, _, _, _, _, _) = fixture();
    let timing = p.dsb_timing();
    for id in [
        0x7d40, 0x7d45, 0x7d55, 0x7d60, 0x7dd5, 0x7d41, 0x7d51, 0x7d67, 0x7dd1, 0xb640,
    ] {
        p.xr30_source(Some(id));
        assert!(crate::intel_gpu_kms::xr30_discovery_profile(
            &p,
            geometry(),
            timing
        ));
    }
    for id in [0x9a49, 0x46a6, 0x6420, 0xe202, 0xffff] {
        p.xr30_source(Some(id));
        assert!(!crate::intel_gpu_kms::xr30_discovery_profile(
            &p,
            geometry(),
            timing
        ));
    }
    p.xr30_source(Some(0x7d40));
    p.xr30_change_epoch_on_read(0x49048, 2);
    assert!(!crate::intel_gpu_kms::xr30_discovery_profile(
        &p,
        geometry(),
        timing
    ));
    assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
    for (register, bad) in [
        (0x510a0, 20 << 22),
        (0x60400, 0x92000006),
        (0x46140, 0x20000000),
        (0x60540, 0x80040000),
        (0x64000, 0),
        (0x64004, 0x31000086),
        (0x70188, 4),
        (0x70190, 0x001e003f),
        (0x70240, 0),
        (0x701cc, 0x2010),
        (0x4804, u32::MAX),
    ] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let b = fb(&mode, o, XR30, 7);
        p.set(register, bad);
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, None);
        let done = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert!(
            done.status() < 0,
            "bad current profile register {register:x}"
        );
        assert!(p.primary_mappings().is_empty());
        assert!(p.dsb_mappings().is_empty());
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
    }
    {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let b = fb(&mode, o, XR30, 7);
        worker.device = Arc::new(p.gen12_pitch(crate::intel_gpu_gt::Gen12Platform::TigerLake, 512));
        request(&cpu, b, 0, 0, NONBLOCK, None);
        let d = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert!(d.status() < 0);
        assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
    }
    // Backend epoch is a separate fact: no first-present discovery bootstrap.
    for epoch in [0, 2] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let b = fb(&mode, o, XR30, 7);
        p.xr30_epoch(epoch);
        if epoch == 0 {
            assert!(!crate::intel_gpu_kms::xr30_discovery_profile(
                &p,
                geometry(),
                p.dsb_timing()
            ));
        }
        // A new source epoch may qualify a new request, but never an old lease.
        request(&cpu, b, 0, 0, NONBLOCK, None);
        let d = if epoch == 0 {
            submit(&q, &cpu, &events)
        } else {
            run(admit(
                &q,
                7,
                drm_uapi::DRM_IOCTL_MODE_ATOMIC,
                64,
                &cpu,
                Some(&events),
                geometry(),
                epoch,
            ))
            .unwrap()
            .unwrap()
            .0
        };
        run(q.run(&mut worker));
        if epoch == 0 {
            assert!(d.status() < 0);
            assert!(p.primary_mappings().is_empty());
        } else {
            assert_eq!(d.status(), 1);
            restore(&worker, &p);
        }
    }
    // Admission checked epoch1, but the real Device session is contended.
    // Recheck after that await: a replacement publication cannot execute this
    // old request or touch PTEs/commands/Card. A new epoch2 request can proceed.
    {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let b = fb(&mode, o, XR30, 7);
        let device = worker.device.clone();
        let held = run(device.session()).unwrap();
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, None);
        let stale = submit(&q, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        let mappings = (p.primary_mappings(), p.dsb_mappings());
        let writes = p.all_writes();
        let arms = p.primary_arms();
        let mut work = Box::pin(q.run(&mut worker));
        for _ in 0..3 {
            pending(work.as_mut());
        }
        assert_eq!((stale.status(), fence.status()), (0, 0));
        assert_eq!((p.primary_mappings(), p.dsb_mappings()), mappings);
        assert_eq!(p.all_writes(), writes);
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        p.xr30_epoch(2);
        drop(held);
        run(work);
        assert!(matches!(stale.result(), Some(Err(FsError::NoDevice))));
        assert_eq!((stale.status(), fence.status()), (-19, -19));
        assert_eq!((p.primary_mappings(), p.dsb_mappings()), mappings);
        assert_eq!(p.all_writes(), writes);
        assert_eq!(p.primary_arms(), arms);
        assert_eq!(p.read32(SURF), CONSOLE);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, None);
        let fresh = run(admit(
            &q,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
            geometry(),
            2,
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!(fresh.status(), 1);
        assert_eq!(p.read32(CTL), 0x82000000);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
        assert!(events.lock().has_deliverable_event(u64::MAX));
        restore(&worker, &p);
    }
    // Actual worker-only extent rejection cannot poison the old tiling lane.
    for modifier in [0x0100000000000001u64, 0x0100000000000009] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let a = fb(&mode, o.clone(), XR24, 7);
        let b = fb(&mode, o.clone(), XR30, 7);
        request(&cpu, b, 0, 0, NONBLOCK, None);
        let d = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(d.status(), 1);
        assert!(crate::intel_gpu_kms::tile4_profile(&p, geometry(), p.dsb_timing()).is_ok());
        {
            let mut card = mode.lock();
            card.intel_x_tiled = true;
            card.intel_tile4 = true;
        }
        let blocked = mode
            .lock()
            .addfb2_intel(
                &crate::drm::fb_cmd::FbCmd {
                    width: 128,
                    height: 96,
                    pixel_format: XR24,
                    handles: [1, 0, 0, 0],
                    pitches: [512, 0, 0, 0],
                    flags: 2,
                    modifier: [modifier, 0, 0, 0],
                    ..Default::default()
                },
                o.clone(),
                7,
                true,
            )
            .unwrap();
        let prior = p.primary_mappings();
        request(&cpu, blocked, 0, 0, NONBLOCK, None);
        assert!(matches!(
            admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        assert_eq!(p.primary_mappings(), prior);
        request(&cpu, a, 0, 0, NONBLOCK, None);
        let d = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(d.status(), 1);
        let gem = crate::intel_gpu_gem::GemState::new();
        let h = gem
            .create_placed(
                4096,
                None,
                crate::intel_gpu_gem::Placement::SystemWc,
                |_, _| Ok(()),
            )
            .unwrap();
        let small = gem.object(h).unwrap();
        small.mark_scanout();
        {
            let mut owner = run(worker.device.session()).unwrap();
            assert_eq!(
                run(owner.present_color(
                    small,
                    geometry(),
                    View {
                        input: InputFormat::Xrgb2101010,
                        ..Default::default()
                    },
                    None,
                    crate::intel_gpu_color::Luts {
                        post: None,
                        pre: None
                    },
                    p.dsb_timing()
                )),
                Err(FsError::InvalidData)
            );
        }
        assert!(crate::intel_gpu_kms::tile4_profile(&p, geometry(), p.dsb_timing()).is_ok());
        {
            let mut c = mode.lock();
            c.intel_x_tiled = true;
            c.intel_tile4 = true;
        }
        let tiled = mode
            .lock()
            .addfb2_intel(
                &crate::drm::fb_cmd::FbCmd {
                    width: 128,
                    height: 96,
                    pixel_format: XR24,
                    handles: [1, 0, 0, 0],
                    pitches: [512, 0, 0, 0],
                    flags: 2,
                    modifier: [modifier, 0, 0, 0],
                    ..Default::default()
                },
                o,
                7,
                true,
            )
            .unwrap();
        request(&cpu, tiled, 0, 0, NONBLOCK, None);
        let d = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(d.status(), 1);
        assert_eq!(
            p.read32(CTL),
            if modifier == 0x0100000000000001 {
                0x84000400
            } else {
                0x84001400
            }
        );
        // Nonlinear->XR30 refuses in raw foreground, before any new stream.
        let mappings = p.primary_mappings();
        let streams = p.dsb_mappings();
        request(&cpu, b, 0, 0, NONBLOCK, None);
        assert!(matches!(
            admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        assert_eq!(p.primary_mappings(), mappings);
        assert_eq!(p.dsb_mappings(), streams);
        restore(&worker, &p);
    }
    // Direct owner-future cancellation is distinct from dropping a raw waiter.
    // Both noPresenter and retainedXR24presenter must reconcile on explicitrestore.
    for previous in [false, true] {
        for explicit_restore in [false, true] {
            let (p, mode, q, mut worker, cpu, events) = fixture();
            let Some(o) = wc_object() else {
                return TestResult::Pass;
            };
            let a = fb(&mode, o.clone(), XR24, 7);
            if previous {
                request(&cpu, a, 0, 0, NONBLOCK, None);
                let d = submit(&q, &cpu, &events);
                run(q.run(&mut worker));
                assert_eq!(d.status(), 1);
            }
            let before_pause = p.primary_mappings();
            let mut owner = run(worker.device.session()).unwrap();
            p.block_pause(true);
            let mut intent = Box::pin(owner.present_color(
                o.clone(),
                geometry(),
                View {
                    input: InputFormat::Xrgb2101010,
                    ..Default::default()
                },
                None,
                crate::intel_gpu_color::Luts {
                    pre: None,
                    post: None,
                },
                p.dsb_timing(),
            ));
            pending(intent.as_mut());
            assert_eq!(p.primary_mappings(), before_pause);
            assert_eq!(p.read32(CTL), 0x84000000);
            assert!(p.dsb_mappings().is_empty());
            drop(intent);
            p.block_pause(false);
            if explicit_restore {
                run(owner.restore_console()).unwrap();
            }
            drop(owner);
            assert_eq!(p.read32(CTL), 0x84000000);
            if explicit_restore {
                assert!(p.primary_mappings().is_empty());
            }
            assert!(crate::intel_gpu_kms::tile4_profile(&p, geometry(), p.dsb_timing()).is_ok());
            mode.lock().intel_tile4 = true;
            let tiled = mode
                .lock()
                .addfb2_intel(
                    &crate::drm::fb_cmd::FbCmd {
                        width: 128,
                        height: 96,
                        pixel_format: XR24,
                        handles: [1, 0, 0, 0],
                        pitches: [512, 0, 0, 0],
                        flags: 2,
                        modifier: [0x0100000000000009, 0, 0, 0],
                        ..Default::default()
                    },
                    o,
                    7,
                    true,
                )
                .unwrap();
            request(&cpu, tiled, 0, 0, NONBLOCK, None);
            let d = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert_eq!(d.status(), 1);
            assert_eq!(p.read32(CTL), 0x84001400);
            restore(&worker, &p);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_unsupported_profiles_before_exposure
);

fn smoke_mtl_xr30_partial_cancel_master_close_retention() -> TestResult {
    for refused in [u64::MAX, CTL, OFFSET, SURF] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let weak = Arc::downgrade(&o);
        let b = fb(&mode, o, XR30, 7);
        request(&cpu, b, 3, 9, NONBLOCK | EVENT, None);
        let done = submit(&q, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        p.allow_flips(false);
        p.refuse_layout(refused);
        let mut work = Box::pin(q.run(&mut worker));
        for _ in 0..8 {
            pending(work.as_mut());
        }
        let mappings = p.primary_mappings();
        let streams = p.dsb_mappings();
        assert!(!mappings.is_empty() && !streams.is_empty());
        drop(work);
        assert!(done.status() < 0 && fence.status() < 0);
        assert!(worker.device.legacy().is_err());
        events.lock().close();
        {
            let mut card = mode.lock();
            card.release_file_framebuffers(7);
            card.master_release(7);
        }
        assert!(weak.upgrade().is_some());
        assert_eq!(p.primary_mappings(), mappings);
        assert_eq!(p.dsb_mappings(), streams);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        // A GT reset alone is not enough. The actual fresh display owner must
        // separately drain both streams and prove the exact original console.
        p.refuse_layout(u64::MAX);
        p.allow_flips(true);
        p.xr30_epoch(0);
        p.poison();
        assert_eq!(p.primary_mappings(), mappings);
        run(worker.device.recover()).unwrap();
        assert_eq!(
            (p.read32(CTL), p.read32(LIVE), p.read32(OFFSET)),
            (0x84000000, CONSOLE, 0)
        );
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), streams);
        assert!(weak.upgrade().is_none());
    }
    // Dropping the real blocking caller's Completion waiter leaves the
    // owned raw FIFO worker running; it is NOT worker/owner cancellation.
    {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let weak = Arc::downgrade(&o);
        let b = fb(&mode, o, XR30, 7);
        request(&cpu, b, 0, 0, EVENT, None);
        let (done, _, nonblock) = admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .unwrap();
        assert!(!nonblock);
        let fence = cpu.exported.lock()[0].clone();
        p.allow_flips(false);
        let mut work = Box::pin(q.run(&mut worker));
        wait_ctl(work.as_mut(), &p, 0x82000000);
        let mut caller = Box::pin(done.result_async());
        pending(caller.as_mut());
        drop(caller);
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert!(weak.upgrade().is_some());
        assert!(mode.lock().crtcs[0].primary_fb.is_none());
        p.allow_flips(true);
        run(work);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
        assert_eq!(p.read32(CTL), 0x82000000);
        restore(&worker, &p);
    }
    // Same live MMIO after backend replacement cannot complete an old epoch.
    let (p, mode, q, mut worker, cpu, events) = fixture();
    let Some(o) = wc_object() else {
        return TestResult::Pass;
    };
    let b = fb(&mode, o, XR30, 7);
    request(&cpu, b, 0, 0, NONBLOCK | EVENT, None);
    let done = submit(&q, &cpu, &events);
    p.allow_flips(false);
    let mut work = Box::pin(q.run(&mut worker));
    wait_ctl(work.as_mut(), &p, 0x82000000);
    let mappings = p.primary_mappings();
    p.xr30_epoch(2);
    p.allow_flips(true);
    run(work);
    assert!(done.status() < 0);
    assert_eq!(p.primary_mappings(), mappings);
    assert!(mode.lock().crtcs[0].primary_fb.is_none());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    p.xr30_epoch(0);
    p.poison();
    run(worker.device.recover()).unwrap();
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_partial_cancel_master_close_retention
);

fn smoke_mtl_xr30_original_console_and_fresh_reset() -> TestResult {
    for fresh in [false, true] {
        let (p, mode, q, mut worker, cpu, events) = fixture();
        let Some(o) = wc_object() else {
            return TestResult::Pass;
        };
        let b = fb(&mode, o, XR30, 7);
        let ctm = blob(&mode);
        let gamma = gamma_blob(&mode, true);
        let original = p.precision();
        request(&cpu, b, 3, 9, NONBLOCK, Some((ctm, gamma)));
        let done = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(CTL), 0x82000000);
        assert_eq!(p.read32(crate::intel_gpu_color::MODE), 1 << 31);
        let before = p.all_writes().len();
        if fresh {
            p.xr30_epoch(0);
            p.poison();
            run(worker.device.recover()).unwrap();
        } else {
            let drop_master = admission(&q, &cpu, &events, 7, drm_uapi::io(u32::from(b'd'), 0x1f))
                .unwrap()
                .unwrap()
                .0;
            run(q.run(&mut worker));
            assert_eq!(drop_master.status(), 1);
            assert!(!mode.lock().has_master());
        }
        let writes = p.all_writes();
        let writes = &writes[before..];
        let console = writes
            .iter()
            .position(|&(r, v)| r == SURF && v == CONSOLE)
            .unwrap();
        let control = writes
            .iter()
            .position(|&(r, v)| r == CTL && v == 0x84000000)
            .unwrap();
        let color = writes
            .iter()
            .position(|&(r, v)| r == crate::intel_gpu_color::MODE && v == 0)
            .unwrap();
        assert!(if fresh {
            control < console && console < color
        } else {
            color < control && control < console
        });
        assert_eq!(
            (
                p.read32(CTL),
                p.read32(0x70188),
                p.read32(OFFSET),
                p.read32(LIVE)
            ),
            (0x84000000, 8, 0, CONSOLE)
        );
        assert_eq!(p.read32(crate::intel_gpu_color::MODE), 0);
        assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(p.precision(), original);
        assert!(p.primary_mappings().is_empty());
        // Source/leaf transport is disabled before fresh recovery can restore;
        // normal restoration likewise never treats command IRQ as fetchstop.
        assert_eq!(p.read32(0x70b08) & 0x80000001, 0);
        assert_eq!(p.read32(0x70c08) & 0x80000001, 0);
        assert!(!writes.is_empty());
    }
    // Real per-card quiesce entry runs from an actual scheduler task. No
    // block_on bridge, scheduler reset, permanent pump or physicalOwner claim.
    let (p, mode, q, mut worker, cpu, events) = fixture();
    let Some(o) = wc_object() else {
        return TestResult::Pass;
    };
    let b = fb(&mode, o, XR30, 7);
    request(&cpu, b, 0, 0, NONBLOCK, None);
    let done = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(done.status(), 1);
    let result = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let completed = result.clone();
    let device = worker.device.clone();
    narf_scheduler::spawn(async move {
        let task = narf_scheduler::current_task_id() != narf_scheduler::TaskId::NONE;
        let good = device.quiesce().await.is_ok();
        completed.store(if task && good { 1 } else { 2 }, Ordering::Release);
    });
    assert!(narf_scheduler::responsive_spin_until(
        || {
            narf_scheduler::poll_one_round_nested();
            result.load(Ordering::Acquire) != 0
        },
        narf_time::Deadline::after_ns(1_000_000_000)
    ));
    assert_eq!(result.load(Ordering::Acquire), 1);
    assert_eq!((p.read32(CTL), p.read32(LIVE)), (0x84000000, CONSOLE));
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_mtl_xr30_original_console_and_fresh_reset
);

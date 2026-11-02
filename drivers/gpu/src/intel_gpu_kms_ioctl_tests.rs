use super::*;
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicUsize};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Cpu {
    bytes: IrqSafeSpinLock<[u8; 4096]>,
    bad_write: AtomicBool,
    writes: AtomicUsize,
    fail_after: AtomicUsize,
    no_descriptor: AtomicBool,
    exported: IrqSafeSpinLock<Vec<Arc<dyn narf_filesystem::DrmFence>>>,
    inputs: IrqSafeSpinLock<Vec<Arc<dyn narf_filesystem::DrmFence>>>,
}
impl Cpu {
    fn new() -> Self {
        Self {
            bytes: IrqSafeSpinLock::new([0; 4096]),
            bad_write: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            fail_after: AtomicUsize::new(usize::MAX),
            no_descriptor: AtomicBool::new(false),
            exported: IrqSafeSpinLock::new(Vec::new()),
            inputs: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
impl IoctlContext for Cpu {
    fn read(&self, address: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(address).map_err(|_| FsError::BadAddress)?;
        let end = start
            .checked_add(dst.len())
            .filter(|n| *n <= 4096)
            .ok_or(FsError::BadAddress)?;
        dst.copy_from_slice(&self.bytes.lock()[start..end]);
        Ok(())
    }
    fn write(&self, address: u64, src: &[u8]) -> Result<(), FsError> {
        if self.bad_write.load(Ordering::Acquire)
            || self.writes.fetch_add(1, Ordering::AcqRel) >= self.fail_after.load(Ordering::Acquire)
        {
            return Err(FsError::BadAddress);
        }
        let start = usize::try_from(address).map_err(|_| FsError::BadAddress)?;
        let end = start
            .checked_add(src.len())
            .filter(|n| *n <= 4096)
            .ok_or(FsError::BadAddress)?;
        self.bytes.lock()[start..end].copy_from_slice(src);
        Ok(())
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn narf_filesystem::DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        if self.no_descriptor.load(Ordering::Acquire) {
            return Err(narf_filesystem::InstallFdError::NoDescriptor);
        }
        report(41).map_err(narf_filesystem::InstallFdError::Report)?;
        self.exported.lock().extend(fences);
        Ok(41)
    }
    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        (fd == 9).then(|| self.inputs.lock().clone())
    }
    fn nonblocking(&self) -> bool {
        false
    }
}
struct Device {
    ready: Arc<AtomicBool>,
    fail: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    presents: Arc<AtomicUsize>,
    copies: Arc<AtomicUsize>,
    unsupported: Arc<AtomicBool>,
    invalid: Arc<AtomicBool>,
}
impl Device {
    fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            fail: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            presents: Arc::new(AtomicUsize::new(0)),
            copies: Arc::new(AtomicUsize::new(0)),
            unsupported: Arc::new(AtomicBool::new(false)),
            invalid: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Backend for Device {
    fn valid(&self) -> Result<(), FsError> {
        if self.invalid.load(Ordering::Acquire) {
            Err(FsError::NoDevice)
        } else {
            Ok(())
        }
    }
    fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb {
        narf_graphics_driver::generic::GenericFb::new(0, 64, 32, 256, 32)
    }
    fn geometry(&self) -> Geometry {
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        }
    }
    fn check(&self, g: Geometry) -> Result<(), FsError> {
        if g == self.geometry() {
            Ok(())
        } else {
            Err(FsError::Unsupported)
        }
    }
    fn present<'a>(
        &'a mut self,
        _: Arc<crate::intel_gpu_gem::GemObject>,
        _: Geometry,
    ) -> FsFuture<'a, FlipStamp> {
        self.presents.fetch_add(1, Ordering::AcqRel);
        if self.unsupported.load(Ordering::Acquire) {
            return alloc::boxed::Box::pin(async { Err(FsError::Unsupported) });
        }
        self.vblank()
    }
    fn copy<'a>(&'a mut self, _: &'a Framebuffer, _: &'a ModeState) -> FsFuture<'a, ()> {
        self.copies.fetch_add(1, Ordering::AcqRel);
        alloc::boxed::Box::pin(async { Ok(()) })
    }
    fn restore(&mut self) -> FsFuture<'_, ()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        alloc::boxed::Box::pin(async { Ok(()) })
    }
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        alloc::boxed::Box::pin(core::future::poll_fn(|_| {
            if self.fail.load(Ordering::Acquire) {
                Poll::Ready(Err(FsError::TimedOut))
            } else if self.ready.load(Ordering::Acquire) {
                Poll::Ready(Ok(FlipStamp {
                    ns: 1234567000,
                    sequence: 77,
                }))
            } else {
                Poll::Pending
            }
        }))
    }
}
fn mode() -> ModeState {
    let mut card = Card::new("intel-gpu", "Intel test", (1, 0, 0));
    card.native_atomic = true;
    card.crtcs.push(Crtc {
        id: 1,
        mode: Some(crate::Mode {
            width: 64,
            height: 32,
            refresh_hz: 60,
            bpp: 32,
        }),
        enabled: true,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    card.master_open(7);
    Arc::new(IrqSafeSpinLock::new(card))
}
fn disable(flags: u32) -> Request {
    Request::Atomic(OwnedAtomic {
        flags,
        cookie: 0xfeedcafe,
        objects: vec![1],
        counts: vec![3],
        props: vec![
            CRTC_ACTIVE_PROP_ID,
            CRTC_MODE_ID_PROP_ID,
            CRTC_OUT_FENCE_PTR_PROP_ID,
        ],
        values: vec![0, 0, 128],
    })
}

fn intel_kms_signals_follow_latch_and_cancellation_refunds_space() -> TestResult {
    let mode = mode();
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let out = OutFences::new(Vec::new());
    let mut device = Device::new();
    let ready = device.ready.clone();
    {
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            disable(EVENT | ALLOW_MODESET | NONBLOCK),
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert!(mode.lock().crtcs[0].enabled);
        assert!(mode.lock().intel_transaction_busy());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(out.lock().is_empty());
        assert_eq!(&cpu.bytes.lock()[128..132], &(-1i32).to_le_bytes());
        ready.store(true, Ordering::Release);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
    }
    assert!(!mode.lock().crtcs[0].enabled);
    assert!(!mode.lock().intel_transaction_busy());
    assert_eq!(*out.lock(), vec![(128, 1234567000)]);
    let mut bytes = [0; 32];
    assert_eq!(
        events.lock().read_deliverable_event(1234566999, &mut bytes),
        None
    );
    assert_eq!(
        events.lock().read_deliverable_event(1234567000, &mut bytes),
        Some(32)
    );
    assert_eq!(
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        0xfeedcafe
    );
    assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 77);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_signals_follow_latch_and_cancellation_refunds_space
);

fn intel_kms_failure_and_cancel_publish_no_state_or_success() -> TestResult {
    for failure in [false, true] {
        let mode = mode();
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let out = OutFences::new(Vec::new());
        let mut device = Device::new();
        let fail = device.fail.clone();
        {
            let mut call = core::pin::pin!(execute(
                &mut device,
                &mode,
                7,
                disable(EVENT | ALLOW_MODESET),
                &cpu,
                Some(&events),
                Some(&out)
            ));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            );
            if failure {
                fail.store(true, Ordering::Release);
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(FsError::TimedOut))
                );
            }
        }
        assert!(mode.lock().crtcs[0].enabled);
        assert!(!mode.lock().intel_transaction_busy());
        assert!(out.lock().is_empty());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_failure_and_cancel_publish_no_state_or_success
);

fn intel_kms_test_only_and_output_fault_do_not_touch_device() -> TestResult {
    for test in [false, true] {
        let mode = mode();
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let out = OutFences::new(Vec::new());
        let mut device = Device::new();
        let calls = device.calls.clone();
        cpu.bad_write.store(true, Ordering::Release);
        let flags = ALLOW_MODESET | if test { TEST_ONLY } else { EVENT };
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            disable(flags),
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(if test {
                Ok(0)
            } else {
                Err(FsError::BadAddress)
            })
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(mode.lock().crtcs[0].enabled);
        assert!(out.lock().is_empty());
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_test_only_and_output_fault_do_not_touch_device
);

fn framebuffer(mode: &ModeState, owner: u64, wc: bool) -> Result<u32, FsError> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let handle = gem.create_placed(
        8192,
        None,
        if wc {
            Placement::SystemWc
        } else {
            Placement::System
        },
        |_, _| Ok(()),
    )?;
    let object = gem.object(handle)?;
    let cmd = crate::drm::fb_cmd::FbCmd {
        width: 64,
        height: 32,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [handle, 0, 0, 0],
        pitches: [256, 0, 0, 0],
        ..Default::default()
    };
    mode.lock()
        .addfb2_intel(&cmd, object, owner, true)
        .map_err(|_| FsError::InvalidData)
}
fn atomic_frame(fb: u32, flags: u32) -> Request {
    Request::Atomic(OwnedAtomic {
        flags,
        cookie: 0x11223344,
        objects: vec![PLANE_ID_BASE, 1],
        counts: vec![2, 1],
        props: vec![
            PLANE_FB_ID_PROP_ID,
            PLANE_CRTC_ID_PROP_ID,
            CRTC_OUT_FENCE_PTR_PROP_ID,
        ],
        values: vec![fb as u64, 1, 128],
    })
}

fn intel_kms_copy_fallback_restores_before_copy_and_waits_real_vblank() -> TestResult {
    let mode = mode();
    let target = framebuffer(&mode, 7, false).expect("WB framebuffer");
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let out = OutFences::new(Vec::new());
    let mut device = Device::new();
    let (ready, copies, presents, calls) = (
        device.ready.clone(),
        device.copies.clone(),
        device.presents.clone(),
        device.calls.clone(),
    );
    {
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            atomic_frame(target, EVENT),
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert_eq!(copies.load(Ordering::Acquire), 1);
        assert_eq!(presents.load(Ordering::Acquire), 0);
        assert_eq!(calls.load(Ordering::Acquire), 2); // restore followed by hardware vblank observation
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert!(out.lock().is_empty());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        ready.store(true, Ordering::Release);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
    }
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(target));
    assert_eq!(*out.lock(), vec![(128, 1234567000)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_copy_fallback_restores_before_copy_and_waits_real_vblank
);

fn intel_kms_deferred_close_cannot_publish_removed_framebuffer() -> TestResult {
    let mode = mode();
    let target = framebuffer(&mode, 8, false).expect("foreign framebuffer");
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let out = OutFences::new(Vec::new());
    let mut device = Device::new();
    let ready = device.ready.clone();
    {
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            atomic_frame(target, EVENT),
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert_eq!(mode.lock().release_file_framebuffers(8), 0);
        assert!(mode.lock().framebuffer(target).is_ok());
        ready.store(true, Ordering::Release);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(FsError::Busy))
        );
    }
    assert!(mode.lock().framebuffer(target).is_err());
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    assert!(out.lock().is_empty());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_deferred_close_cannot_publish_removed_framebuffer
);

fn intel_kms_atomic_shapes_and_fence_errors_leave_hardware_untouched() -> TestResult {
    let mode = mode();
    let target = framebuffer(&mode, 7, false).expect("framebuffer");
    let cpu = Cpu::new();
    for (prop, value, error) in [
        (PLANE_SRC_X_PROP_ID, 1, FsError::InvalidData),
        (PLANE_CRTC_X_PROP_ID, 1, FsError::Unsupported),
        (
            PLANE_CRTC_ID_PROP_ID,
            u64::from(u32::MAX) + 1,
            FsError::InvalidData,
        ),
        (PLANE_IN_FENCE_FD_PROP_ID, 8, FsError::InvalidData),
    ] {
        let Request::Atomic(mut a) = atomic_frame(target, 0) else {
            unreachable!()
        };
        a.counts[0] += 1;
        a.props.insert(2, prop);
        a.values.insert(2, value);
        let mut device = Device::new();
        let calls = device.calls.clone();
        let out = OutFences::new(Vec::new());
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            Request::Atomic(a),
            &cpu,
            None,
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(error))
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_atomic_shapes_and_fence_errors_leave_hardware_untouched
);

fn intel_kms_public_wc_primary_flips_reach_direct_backend() -> TestResult {
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(framebuffer(&mode(), 7, true), Err(FsError::NotImplemented));
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    {
        for page_flip in [false, true] {
            let mode = mode();
            let old = framebuffer(&mode, 7, true).expect("old WC");
            let target = framebuffer(&mode, 7, true).expect("new WC");
            mode.lock().crtcs[0].primary_fb = Some(old);
            let request = if page_flip {
                Request::PageFlip(DrmModePageFlipUapi {
                    crtc_id: 1,
                    fb_id: target,
                    flags: EVENT,
                    reserved: 0,
                    user_data: 0x77,
                })
            } else {
                atomic_frame(target, EVENT | NONBLOCK)
            };
            let cpu = Cpu::new();
            let events = Events::new(IrqSafeSpinLock::new(Default::default()));
            let out = OutFences::new(Vec::new());
            let mut device = Device::new();
            let (ready, presents, copies) = (
                device.ready.clone(),
                device.presents.clone(),
                device.copies.clone(),
            );
            {
                let mut call = core::pin::pin!(execute(
                    &mut device,
                    &mode,
                    7,
                    request,
                    &cpu,
                    Some(&events),
                    Some(&out)
                ));
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                );
                assert_eq!(mode.lock().crtcs[0].primary_fb, Some(old));
                assert_eq!(presents.load(Ordering::Acquire), 1);
                assert_eq!(copies.load(Ordering::Acquire), 0);
                assert!(out.lock().is_empty());
                assert!(!events.lock().has_deliverable_event(u64::MAX));
                ready.store(true, Ordering::Release);
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(0))
                );
            }
            assert_eq!(mode.lock().crtcs[0].primary_fb, Some(target));
            assert!(events.lock().has_deliverable_event(u64::MAX));
        }
        TestResult::Pass
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_public_wc_primary_flips_reach_direct_backend
);

fn intel_kms_wc_admission_falls_back_only_before_hardware_arm() -> TestResult {
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(framebuffer(&mode(), 7, true), Err(FsError::NotImplemented));
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    {
        for hard in [false, true] {
            let mode = mode();
            let old = framebuffer(&mode, 7, true).expect("old");
            let target = framebuffer(&mode, 7, true).expect("target");
            mode.lock().crtcs[0].primary_fb = Some(old);
            let cpu = Cpu::new();
            let events = Events::new(IrqSafeSpinLock::new(Default::default()));
            let out = OutFences::new(Vec::new());
            let mut device = Device::new();
            device.ready.store(true, Ordering::Release);
            device.fail.store(hard, Ordering::Release);
            device.unsupported.store(!hard, Ordering::Release);
            let copies = device.copies.clone();
            {
                let mut call = core::pin::pin!(execute(
                    &mut device,
                    &mode,
                    7,
                    atomic_frame(target, EVENT),
                    &cpu,
                    Some(&events),
                    Some(&out)
                ));
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(if hard { Err(FsError::TimedOut) } else { Ok(0) })
                );
            }
            assert_eq!(copies.load(Ordering::Acquire), usize::from(!hard));
            assert_eq!(
                mode.lock().crtcs[0].primary_fb,
                Some(if hard { old } else { target })
            );
            assert_eq!(events.lock().has_deliverable_event(u64::MAX), !hard);
            assert_eq!(out.lock().is_empty(), hard);
        }
        TestResult::Pass
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_wc_admission_falls_back_only_before_hardware_arm
);

fn atomic_wire(cpu: &Cpu, flags: u32, count: u32, props: u32) {
    let mut bytes = [0; 56];
    bytes[0..4].copy_from_slice(&flags.to_le_bytes());
    bytes[4..8].copy_from_slice(&count.to_le_bytes());
    for (off, ptr) in [(8, 128u64), (16, 144), (24, 160), (32, 192)] {
        bytes[off..off + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    cpu.write(64, &bytes).expect("header");
    cpu.write(128, &PLANE_ID_BASE.to_le_bytes())
        .expect("object");
    cpu.write(144, &props.to_le_bytes()).expect("count");
    cpu.write(160, &PLANE_FB_ID_PROP_ID.to_le_bytes())
        .expect("prop");
}
fn intel_kms_nested_requests_are_owned_and_bounded() -> TestResult {
    let mode = mode();
    let old = framebuffer(&mode, 7, false).expect("old");
    let first = framebuffer(&mode, 7, false).expect("first");
    let replacement = framebuffer(&mode, 7, false).expect("replacement");
    mode.lock().crtcs[0].primary_fb = Some(old);
    let cpu = Cpu::new();
    atomic_wire(&cpu, 0, 1, 1);
    cpu.write(192, &u64::from(first).to_le_bytes())
        .expect("value");
    let request = Request::copy(drm_uapi::DRM_IOCTL_MODE_ATOMIC, 64, &cpu).expect("owned request");
    cpu.write(192, &u64::from(replacement).to_le_bytes())
        .expect("raced user overwrite");
    let mut device = Device::new();
    device.ready.store(true, Ordering::Release);
    {
        let mut call = core::pin::pin!(execute(&mut device, &mode, 7, request, &cpu, None, None));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
    }
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(first));
    for (flags, count, props, error) in [
        (2, 1, 1, FsError::InvalidData),
        (EVENT | TEST_ONLY, 1, 1, FsError::InvalidData),
        (0, 257, 1, FsError::InvalidData),
        (0, 1, 4097, FsError::OutOfMemory),
    ] {
        atomic_wire(&cpu, flags, count, props);
        assert!(
            matches!(Request::copy(drm_uapi::DRM_IOCTL_MODE_ATOMIC,64,&cpu),Err(e) if e==error)
        );
    }
    atomic_wire(&cpu, 0, 1, 1);
    cpu.write(72, &0u64.to_le_bytes())
        .expect("null object array");
    assert!(matches!(
        Request::copy(drm_uapi::DRM_IOCTL_MODE_ATOMIC, 64, &cpu),
        Err(FsError::BadAddress)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_nested_requests_are_owned_and_bounded
);

fn intel_kms_event_exhaustion_precedes_hardware_or_output_publication() -> TestResult {
    let mode = mode();
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let out = OutFences::new(Vec::new());
    for cookie in 0..128 {
        FlipEventReservation::reserve(&events)
            .expect("space")
            .complete(cookie, 1, FlipStamp { ns: 1, sequence: 1 });
    }
    let mut device = Device::new();
    device.ready.store(true, Ordering::Release);
    let calls = device.calls.clone();
    {
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            disable(EVENT | ALLOW_MODESET),
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(FsError::OutOfMemory))
        );
    }
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(mode.lock().crtcs[0].enabled);
    assert!(!mode.lock().intel_transaction_busy());
    assert!(out.lock().is_empty());
    assert_eq!(&cpu.bytes.lock()[128..132], &[0; 4]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_event_exhaustion_precedes_hardware_or_output_publication
);

fn intel_kms_metadata_observation_preserves_initial_console_state() -> TestResult {
    let mode = mode();
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let out = OutFences::new(Vec::new());
    let mut device = Device::new();
    let ready = device.ready.clone();
    let request = Request::Atomic(OwnedAtomic {
        flags: EVENT | NONBLOCK,
        cookie: 99,
        objects: vec![1],
        counts: vec![1],
        props: vec![CRTC_OUT_FENCE_PTR_PROP_ID],
        values: vec![128],
    });
    {
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            request,
            &cpu,
            Some(&events),
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert!(mode.lock().crtcs[0].enabled);
        assert!(mode.lock().crtcs[0].mode.is_some());
        assert!(out.lock().is_empty());
        ready.store(true, Ordering::Release);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
    }
    let card = mode.lock();
    assert!(card.crtcs[0].enabled);
    assert!(card.crtcs[0].mode.is_some());
    assert_eq!(card.crtcs[0].primary_fb, None);
    assert_eq!(*out.lock(), vec![(128, 1234567000)]);
    assert!(events.lock().has_deliverable_event(u64::MAX));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_metadata_observation_preserves_initial_console_state
);

fn intel_kms_test_only_matches_source_bounds_without_hardware_or_waits() -> TestResult {
    let mode = mode();
    let target = framebuffer(&mode, 7, false).expect("framebuffer");
    mode.lock()
        .framebuffers
        .iter_mut()
        .find(|f| f.id == target)
        .expect("target")
        .pitch = 128;
    let cpu = Cpu::new();
    for flags in [0, TEST_ONLY] {
        let mut device = Device::new();
        let calls = device.calls.clone();
        let out = OutFences::new(Vec::new());
        let mut call = core::pin::pin!(execute(
            &mut device,
            &mode,
            7,
            atomic_frame(target, flags),
            &cpu,
            None,
            Some(&out)
        ));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(FsError::InvalidData))
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert!(!mode.lock().intel_transaction_busy());
    }
    assert!(Plan::stage(
        &mode.lock(),
        Request::Property {
            object: PLANE_ID_BASE,
            kind: DRM_MODE_OBJECT_CRTC,
            prop: PLANE_FB_ID_PROP_ID,
            value: target as u64
        },
        Geometry {
            width: 64,
            height: 32,
            pitch: 256
        }
    )
    .is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_test_only_matches_source_bounds_without_hardware_or_waits
);

fn intel_kms_real_copy_uses_mapped_console_alias_and_preserves_padding() -> TestResult {
    use crate::intel_gpu_gem::GemState;
    let mode = mode();
    let gem = GemState::new();
    let handle = gem.create(4096, |_, _| Ok(())).expect("WB source");
    let object = gem.object(handle).expect("source");
    let mut source = vec![0x5c; 4096];
    for row in 0..3usize {
        for byte in 0..68usize {
            source[row * 128 + byte] = (row * 71 + byte) as u8;
        }
    }
    object.write(0, &source).expect("source pixels");
    let cmd = crate::drm::fb_cmd::FbCmd {
        width: 17,
        height: 3,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [handle, 0, 0, 0],
        pitches: [128, 0, 0, 0],
        ..Default::default()
    };
    let id = mode
        .lock()
        .addfb2_intel(&cmd, object, 7, false)
        .expect("source framebuffer");
    let frame = mode.lock().framebuffer(id).expect("frame").clone();
    gem.close(handle)
        .expect("framebuffer retains the closed GEM source");
    let console = narf_graphics_driver::generic::GenericFb::new(0x12345000, 17, 3, 128, 32);
    let mut destination = vec![0xa5u8; 16 + 3 * 128 + 16];
    // Mirrors fb GenericScanout/external_scanout_geom: the same physical
    // console identity plus its retained mapped alias, not virt == 0.
    let info = crate::drm_fb_hook::ScanoutGeom {
        phys: 0x12345000,
        width: 17,
        height: 3,
        stride_bytes: 128,
        virt: destination.as_mut_ptr() as u64 + 16,
    };
    let claims = AtomicUsize::new(0);
    {
        let mut copy = core::pin::pin!(copy_frame_to_query(
            &frame,
            &mode,
            console,
            || Some(info),
            || {
                claims.fetch_add(1, Ordering::AcqRel);
            }
        ));
        assert_eq!(
            copy.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        );
    }
    assert_eq!(claims.load(Ordering::Acquire), 1);
    assert!(destination[..16].iter().all(|b| *b == 0xa5));
    assert!(destination[16 + 3 * 128..].iter().all(|b| *b == 0xa5));
    for row in 0..3usize {
        assert_eq!(
            &destination[16 + row * 128..16 + row * 128 + 68],
            &source[row * 128..row * 128 + 68]
        );
        assert!(destination[16 + row * 128 + 68..16 + (row + 1) * 128]
            .iter()
            .all(|b| *b == 0xa5));
    }
    for mismatch in 0..5 {
        destination.fill(0xa5);
        claims.store(0, Ordering::Release);
        let mut changed = info;
        match mismatch {
            0 => changed.phys += 4096,
            1 => changed.width += 1,
            2 => changed.height += 1,
            3 => changed.stride_bytes += 64,
            _ => {}
        }
        let query = if mismatch == 4 { None } else { Some(changed) };
        let mut copy = core::pin::pin!(copy_frame_to_query(
            &frame,
            &mode,
            console,
            || query,
            || {
                claims.fetch_add(1, Ordering::AcqRel);
            }
        ));
        assert_eq!(
            copy.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(if mismatch == 4 {
                FsError::NoDevice
            } else {
                FsError::Busy
            }))
        );
        assert_eq!(claims.load(Ordering::Acquire), 0);
        assert!(destination.iter().all(|b| *b == 0xa5));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_real_copy_uses_mapped_console_alias_and_preserves_padding
);

#[path = "intel_gpu_kms_queue_tests.rs"]
mod nonblock;

#[path = "intel_gpu_color_ioctl_tests.rs"]
mod color;

#[path = "intel_gpu_cursor_ioctl_tests.rs"]
mod cursor;

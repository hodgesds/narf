//! DIRTYFB and FB_DAMAGE_CLIPS through the Intel KMS transaction path, on
//! both architectures: `drm_ioctl` / `drm_mode_dirtyfb_ioctl`'s errno order,
//! `drm_atomic_helper_dirtyfb`'s damage, `drm_atomic_set_property` and
//! `drm_property_replace_blob_from_id` on the FB_DAMAGE_CLIPS blob, and the
//! plan's damage reaching the display owner. Linux b90c984d.
use super::*;
use crate::drm::fb_cmd::{Damage, Rect};

/// `DRM_IOWR('d', 0xB1, struct drm_mode_fb_dirty_cmd)`.
const DIRTYFB: u32 = 0xc018_64b1;

fn put_dirty(cpu: &Cpu, at: usize, fb: u32, flags: u32, num_clips: u32, clips_ptr: u64) {
    let mut bytes = cpu.bytes.lock();
    for (i, word) in [fb, flags, 0xdead_beef, num_clips].into_iter().enumerate() {
        bytes[at + 4 * i..at + 4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes[at + 16..at + 24].copy_from_slice(&clips_ptr.to_le_bytes());
}

fn put_clips(cpu: &Cpu, at: usize, rects: &[[u16; 4]]) {
    let mut bytes = cpu.bytes.lock();
    for (i, rect) in rects.iter().enumerate() {
        for (j, v) in rect.iter().enumerate() {
            let o = at + 8 * i + 2 * j;
            bytes[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// One DIRTYFB admission: `None` when admitted, else its error.
fn admit_dirty(queue: &queue::Queue, open: u64, arg: u64, cpu: &Cpu) -> Option<FsError> {
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let geometry = Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    };
    let mut admission = core::pin::pin!(admit(
        queue,
        open,
        DIRTYFB,
        arg,
        cpu,
        Some(&events),
        geometry,
        1
    ));
    match admission
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(_)) => None,
        Poll::Ready(Err(queue::SubmitError::Io(error))) => Some(error),
        Poll::Ready(Err(queue::SubmitError::NoDescriptor)) => panic!("DIRTYFB exported a fd"),
        Poll::Pending => panic!("DIRTYFB admission must finish synchronously"),
    }
}

fn intel_kms_dirtyfb_errnos_follow_drm_mode_dirtyfb_ioctl_order() -> TestResult {
    let mode = mode();
    // WC GEM allocation is NotImplemented off x86_64 (kernel_root is
    // unsupported there); assert the error and stop, like the
    // neighbouring wc test does.
    #[cfg(target_arch = "aarch64")]
    {
        assert!(matches!(
            framebuffer(&mode, 7, true),
            Err(FsError::NotImplemented)
        ));
        return TestResult::Pass;
    }
    let fb = framebuffer(&mode, 7, true).unwrap();
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    // drm_ioctl copies the request (-EFAULT) before drm_ioctl_permit
    // refuses a non-master (-EACCES).
    assert_eq!(
        admit_dirty(&queue, 8, 4090, &cpu),
        Some(FsError::BadAddress)
    );
    put_dirty(&cpu, 0, fb, 0, 0, 0);
    assert_eq!(
        admit_dirty(&queue, 8, 0, &cpu),
        Some(FsError::PermissionDenied)
    );
    // drm_framebuffer_lookup (-ENOENT) precedes every clip check.
    put_dirty(&cpu, 0, 999, 0, 1, 0);
    assert_eq!(admit_dirty(&queue, 7, 0, &cpu), Some(FsError::NotFound));
    // The -EINVAL checks, in order: count without pointer (and the
    // reverse), an odd annotated copy, then a negative or excessive count.
    for (flags, num_clips, clips_ptr) in [
        (0, 1, 0),
        (0, 0, 0x100),
        (1, 3, 0x100),
        (0, 257, 0x100),
        (0, 0x8000_0000, 0x100),
    ] {
        put_dirty(&cpu, 0, fb, flags, num_clips, clips_ptr);
        assert_eq!(
            admit_dirty(&queue, 7, 0, &cpu),
            Some(FsError::InvalidData),
            "flags {flags:#x} clips {num_clips} ptr {clips_ptr:#x}"
        );
    }
    // The clip copy (-EFAULT) comes last.
    put_dirty(&cpu, 0, fb, 0, 2, 4090);
    assert_eq!(admit_dirty(&queue, 7, 0, &cpu), Some(FsError::BadAddress));
    // Unknown flag bits are masked (DRM_MODE_FB_DIRTY_FLAGS & r->flags).
    put_dirty(&cpu, 0, fb, 0xffff_fffc, 0, 0);
    assert_eq!(admit_dirty(&queue, 7, 0, &cpu), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_dirtyfb_errnos_follow_drm_mode_dirtyfb_ioctl_order
);

fn intel_kms_dirtyfb_clips_become_the_present_damage() -> TestResult {
    let mode = mode();
    // WC GEM allocation is NotImplemented off x86_64 (kernel_root is
    // unsupported there); assert the error and stop, like the
    // neighbouring wc test does.
    #[cfg(target_arch = "aarch64")]
    {
        assert!(matches!(
            framebuffer(&mode, 7, true),
            Err(FsError::NotImplemented)
        ));
        return TestResult::Pass;
    }
    let fb = framebuffer(&mode, 7, true).unwrap();
    let other = framebuffer(&mode, 7, true).unwrap();
    mode.lock().crtcs[0].primary_fb = Some(fb);
    let cpu = Cpu::new();
    put_dirty(&cpu, 0, fb, 1, 4, 0x100);
    put_clips(
        &cpu,
        0x100,
        &[[1, 2, 3, 4], [0, 9, 9, 9], [5, 6, 7, 8], [0, 0, 1, 1]],
    );
    let Ok(Request::Dirty(id, damage)) = Request::copy_dirty(0, &cpu, true, |id| id == fb) else {
        panic!("DIRTYFB request not decoded");
    };
    // ANNOTATE_COPY: clips 0 and 2 (drm_atomic_helper_dirtyfb's src_inc 2).
    assert_eq!(id, fb);
    assert_eq!(
        damage,
        Damage::Clips(alloc::vec![Rect::new(1, 2, 3, 4), Rect::new(5, 6, 7, 8)])
    );
    let geometry = Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    };
    // The primary's framebuffer: a present of it carrying the damage.
    let plan = Plan::stage(&mode.lock(), Request::Dirty(fb, damage.clone()), geometry).unwrap();
    assert!(matches!(plan.action, Action::Present));
    assert_eq!(plan.damage, damage);
    // Any other framebuffer is shown nowhere: nothing to commit.
    let plan = Plan::stage(&mode.lock(), Request::Dirty(other, damage), geometry).unwrap();
    assert!(matches!(plan.action, Action::Noop));
    // A clipless DIRTYFB damages the whole plane.
    put_dirty(&cpu, 0, fb, 0, 0, 0);
    let Ok(Request::Dirty(_, damage)) = Request::copy_dirty(0, &cpu, true, |_| true) else {
        panic!("clipless DIRTYFB not decoded");
    };
    assert_eq!(damage, Damage::Full);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_dirtyfb_clips_become_the_present_damage
);

fn damage_frame(fb: u32, damage: u64) -> Request {
    let Request::Atomic(mut a) = atomic_frame(fb, 0) else {
        unreachable!()
    };
    a.counts[0] += 1;
    a.props.insert(2, PLANE_FB_DAMAGE_CLIPS_PROP_ID);
    a.values.insert(2, damage);
    Request::Atomic(a)
}

fn rects_blob(rects: &[[i32; 4]]) -> Vec<u8> {
    rects
        .iter()
        .flat_map(|r| r.iter().flat_map(|v| v.to_le_bytes()))
        .collect()
}

fn intel_kms_fb_damage_clips_validates_like_drm_atomic_set_property() -> TestResult {
    let mode = mode();
    // WC GEM allocation is NotImplemented off x86_64 (kernel_root is
    // unsupported there); assert the error and stop, like the
    // neighbouring wc test does.
    #[cfg(target_arch = "aarch64")]
    {
        assert!(matches!(
            framebuffer(&mode, 7, true),
            Err(FsError::NotImplemented)
        ));
        return TestResult::Pass;
    }
    let fb = framebuffer(&mode, 7, true).unwrap();
    let clips = rects_blob(&[[0, 4, 64, 6], [10, 20, 12, 21]]);
    let good = mode.lock().create_property_blob(clips.clone()).unwrap();
    let partial = mode
        .lock()
        .create_property_blob(alloc::vec![0; 20])
        .unwrap();
    let geometry = Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    };
    let stage = |value: u64| Plan::stage(&mode.lock(), damage_frame(fb, value), geometry);
    // No blob: a full-plane update.
    assert_eq!(stage(0).unwrap().damage, Damage::Full);
    // The blob's rectangles, unclamped.
    let expected = Damage::from_blob(&clips).unwrap();
    assert_eq!(stage(u64::from(good)).unwrap().damage, expected);
    // drm_property_lookup_blob takes the id as u32.
    assert_eq!(
        stage(1u64 << 32 | u64::from(good)).unwrap().damage,
        expected
    );
    // An unknown blob, and one that is not whole drm_mode_rects: -EINVAL.
    assert!(matches!(stage(0x7777), Err(FsError::InvalidData)));
    assert!(matches!(
        stage(u64::from(partial)),
        Err(FsError::InvalidData)
    ));
    // FB_DAMAGE_CLIPS alone does not turn a commit into a color commit.
    assert!(matches!(
        stage(u64::from(good)).unwrap().action,
        Action::Present
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_fb_damage_clips_validates_like_drm_atomic_set_property
);

/// A display owner that records the damage each present carries.
struct Probe {
    seen: Vec<Damage>,
}
impl Backend for Probe {
    fn geometry(&self) -> Geometry {
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        }
    }
    fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb {
        narf_graphics_driver::generic::GenericFb::new(0, 64, 32, 256, 32)
    }
    fn check(&self, _: Geometry) -> Result<(), FsError> {
        Ok(())
    }
    fn present<'a>(
        &'a mut self,
        _: Arc<crate::intel_gpu_gem::GemObject>,
        _: Geometry,
    ) -> FsFuture<'a, FlipStamp> {
        self.seen.push(Damage::Full);
        self.vblank()
    }
    fn present_damaged<'a>(
        &'a mut self,
        _: Arc<crate::intel_gpu_gem::GemObject>,
        _: Geometry,
        damage: &'a Damage,
    ) -> FsFuture<'a, FlipStamp> {
        self.seen.push(damage.clone());
        self.vblank()
    }
    fn restore(&mut self) -> FsFuture<'_, ()> {
        alloc::boxed::Box::pin(async { Ok(()) })
    }
    /// A CPU copy is not a present: it records no damage.
    fn copy<'a>(&'a mut self, _: &'a Framebuffer, _: &'a ModeState) -> FsFuture<'a, ()> {
        alloc::boxed::Box::pin(async { Ok(()) })
    }
    fn vblank(&mut self) -> FsFuture<'_, FlipStamp> {
        alloc::boxed::Box::pin(async {
            Ok(FlipStamp {
                ns: 1000,
                sequence: 1,
            })
        })
    }
}

fn intel_kms_commit_damage_reaches_the_display_owner() -> TestResult {
    let mode = mode();
    // WC GEM allocation is NotImplemented off x86_64 (kernel_root is
    // unsupported there); assert the error and stop, like the
    // neighbouring wc test does.
    #[cfg(target_arch = "aarch64")]
    {
        assert!(matches!(
            framebuffer(&mode, 7, true),
            Err(FsError::NotImplemented)
        ));
        return TestResult::Pass;
    }
    let fb = framebuffer(&mode, 7, true).unwrap();
    let clips = rects_blob(&[[0, 8, 64, 9]]);
    let blob = mode.lock().create_property_blob(clips.clone()).unwrap();
    let cpu = Cpu::new();
    let out = OutFences::new(Vec::new());
    let mut probe = Probe { seen: Vec::new() };
    for (request, expected) in [
        (
            damage_frame(fb, u64::from(blob)),
            Damage::from_blob(&clips).unwrap(),
        ),
        (damage_frame(fb, 0), Damage::Full),
        (
            Request::Dirty(fb, Damage::Clips(alloc::vec![Rect::new(1, 1, 2, 2)])),
            Damage::Clips(alloc::vec![Rect::new(1, 1, 2, 2)]),
        ),
    ] {
        {
            let mut call = core::pin::pin!(execute(
                &mut probe,
                &mode,
                7,
                request,
                &cpu,
                None,
                Some(&out)
            ));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(0))
            );
        }
        assert_eq!(probe.seen.pop(), Some(expected));
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_commit_damage_reaches_the_display_owner
);

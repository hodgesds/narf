//! DCN30's linear primary: a pinned GEM framebuffer the HUBP scans out in
//! place (amdgpu_dm's flip to the client BO address) at its own pitch,
//! viewport and placement, or a retained GEM placement or dumb buffer whose
//! SRC rectangle is copied unscaled into the native back buffer, which the
//! pipe then shows with the frame's placement.
use super::{Frame, ScanError};
use crate::amdgpu_present_damage as damage;
use crate::{amdgpu_gem::GemPlacement, amdgpu_navi48_platform::PlaneFrame};
use alloc::sync::Arc;

impl Frame {
    pub(super) fn from_plane(p: PlaneFrame, ticket: Option<u64>) -> Option<Self> {
        if !matches!(p.format, 0x3432_5258 | 0x3432_5241)
            || p.modifier != 0
            || p.chroma_pitch != 0
            || p.offsets[1] != 0
            || p.width == 0
            || p.height == 0
            || p.pitch % 4 != 0
            || p.pitch < p.width.checked_mul(4)?
            || p.offsets[0] % 4 != 0
        {
            return None;
        }
        let end = u64::from(p.offsets[0])
            .checked_add(u64::from(p.height - 1) * u64::from(p.pitch))?
            .checked_add(u64::from(p.width) * 4)?;
        if let Some(pin) = p.bo.as_ref() {
            if end > pin.byte_len() {
                return None;
            }
        } else if p.phys == 0 || p.phys % 4 != 0 || p.phys.checked_add(end).is_none() {
            return None;
        }
        if let Some(placement) = p.placement {
            let (sx, sy, sw, sh) = placement.src;
            let (_, _, dw, dh) = placement.dst;
            let fits = |at: u32, len: u32, max: u32| at.checked_add(len).is_some_and(|e| e <= max);
            if sw == 0
                || sh == 0
                || dw == 0
                || dh == 0
                || !fits(sx, sw, p.width)
                || !fits(sy, sh, p.height)
            {
                return None;
            }
        }
        Some(Self {
            phys: p.phys,
            pitch: p.pitch,
            width: p.width,
            height: p.height,
            offset: u64::from(p.offsets[0]),
            bo: p.bo,
            ticket,
            damage: None,
            placement: p.placement,
        })
    }
}

/// Why a GEM frame cannot be scanned out in place (it is then copied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ineligible {
    /// A dumb buffer (no GEM pin to fetch from).
    NotGem,
    /// The pitch does not fit the HUBP's 14-bit pitch field.
    Pitch,
    /// The first pixel is not on a 256-byte request boundary.
    Alignment,
}
impl Ineligible {
    pub(super) const ALL: [Self; 3] = [Self::NotGem, Self::Pitch, Self::Alignment];
}

/// The CRTC's full screen, as `(width, height)` of its mode.
type Mode = (u32, u32);

/// The SRC rectangle a frame shows: its placement's, else the mode's
/// full screen from the framebuffer's origin.
pub(super) fn source_rect(frame: &Frame, mode: Mode) -> (u32, u32, u32, u32) {
    frame.placement.map_or((0, 0, mode.0, mode.1), |p| p.src)
}
/// The CRTC rectangle a frame shows its SRC in.
fn crtc_rect(frame: &Frame, mode: Mode) -> (i32, i32, u32, u32) {
    frame.placement.map_or((0, 0, mode.0, mode.1), |p| p.dst)
}

/// What the pipe fetches for `frame` scanned out in place: its own
/// framebuffer (pitch in pixels, size) and its placement
/// (`fill_dc_plane_info_and_addr`, `amdgpu_dm_plane_fill_dc_scaling_info`).
pub(super) fn direct_request(frame: &Frame, mode: Mode) -> crate::amdgpu_navi22_plane::Request {
    crate::amdgpu_navi22_plane::Request {
        pitch: frame.pitch / 4,
        width: frame.width,
        height: frame.height,
        src: source_rect(frame, mode),
        dst: crtc_rect(frame, mode),
    }
}

/// Where a frame that cannot be fetched in place is copied: its SRC
/// rectangle, unscaled, to the origin of the owned back surface `back`,
/// which the pipe then shows in the frame's CRTC rectangle. None when the
/// SRC rectangle is larger than the owned surface. An unplaced frame copies
/// its full screen (clipped to the framebuffer), as before.
pub(super) fn copied_request(
    frame: &Frame,
    back: &narf_graphics_driver::generic::GenericFb,
) -> Option<crate::amdgpu_navi22_plane::Request> {
    let mode = (back.width, back.height);
    let (_, _, w, h) = source_rect(frame, mode);
    if w > back.width || h > back.height {
        return None;
    }
    Some(crate::amdgpu_navi22_plane::Request {
        pitch: back.pitch / 4,
        width: back.width,
        height: back.height,
        src: (0, 0, w, h),
        dst: crtc_rect(frame, mode),
    })
}

/// `amdgpu_dm_plane_helper_prepare_fb` + `fill_plane_buffer_attributes`
/// for the lit primary: the GPU address the HUBP fetches `frame` from when
/// it can be scanned out in place, at its own pitch and placement (the
/// plane update programs the pitch, viewport and scaler with it).
/// `from_plane` already restricted frames to linear XR24/AR24, SRC inside
/// the framebuffer and the extent to the pinned (VRAM, contiguous)
/// placement.
pub(super) fn direct(frame: &Frame) -> Result<u64, Ineligible> {
    let pin = frame.bo.as_ref().ok_or(Ineligible::NotGem)?;
    if frame.pitch / 4 > crate::amdgpu_dcn_plane::MAX_DIMENSION + 1 {
        return Err(Ineligible::Pitch);
    }
    let address = pin
        .address()
        .checked_add(frame.offset)
        .ok_or(Ineligible::Alignment)?;
    if address == 0 || address % crate::amdgpu_dcn30_flip::ADDRESS_ALIGN != 0 {
        return Err(Ineligible::Alignment);
    }
    Ok(address)
}

/// The client framebuffer pin the HUBP may still fetch (amdgpu_dm keeps
/// the old fb pinned until `cleanup_fb` after the next flip). A flip only
/// completes once SURFACE_EARLIEST_INUSE names its new surface, so a pin
/// is released as soon as a later flip latches; a failed flip keeps it.
#[derive(Debug, Default)]
pub(super) struct ShownPin(Option<Arc<crate::amdgpu_gem::ScanoutPin>>);
impl ShownPin {
    pub(super) const fn new() -> Self {
        Self(None)
    }
    /// A flip to `pin` latched; returns the pin it replaced, now unfetched.
    pub(super) fn latched_external(
        &mut self,
        pin: Arc<crate::amdgpu_gem::ScanoutPin>,
    ) -> Option<Arc<crate::amdgpu_gem::ScanoutPin>> {
        self.0.replace(pin)
    }
    /// A flip to an owned surface latched (or the pipe was relit on one).
    pub(super) fn latched_owned(&mut self) -> Option<Arc<crate::amdgpu_gem::ScanoutPin>> {
        self.0.take()
    }
}

/// The dumb buffer `frame` copies from, for damage tracking (None: a GEM
/// frame).
pub(super) fn damage_source(frame: &Frame) -> Option<damage::Source> {
    frame.bo.is_none().then_some(damage::Source {
        phys: frame.phys,
        pitch: frame.pitch,
        width: frame.width,
        height: frame.height,
        offset: frame.offset,
    })
}

/// `next` replaces the waiting `old`: its damage must cover both, since
/// `old` is never copied.
pub(super) fn coalesce(old: &Frame, next: &mut Frame) {
    next.damage = damage::coalesce(
        (damage_source(old), old.damage.as_ref()),
        (damage_source(next), next.damage.as_ref()),
    );
}

fn error(e: narf_filesystem::FsError) -> ScanError {
    match e {
        narf_filesystem::FsError::OutOfMemory | narf_filesystem::FsError::NoSpace => {
            ScanError::Allocation
        }
        narf_filesystem::FsError::InvalidData => ScanError::Invalid,
        _ => ScanError::DeviceGone,
    }
}

/// `drm_atomic_helper_wait_for_fences` for the frame's implicit WRITE
/// fences, bounded at 5 s. Woken by any Navi22 fence interrupt
/// (`amdgpu_fence_navi22::wait_change`, sequence taken before sampling so
/// no completion is missed), and re-sampled at least every millisecond
/// since polling stays the mandatory completion path.
pub(super) async fn wait_rendered(pin: &crate::amdgpu_gem::ScanoutPin) -> Result<(), ScanError> {
    let deadline = narf_time::monotonic_ns().saturating_add(5_000_000_000);
    loop {
        let observed = crate::amdgpu_fence_navi22::change_sequence();
        let fences = pin
            .object()
            .dma_buf()
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Write);
        if fences.iter().all(|f| f.is_signalled()) {
            return Ok(());
        }
        let now = narf_time::monotonic_ns();
        if now >= deadline {
            return Err(ScanError::Timeout);
        }
        crate::amdgpu_fence_navi22::wait_change(observed, deadline.min(now + 1_000_000)).await;
    }
}

/// No platform owner or IRQ spinlock may be held here: both rendering
/// and the SDMA readback worker must be able to take the owner lock.
pub(super) async fn source(frame: &Frame) -> Result<Option<Arc<GemPlacement>>, ScanError> {
    let Some(pin) = frame.bo.as_ref() else {
        return Ok(None);
    };
    wait_rendered(pin).await?;
    let placement = pin.placement();
    if placement.cpu_visible() {
        return Ok(Some(placement.clone()));
    }
    let card = pin.object().card().ok_or(ScanError::Invalid)?;
    let mut staging = GemPlacement::new_system(pin.byte_len()).map_err(error)?;
    crate::amdgpu_rdna2_vram::reader(card)
        .read(pin.object().clone(), placement.clone(), &mut staging)
        .await
        .map_err(error)?;
    Ok(Some(Arc::new(staging)))
}

/// Caller retains the frame and serializes visible-VRAM CPU reads with
/// reset. `source` is the pinned placement or its completed private readback.
pub(super) fn row(
    frame: &Frame,
    source: Option<&GemPlacement>,
    y: u32,
    out: &mut [u32],
) -> Result<(), ScanError> {
    if y >= frame.height || out.len() > frame.width as usize {
        return Err(ScanError::Invalid);
    }
    let offset = frame.offset + u64::from(y) * u64::from(frame.pitch);
    if let Some(source) = source {
        // SAFETY: every u32 byte is initialized, and this disjoint mutable
        // byte view covers exactly the destination row.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), out.len() * 4)
        };
        source.read_bytes(offset, bytes).ok_or(ScanError::Invalid)
    } else {
        if frame.bo.is_some() {
            return Err(ScanError::Invalid);
        }
        // SAFETY: from_plane checked alignment/overflow; the trusted DRM
        // dumb-buffer producer retains the allocation and bounds its extent.
        let pixels = unsafe {
            core::slice::from_raw_parts(
                narf_memory::PhysAddr::new(frame.phys + offset).kernel_ptr::<u32>(),
                out.len(),
            )
        };
        out.copy_from_slice(pixels);
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::amdgpu_gem::{self as gem, GemState, VramHeap};
    use alloc::{vec, vec::Vec};
    use core::{
        future::Future,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fixture {
        state: GemState,
        bytes: Vec<u8>,
    }
    const CARD: u32 = 0xfe22_0510;
    impl Fixture {
        fn new() -> Self {
            let mut bytes = vec![0u8; 6 * 4096];
            let map = narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0xc800_0000),
                virt: bytes.as_mut_ptr() as u64,
                len: bytes.len() as u64,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            };
            // SAFETY: the fixture retains these bytes until its GEM table
            // and all test pins are gone; no hardware references this BAR.
            let pool =
                unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x9_0000_0000) }.unwrap();
            gem::register_vram_heap(
                CARD,
                VramHeap {
                    pool,
                    fb_base: 0x9_0000_0000,
                    fb_offset: 0x9_0000_0000,
                    unmapped: None,
                },
            );
            Self {
                state: GemState::for_card(CARD),
                bytes,
            }
        }
        fn object(&self) -> Arc<gem::GemObject> {
            let mut request = [0u8; 32];
            request[..8].copy_from_slice(&8192u64.to_le_bytes());
            request[8..16].copy_from_slice(&4096u64.to_le_bytes());
            request[16..24].copy_from_slice(
                &u64::from(crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes(),
            );
            gem::dispatch(0xc020_6440, request.as_mut_ptr() as usize, &self.state).unwrap();
            self.state
                .object(u32::from_le_bytes(request[..4].try_into().unwrap()))
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            gem::unregister_vram_heap(CARD);
        }
    }

    fn navi22_linear_gem_copy_keeps_pin_and_reads_offset_rows() -> TestResult {
        let mut fixture = Fixture::new();
        let object = fixture.object();
        for y in 0..2usize {
            for x in 0..8usize {
                let offset = 16 + y * 64 + x * 4;
                fixture.bytes[offset..offset + 4]
                    .copy_from_slice(&(0x1234_0000 + y as u32 * 256 + x as u32).to_le_bytes());
            }
        }
        let pin = Arc::new(object.pin_scanout().unwrap());
        let mut plane = PlaneFrame::linear(0, 64, 8, 2, 0x3432_5258);
        plane.bo = Some(pin.clone());
        plane.offsets[0] = 16;
        let frame = Frame::from_plane(plane.clone(), None).unwrap();
        drop(pin);
        let placement = narf_scheduler::block_on_spin(source(&frame))
            .unwrap()
            .unwrap();
        let mut pixels = [0u32; 8];
        if !object.pinned()
            || row(&frame, Some(&placement), 1, &mut pixels).is_err()
            || pixels != core::array::from_fn(|x| 0x1234_0100 + x as u32)
        {
            return TestResult::Fail("GEM offset/pitch copy or source lifetime");
        }
        if row(&frame, None, 0, &mut pixels) != Err(ScanError::Invalid)
            || row(&frame, Some(&placement), 2, &mut pixels) != Err(ScanError::Invalid)
        {
            return TestResult::Fail("GEM copy fell through to a raw physical pointer");
        }
        plane.offsets[0] = 8192 - 32;
        if Frame::from_plane(plane.clone(), None).is_some() {
            return TestResult::Fail("GEM image extent exceeded the pinned BO");
        }
        plane.offsets[0] = 0;
        plane.format = 0x3033_5258;
        if Frame::from_plane(plane.clone(), None).is_some() {
            return TestResult::Fail("8888 copy accepted a 10-bit format");
        }
        plane.format = 0x3432_5258;
        plane.modifier = 1;
        if Frame::from_plane(plane.clone(), None).is_some() {
            return TestResult::Fail("linear copy accepted a tiled framebuffer");
        }
        drop(plane);
        drop(frame);
        if object.pinned() {
            return TestResult::Fail("copy leaked its source pin");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_linear_gem_copy_keeps_pin_and_reads_offset_rows
    );

    struct Fence(AtomicBool);
    impl narf_filesystem::DrmFence for Fence {
        fn is_signalled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn wait(&self, _: u64) -> bool {
            self.is_signalled()
        }
        fn driver_name(&self) -> &str {
            "navi22-copy-test"
        }
    }
    fn navi22_linear_gem_copy_waits_for_render_fence_without_owner() -> TestResult {
        let fixture = Fixture::new();
        let object = fixture.object();
        let mut plane = PlaneFrame::linear(0, 64, 8, 2, 0x3432_5258);
        plane.bo = Some(Arc::new(object.pin_scanout().unwrap()));
        let frame = Frame::from_plane(plane, None).unwrap();
        let fence = Arc::new(Fence(AtomicBool::new(false)));
        object
            .dma_buf()
            .resv
            .add_fence(fence.clone(), narf_filesystem::dma_buf::DmaResvUsage::Write);
        let mut future = core::pin::pin!(source(&frame));
        let mut context = Context::from_waker(Waker::noop());
        if !matches!(future.as_mut().poll(&mut context), Poll::Pending) {
            return TestResult::Fail("copy read pixels while rendering was pending");
        }
        // The render-completion path can take the same owner the presenter
        // will need later. Polling the wait must not have retained it.
        let Some(owner) = super::super::OWNER.try_lock() else {
            return TestResult::Fail("render-fence wait retained the GPU owner");
        };
        fence.0.store(true, Ordering::Release);
        drop(owner);
        if narf_scheduler::block_on_spin(future).is_err() {
            return TestResult::Fail("copy failed after rendering completed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_linear_gem_copy_waits_for_render_fence_without_owner
    );

    /// The render-fence wait is woken by a fence interrupt (the change
    /// sequence it registered on), not only by its 1 ms re-check timer.
    fn navi22_render_wait_wakes_on_fence_change() -> TestResult {
        struct Count(core::sync::atomic::AtomicUsize);
        impl alloc::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let fixture = Fixture::new();
        let object = fixture.object();
        let pin = object.pin_scanout().unwrap();
        let fence = Arc::new(Fence(AtomicBool::new(false)));
        object
            .dma_buf()
            .resv
            .add_fence(fence.clone(), narf_filesystem::dma_buf::DmaResvUsage::Write);
        let count = Arc::new(Count(core::sync::atomic::AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(wait_rendered(&pin));
        if !matches!(future.as_mut().poll(&mut context), Poll::Pending) {
            return TestResult::Fail("render wait finished before its fence");
        }
        let before = count.0.load(Ordering::Acquire);
        fence.0.store(true, Ordering::Release);
        crate::amdgpu_fence_navi22::notify_all();
        if count.0.load(Ordering::Acquire) == before {
            return TestResult::Fail("fence interrupt did not wake the render wait");
        }
        if !matches!(future.as_mut().poll(&mut context), Poll::Ready(Ok(()))) {
            return TestResult::Fail("woken render wait did not complete");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_render_wait_wakes_on_fence_change
    );

    /// A positioned or scaled primary keeps its placement: scanned out in
    /// place it is its own framebuffer's request; copied, its SRC moves to
    /// the owned surface's origin and keeps its CRTC rectangle.
    fn navi22_placed_primary_requests() -> TestResult {
        use crate::drm::card::Placement;
        use narf_graphics_driver::generic::GenericFb;
        let kwin = Placement {
            src: (3, 2, 55, 55),
            dst: (1912, 1073, 55, 55),
        };
        // Placement outside the framebuffer is refused at from_plane.
        let mut plane = PlaneFrame::linear(0x10_0000, 256, 60, 60, 0x3432_5258);
        plane.placement = Some(Placement {
            src: (10, 0, 55, 55),
            dst: (0, 0, 55, 55),
        });
        if Frame::from_plane(plane.clone(), None).is_some() {
            return TestResult::Fail("SRC past the framebuffer accepted");
        }
        plane.placement = Some(kwin);
        let Some(frame) = Frame::from_plane(plane, None) else {
            return TestResult::Fail("placed frame refused");
        };
        let mode = (3840, 2160);
        let r = direct_request(&frame, mode);
        if (r.pitch, r.width, r.height, r.src, r.dst) != (64, 60, 60, kwin.src, kwin.dst) {
            return TestResult::Fail("in-place request");
        }
        let back = GenericFb::new(0xe000_0000, 3840, 2160, 3840 * 4, 32);
        let Some(c) = copied_request(&frame, &back) else {
            return TestResult::Fail("copied request");
        };
        if (c.pitch, c.width, c.height, c.src, c.dst)
            != (3840, 3840, 2160, (0, 0, 55, 55), kwin.dst)
        {
            return TestResult::Fail("copied request rectangles");
        }
        // An unplaced frame is the full screen; a SRC wider than the owned
        // surface cannot be copied into it.
        let full = Frame::from_plane(
            PlaneFrame::linear(0x10_0000, 256, 64, 16, 0x3432_5258),
            None,
        )
        .unwrap();
        let small = GenericFb::new(0xe000_0000, 64, 16, 256, 32);
        if copied_request(&full, &small).map(|r| (r.src, r.dst))
            != Some(((0, 0, 64, 16), (0, 0, 64, 16)))
        {
            return TestResult::Fail("full-screen copy");
        }
        let mut wide = PlaneFrame::linear(0x10_0000, 512, 128, 16, 0x3432_5258);
        wide.placement = Some(Placement {
            src: (0, 0, 128, 16),
            dst: (0, 0, 64, 8),
        });
        let wide = Frame::from_plane(wide, None).unwrap();
        if copied_request(&wide, &small).is_some() {
            return TestResult::Fail("SRC larger than the owned surface");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/navi22", navi22_placed_primary_requests);

    /// A relight lights the pipe on its cleared owned surface; the committed
    /// primary is shown again from a copy that completes no event and
    /// copies every row (the compositor will not repaint an unchanged frame).
    fn navi22_committed_frame_is_shown_again_after_relight() -> TestResult {
        let mut frame = Frame::from_plane(
            PlaneFrame::linear(0x10_0000, 256, 64, 16, 0x3432_5258),
            Some(7),
        )
        .unwrap();
        frame.damage = Some(3..5);
        let again = super::super::committed_copy(&frame);
        if again.ticket.is_some() || again.damage.is_some() || again.phys != frame.phys {
            return TestResult::Fail("committed copy keeps the event or damage");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_committed_frame_is_shown_again_after_relight
    );

    /// The DRM cursor plane's state is recorded without OWNER: every move
    /// and image lands at once, the newest wins, and the cursor task (which
    /// waits for OWNER) applies it, so a move during a present is late but
    /// never lost.
    fn navi22_drm_cursor_moves_are_recorded_without_owner() -> TestResult {
        use crate::amdgpu_navi48_platform::{CursorContent, CursorImage};
        let mut c = super::super::DrmCursor {
            image: None,
            pending: None,
            position: (0, 0),
            dirty: false,
            running: true,
        };
        let image = || CursorImage {
            width: 2,
            height: 1,
            pixels: vec![0xff00_0000, 0xffff_ffff],
        };
        super::super::record_cursor(&mut c, Some(CursorContent::Image(image())), (10, 20));
        let first = c.image.clone();
        // Moves while the task is still waiting: the latest position stays,
        // the unchanged image is not replaced (no re-upload).
        for x in 11..40 {
            super::super::record_cursor(&mut c, Some(CursorContent::Image(image())), (x, 20));
        }
        if !c.dirty
            || c.position != (39, 20)
            || !c
                .image
                .as_ref()
                .zip(first.as_ref())
                .is_some_and(|(a, b)| alloc::sync::Arc::ptr_eq(a, b))
        {
            return TestResult::Fail("cursor moves lost or image replaced");
        }
        super::super::record_cursor(&mut c, None, (-5, -5));
        if c.image.is_some() || c.position != (-5, -5) {
            return TestResult::Fail("cursor off not recorded");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_drm_cursor_moves_are_recorded_without_owner
    );

    /// Any pinned, request-aligned GEM framebuffer is scanned out in place:
    /// the plane update programs its pitch, size and placement. A dumb
    /// buffer, a pitch past the HUBP's field or an unaligned first pixel
    /// copies.
    fn navi22_direct_scanout_eligibility() -> TestResult {
        let fixture = Fixture::new();
        let object = fixture.object();
        let pin = Arc::new(object.pin_scanout().unwrap());
        let gem = |pitch: u32, width: u32, height: u32, offset: u32| {
            let mut plane = PlaneFrame::linear(0, pitch, width, height, 0x3432_5258);
            plane.bo = Some(pin.clone());
            plane.offsets[0] = offset;
            Frame::from_plane(plane, None).unwrap()
        };
        if direct(&gem(256, 8, 2, 0)) != Ok(pin.address()) {
            return TestResult::Fail("pinned frame was not scanned out in place");
        }
        if direct(&gem(256, 8, 2, 512)) != Ok(pin.address() + 512) {
            return TestResult::Fail("aligned offset not added to the pin address");
        }
        // Another pitch or size than the lit surface is fetched in place.
        if direct(&gem(512, 8, 2, 0)).is_err() || direct(&gem(256, 4, 1, 0)).is_err() {
            return TestResult::Fail("pitch or size forced a copy");
        }
        let dumb = Frame::from_plane(
            PlaneFrame::linear(0x8000_0000, 256, 8, 2, 0x3432_5258),
            None,
        )
        .unwrap();
        for (frame, want, what) in [
            (dumb, Ineligible::NotGem, "dumb buffer"),
            (
                gem(256, 8, 2, 16),
                Ineligible::Alignment,
                "offset alignment",
            ),
        ] {
            if direct(&frame) != Err(want) {
                return TestResult::Fail(what);
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_direct_scanout_eligibility
    );

    /// cleanup_fb after the next flip: a scanned-out client framebuffer
    /// stays pinned until a later flip (client or owned) latches.
    fn navi22_direct_scanout_pins_retire_after_the_next_flip() -> TestResult {
        let fixture = Fixture::new();
        let first = fixture.object();
        let second = fixture.object();
        let mut shown = ShownPin::new();
        if shown
            .latched_external(Arc::new(first.pin_scanout().unwrap()))
            .is_some()
            || !first.pinned()
        {
            return TestResult::Fail("first scanned-out framebuffer not kept pinned");
        }
        let replaced = shown.latched_external(Arc::new(second.pin_scanout().unwrap()));
        if !first.pinned() || replaced.is_none() {
            return TestResult::Fail("replaced pin not handed back for release");
        }
        drop(replaced);
        if first.pinned() || !second.pinned() {
            return TestResult::Fail("pins after a client-to-client flip");
        }
        let released = shown.latched_owned();
        drop(released);
        if second.pinned() || shown.latched_owned().is_some() {
            return TestResult::Fail("owned flip kept the client pin");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_direct_scanout_pins_retire_after_the_next_flip
    );

    fn navi22_replaced_dirty_frame_keeps_its_damage() -> TestResult {
        let dumb = |phys, damage| {
            let mut frame =
                Frame::from_plane(PlaneFrame::linear(phys, 64, 16, 100, 0x3432_5258), None)
                    .unwrap();
            frame.damage = damage;
            frame
        };
        let mut next = dumb(0x8000_0000, Some(50..60));
        coalesce(&dumb(0x8000_0000, Some(10..20)), &mut next);
        if next.damage != Some(10..60) || damage_source(&next).map(|s| s.offset) != Some(0) {
            return TestResult::Fail("replaced frame's damage lost");
        }
        for old in [dumb(0x8000_0000, None), dumb(0x9000_0000, Some(1..2))] {
            let mut next = dumb(0x8000_0000, Some(50..60));
            coalesce(&old, &mut next);
            if next.damage.is_some() {
                return TestResult::Fail("frame replacing a full or foreign frame stayed partial");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_replaced_dirty_frame_keeps_its_damage
    );
}

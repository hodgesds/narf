//! DCN30's linear primary: a pinned GEM framebuffer the HUBP scans out in
//! place (amdgpu_dm's flip to the client BO address), or a retained GEM
//! placement or dumb buffer copied into the native back buffer before its
//! VUPDATE flip.
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
        Some(Self {
            phys: p.phys,
            pitch: p.pitch,
            width: p.width,
            height: p.height,
            offset: u64::from(p.offsets[0]),
            bo: p.bo,
            ticket,
            damage: None,
        })
    }
}

/// Why a GEM frame cannot be scanned out in place (it is then copied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ineligible {
    /// A dumb buffer (no GEM pin to fetch from).
    NotGem,
    /// The pitch differs from the one the HUBP was programmed with.
    Pitch,
    /// The frame does not cover the active mode exactly.
    Size,
    /// The first pixel is not on a 256-byte request boundary.
    Alignment,
}
impl Ineligible {
    pub(super) const ALL: [Self; 4] = [Self::NotGem, Self::Pitch, Self::Size, Self::Alignment];
}

/// `amdgpu_dm_plane_helper_prepare_fb` + `fill_plane_buffer_attributes`
/// for the lit primary: the GPU address the HUBP fetches `frame` from,
/// when it can be scanned out in place on a pipe showing `front` (the
/// owned surface the modeset programmed: its pitch and size). `from_plane`
/// already restricted frames to linear XR24/AR24 and the extent to the
/// pinned (VRAM, contiguous) placement.
pub(super) fn direct(
    frame: &Frame,
    front: &narf_graphics_driver::generic::GenericFb,
) -> Result<u64, Ineligible> {
    let pin = frame.bo.as_ref().ok_or(Ineligible::NotGem)?;
    if frame.pitch != front.pitch {
        return Err(Ineligible::Pitch);
    }
    if (frame.width, frame.height) != (front.width, front.height) {
        return Err(Ineligible::Size);
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

    /// Direct scanout takes a pinned client framebuffer only when the
    /// HUBP can fetch it as programmed: same pitch and size as the lit
    /// surface, first pixel on a 256-byte boundary. Everything else copies.
    fn navi22_direct_scanout_eligibility() -> TestResult {
        use narf_graphics_driver::generic::GenericFb;
        let fixture = Fixture::new();
        let object = fixture.object();
        let pin = Arc::new(object.pin_scanout().unwrap());
        let front = GenericFb::new(0xe000_0000, 8, 2, 256, 32);
        let gem = |pitch: u32, width: u32, height: u32, offset: u32| {
            let mut plane = PlaneFrame::linear(0, pitch, width, height, 0x3432_5258);
            plane.bo = Some(pin.clone());
            plane.offsets[0] = offset;
            Frame::from_plane(plane, None).unwrap()
        };
        if direct(&gem(256, 8, 2, 0), &front) != Ok(pin.address()) {
            return TestResult::Fail("matching pinned frame was not scanned out in place");
        }
        if direct(&gem(256, 8, 2, 512), &front) != Ok(pin.address() + 512) {
            return TestResult::Fail("aligned offset not added to the pin address");
        }
        let dumb = Frame::from_plane(
            PlaneFrame::linear(0x8000_0000, 256, 8, 2, 0x3432_5258),
            None,
        )
        .unwrap();
        for (frame, want, what) in [
            (dumb, Ineligible::NotGem, "dumb buffer"),
            (gem(512, 8, 2, 0), Ineligible::Pitch, "pitch"),
            (gem(256, 4, 2, 0), Ineligible::Size, "width"),
            (gem(256, 8, 1, 0), Ineligible::Size, "height"),
            (
                gem(256, 8, 2, 16),
                Ineligible::Alignment,
                "offset alignment",
            ),
        ] {
            if direct(&frame, &front) != Err(want) {
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

//! DCN30's linear primary: a retained GEM placement or a dumb buffer,
//! copied into the native back buffer before its VUPDATE flip.
use super::{Frame, ScanError};
use crate::{amdgpu_gem::GemPlacement, amdgpu_navi48_platform::PlaneFrame};
use alloc::sync::Arc;
use core::ops::Range;

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

/// A dumb-buffer source: frames of one source and size share contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Source {
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    offset: u64,
}
impl Source {
    fn of(frame: &Frame) -> Option<Self> {
        frame.bo.is_none().then_some(Self {
            phys: frame.phys,
            pitch: frame.pitch,
            width: frame.width,
            height: frame.height,
            offset: frame.offset,
        })
    }
}

fn span(a: &Range<u32>, b: &Range<u32>) -> Range<u32> {
    if a.is_empty() {
        b.clone()
    } else if b.is_empty() {
        a.clone()
    } else {
        a.start.min(b.start)..a.end.max(b.end)
    }
}

/// What the two scanout buffers hold of a dumb source, so a damaged frame
/// copies only the rows its back buffer lacks. The back buffer is the
/// frame before the front, so it lacks the front's damage and the new
/// frame's. Anything else (another source, a GEM frame, an unknown back
/// buffer) copies every row.
#[derive(Debug, Default)]
pub(super) struct Damage {
    /// The front buffer shows this source in full, as of its frame.
    front: Option<Source>,
    /// The back buffer (by address, after `flips` flips) shows this source
    /// except these rows.
    back: Option<(Source, u64, u64, Range<u32>)>,
}
impl Damage {
    pub(super) const fn new() -> Self {
        Self {
            front: None,
            back: None,
        }
    }
    /// The rows of `frame` to copy into the back buffer at `back`, after
    /// the scanout's `flips` flips.
    pub(super) fn plan(&self, frame: &Frame, back: u64, flips: u64) -> Range<u32> {
        let all = 0..frame.height;
        let (Some(source), Some(rows)) = (Source::of(frame), frame.damage.as_ref()) else {
            return all;
        };
        match &self.back {
            Some((s, address, f, stale)) if *s == source && *address == back && *f == flips => {
                let rows = span(stale, rows);
                rows.start.min(frame.height)..rows.end.min(frame.height)
            }
            _ => all,
        }
    }
    /// `frame` (copied per `plan`) was flipped to the front; `back` is the
    /// new back buffer (the old front), and `flips` the scanout's count.
    pub(super) fn flipped(&mut self, frame: &Frame, back: u64, flips: u64) {
        let source = Source::of(frame);
        let rows = frame.damage.clone().unwrap_or(0..frame.height);
        self.back = match (self.front, source) {
            (Some(f), Some(s)) if f == s => Some((s, back, flips, rows)),
            _ => None,
        };
        self.front = source;
    }
    /// Neither buffer's contents are known.
    pub(super) fn forget(&mut self) {
        *self = Self::new();
    }
}

/// `next` replaces the waiting `old`: its damage must cover both, since
/// `old` is never copied.
pub(super) fn coalesce(old: &Frame, next: &mut Frame) {
    next.damage = match (Source::of(old), Source::of(next), &old.damage, &next.damage) {
        (Some(a), Some(b), Some(x), Some(y)) if a == b => Some(span(x, y)),
        _ => None,
    };
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

/// No platform owner or IRQ spinlock may be held here: both rendering
/// and the SDMA readback worker must be able to take the owner lock.
pub(super) async fn source(frame: &Frame) -> Result<Option<Arc<GemPlacement>>, ScanError> {
    let Some(pin) = frame.bo.as_ref() else {
        return Ok(None);
    };
    let deadline = narf_time::Deadline::after_ms(5_000);
    loop {
        let fences = pin
            .object()
            .dma_buf()
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Write);
        if fences.iter().all(|f| f.is_signalled()) {
            break;
        }
        if deadline.expired() {
            return Err(ScanError::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
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
            let mut bytes = vec![0u8; 3 * 4096];
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

    fn dumb(phys: u64, damage: Option<Range<u32>>) -> Frame {
        let mut frame =
            Frame::from_plane(PlaneFrame::linear(phys, 64, 16, 100, 0x3432_5258), None).unwrap();
        frame.damage = damage;
        frame
    }

    fn navi22_dirty_frames_copy_only_what_the_back_buffer_lacks() -> TestResult {
        const A: u64 = 0x1000_0000;
        const B: u64 = 0x2000_0000;
        let mut d = Damage::new();
        // Nothing is known of either buffer yet: every row.
        let first = dumb(0x8000_0000, Some(10..20));
        if d.plan(&first, B, 0) != (0..100) {
            return TestResult::Fail("unknown back buffer took a partial copy");
        }
        d.flipped(&first, A, 1);
        // The new back (A) held whatever preceded this source.
        let second = dumb(0x8000_0000, Some(10..20));
        if d.plan(&second, A, 1) != (0..100) {
            return TestResult::Fail("back buffer from before the source took a partial copy");
        }
        d.flipped(&second, B, 2);
        // B shows the first frame: it lacks the second's and third's rows.
        let third = dumb(0x8000_0000, Some(30..40));
        if d.plan(&third, B, 2) != (10..40) {
            return TestResult::Fail("partial copy is not both frames' damage");
        }
        // Another buffer, another flip count, another source, or a full
        // frame each copies every row.
        if d.plan(&third, A, 2) != (0..100)
            || d.plan(&third, B, 3) != (0..100)
            || d.plan(&dumb(0x9000_0000, Some(30..40)), B, 2) != (0..100)
            || d.plan(&dumb(0x8000_0000, None), B, 2) != (0..100)
        {
            return TestResult::Fail("unrelated back buffer took a partial copy");
        }
        d.flipped(&third, A, 3);
        if d.plan(&dumb(0x8000_0000, Some(95..400)), A, 3) != (30..100) {
            return TestResult::Fail("damage not clamped to the frame");
        }
        // A full frame leaves its successor's back buffer stale everywhere.
        d.flipped(&dumb(0x8000_0000, None), B, 4);
        if d.plan(&dumb(0x8000_0000, Some(1..2)), B, 4) != (0..100) {
            return TestResult::Fail("full frame's successor took a partial copy");
        }
        // Switching sources forgets the back buffer.
        d.flipped(&dumb(0x9000_0000, Some(1..2)), A, 5);
        if d.plan(&dumb(0x9000_0000, Some(1..2)), A, 5) != (0..100) {
            return TestResult::Fail("new source's first back buffer took a partial copy");
        }
        d.forget();
        if d.plan(&third, A, 3) != (0..100) {
            return TestResult::Fail("forgotten buffers took a partial copy");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_dirty_frames_copy_only_what_the_back_buffer_lacks
    );

    fn navi22_replaced_dirty_frame_keeps_its_damage() -> TestResult {
        let mut next = dumb(0x8000_0000, Some(50..60));
        coalesce(&dumb(0x8000_0000, Some(10..20)), &mut next);
        if next.damage != Some(10..60) {
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

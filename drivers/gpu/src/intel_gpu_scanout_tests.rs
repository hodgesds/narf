//! Native ownership/register models, not silicon or display IRQ acceptance.

use super::*;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Registers {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    frames: VecDeque<u32>,
    invalidate: bool,
    invalidations: usize,
    drop_ptes: bool,
    drop_surface: bool,
    unavailable: bool,
}

#[derive(Clone)]
struct Model(Rc<RefCell<Registers>>);
impl Model {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(Registers {
            // Literal PRM/Linux pipe-A offsets and 64x32 XRGB geometry.
            regs: [
                (0x70180, 0x84000000),
                (0x70188, 4),
                (0x70190, 0x001f003f),
                (0x701a4, 0),
                (0x7019c, 0x01000000),
                (0x701ac, 0x01000000),
                (0x70040, 40),
                (0x44408, 0),
            ]
            .into_iter()
            .collect(),
            writes: Vec::new(),
            frames: VecDeque::new(),
            invalidate: true,
            invalidations: 0,
            drop_ptes: false,
            drop_surface: false,
            unavailable: false,
        })))
    }
    fn set(&self, off: u64, value: u32) {
        self.0.borrow_mut().regs.insert(off, value);
    }
    fn land(&self, offset: u32, frame: u32) {
        self.set(0x701ac, offset);
        self.set(0x70040, frame);
        let mut state = self.0.borrow_mut();
        *state.regs.entry(0x44408).or_default() |= 8;
    }
}
impl MmioWindow for Model {
    fn read32(&self, off: u64) -> u32 {
        let mut state = self.0.borrow_mut();
        if state.unavailable {
            return u32::MAX;
        }
        if off == 0x70040 || off == 0x71040 {
            if let Some(frame) = state.frames.pop_front() {
                return frame;
            }
        }
        state.regs.get(&off).copied().unwrap_or(0)
    }
    fn write32(&self, off: u64, value: u32) {
        let mut state = self.0.borrow_mut();
        state.writes.push((off, value));
        if state.unavailable
            || (state.drop_ptes && off >= 0x800000)
            || (state.drop_surface && (off == 0x7019c || off == 0x7119c))
        {
            return;
        }
        if off == 0x44408 || off == 0x44418 {
            *state.regs.entry(off).or_default() &= !value;
        } else {
            state.regs.insert(off, value);
        }
    }
}
// SAFETY: no hardware accesses; invalidation is modeled independently of
// writes, including the failure path. The Rc retains the register owner.
unsafe impl ScanoutIo for Model {
    fn invalidate_ggtt(&self) -> bool {
        let mut state = self.0.borrow_mut();
        state.invalidations += 1;
        state.invalidate && !state.unavailable
    }
}

fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    }
}
fn object(size: u64) -> Arc<GemObject> {
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(size, |_, _| Ok(())).expect("GEM allocation");
    let object = gem.object(handle).expect("object");
    gem.close(handle).expect("close handle before scanout");
    object
}
fn presenter(model: &Model) -> Presenter<Model> {
    // SAFETY: the model exclusively owns its fake function/plane and starts
    // with invalid new GGTT slots; no DMA or actual power owner exists.
    unsafe {
        Presenter::new(
            model.clone(),
            0x1000000,
            Pipe::A,
            PteFormat::Gen12,
            0,
            0x1000000,
        )
    }
    .expect("presenter")
}
fn shutdown(owner: &mut Presenter<Model>) {
    // SAFETY: the modeled fetch engine has been stopped by the fixture.
    unsafe { owner.shutdown_stopped() }.expect("stopped release");
}

fn scanout_reservations_exclude_other_pipes_and_gt() -> TestResult {
    use crate::intel_gpu_gtt::{check_console_scanout_range, GttError};
    if (GEM_SCANOUT_GTT_START, GEM_SCANOUT_GTT_END) != (0x0a000000, 0x10000000)
        || u64::from(crate::intel_gpu_rcs::GGTT_ARENA_BASE) < GEM_SCANOUT_GTT_END
    {
        return TestResult::Fail("scanout and submission arenas overlap");
    }
    for offset in [0x01000000, 0x03000000, 0x05000000, 0x07000000] {
        if check_console_scanout_range(0x1000000, offset, 0x02000000) != Ok(())
            || check_console_scanout_range(0x1000000, offset, 0x02000001)
                != Err(GttError::OutOfBounds)
        {
            return TestResult::Fail("legacy scanout escaped its 32 MiB pipe window");
        }
    }
    for offset in [0, 0x01001000, 0x09000000, 0x0a000000, 0x10000000] {
        if check_console_scanout_range(0x1000000, offset, 4096) != Err(GttError::OutOfBounds) {
            return TestResult::Fail("unreserved legacy scanout window admitted");
        }
    }
    let never_dereference = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0x1000000,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    if crate::intel_gpu_gtt::map_contiguous_scanout(&never_dereference, 0x200000, 0x02000001)
        != Err(GttError::OutOfBounds)
        || crate::intel_gpu_gtt::alloc_contiguous_scanout_at(&never_dereference, 0x0a000000, 4096)
            .is_ok()
    {
        return TestResult::Fail("production mapper touched an overlapping reservation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_reservations_exclude_other_pipes_and_gt
);

fn scanout_rejects_wb_and_bad_geometry_before_writes() -> TestResult {
    if (Geometry {
        width: 64,
        height: 1,
        pitch: 252 * 1024,
    })
    .extent()
        != Ok(258048)
    {
        return TestResult::Fail("last encodable 4 KiB-aligned direct stride refused");
    }
    let model = Model::new();
    let mut owner = presenter(&model);
    let object = object(8192);
    object.mark_scanout();
    if owner.prepare(object.clone(), geometry()) != Err(ScanoutError::Unsupported)
        || !model.0.borrow().writes.is_empty()
    {
        return TestResult::Fail("WB framebuffer reached PTE writes");
    }
    for geometry in [
        Geometry {
            width: 0,
            ..geometry()
        },
        Geometry {
            width: 8193,
            ..geometry()
        },
        Geometry {
            height: 8193,
            ..geometry()
        },
        Geometry {
            pitch: 255,
            ..geometry()
        },
        Geometry {
            pitch: 192,
            ..geometry()
        },
        Geometry {
            pitch: 256 * 1024,
            ..geometry()
        },
        Geometry {
            pitch: 256 * 1024 + 64,
            ..geometry()
        },
        Geometry {
            pitch: 128 * 1024 + 64,
            ..geometry()
        },
        Geometry {
            height: 8192,
            pitch: 32768,
            ..geometry()
        },
    ] {
        if owner.prepare_object(object.clone(), geometry) != Err(ScanoutError::Unsupported) {
            return TestResult::Fail("unsupported framebuffer geometry admitted");
        }
    }
    if !model.0.borrow().writes.is_empty() || !owner.surfaces.is_empty() {
        return TestResult::Fail("invalid geometry allocated a window");
    }
    shutdown(&mut owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_rejects_wb_and_bad_geometry_before_writes
);

fn scanout_maps_retained_pages_and_reuses_only_after_invalidation() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let object = object(16384);
    let pages: Vec<u64> = object.pages().collect();
    let weak = Arc::downgrade(&object);
    // WB test pages exercise the same mapping/lifetime core on both arches;
    // the public admission above still refuses them for real display fetch.
    let id = owner.prepare_object(object, geometry()).expect("map");
    if weak.upgrade().is_none()
        || model.read32(0x850000) != pages[0] as u32 | 1
        || model.read32(0x850004) != (pages[0] >> 32) as u32
        || model.read32(0x850008) != pages[1] as u32 | 1
        || model.read32(0x850010) != 0
        || model.0.borrow().invalidations != 1
    {
        return TestResult::Fail("owned extent/PTE publication differs from literal GGTT layout");
    }
    model.0.borrow_mut().invalidate = false;
    if owner.release(id) != Err(ScanoutError::Unavailable)
        || weak.upgrade().is_none()
        || !owner.free.iter().all(|&(offset, _)| offset != 0x0a000000)
    {
        return TestResult::Fail("failed invalidation freed RAM or reused the window");
    }
    model.0.borrow_mut().invalidate = true;
    shutdown(&mut owner);
    if weak.upgrade().is_some() || model.read32(0x850000) != 0 || model.read32(0x850008) != 0 {
        return TestResult::Fail("verified stopped teardown did not release the mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_maps_retained_pages_and_reuses_only_after_invalidation
);

fn scanout_latch_requires_fresh_status_live_address_and_frame() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let first = owner
        .prepare_object(object(8192), geometry())
        .expect("first");
    let next_object = object(8192);
    let next_weak = Arc::downgrade(&next_object);
    let next = owner.prepare_object(next_object, geometry()).expect("next");
    // Old flip-done plus an unrelated cursor status: arming clears only bit3.
    model.set(0x44408, 8 | (1 << 11));
    owner.arm(first, 21, 100).expect("arm first");
    if model.read32(0x44408) != 1 << 11
        || owner.poll(101) != Ok(None)
        || owner.release(first) != Err(ScanoutError::Busy)
        || owner.arm(next, 22, 102) != Err(ScanoutError::Busy)
    {
        return TestResult::Fail("pending surface replaced/released or stale status completed it");
    }
    model.set(0x701ac, 0x0a000000);
    model.set(0x70040, 41);
    if owner.poll(103) != Ok(None) {
        return TestResult::Fail("live surface and frame completed without flip-done");
    }
    model.set(0x44408, 8 | (1 << 11));
    model.set(0x70040, 40);
    if owner.poll(104) != Ok(None) {
        return TestResult::Fail("unchanged frame completed flip");
    }
    model.set(0x701ac, 0x01000000);
    model.set(0x70040, 41);
    if owner.poll(105) != Ok(None) {
        return TestResult::Fail("old live surface completed flip");
    }
    model.land(0x0a000000, 41);
    let completion = owner.poll(106).expect("poll").expect("latch");
    if completion.ticket != 21
        || completion.stamp.sequence != 41
        || completion.stamp.ns != 106
        || completion.retired.is_some()
        || model.read32(0x44408) != 1 << 11
    {
        return TestResult::Fail("completion does not carry this latch evidence");
    }
    owner.arm(next, 22, 110).expect("arm next");
    if owner.release(first) != Err(ScanoutError::Busy) || next_weak.upgrade().is_none() {
        return TestResult::Fail("previous front was freed before replacement latched");
    }
    model.land(0x0a002000, 42);
    let completion = owner.poll(111).expect("poll next").expect("next latch");
    if completion.retired != Some(first) || completion.ticket != 22 {
        return TestResult::Fail("replacement did not retire previous front");
    }
    owner.release(first).expect("retired release");
    if owner.release(next) != Err(ScanoutError::Busy) {
        return TestResult::Fail("current surface released");
    }
    shutdown(&mut owner);
    if next_weak.upgrade().is_some() {
        return TestResult::Fail("stopped current buffer still retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_latch_requires_fresh_status_live_address_and_frame
);

fn scanout_timeout_and_failed_stop_retain_pending_and_previous() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let first_object = object(8192);
    let first_weak = Arc::downgrade(&first_object);
    let first = owner
        .prepare_object(first_object, geometry())
        .expect("first");
    owner.arm(first, 1, 0).expect("first arm");
    model.land(0x0a000000, 41);
    owner.poll(1).expect("first poll").expect("first latch");
    let next_object = object(8192);
    let next_weak = Arc::downgrade(&next_object);
    let next = owner.prepare_object(next_object, geometry()).expect("next");
    owner.arm(next, 2, 2).expect("next arm");
    if owner.poll(1_000_000_002) != Err(ScanoutError::Timeout)
        || first_weak.upgrade().is_none()
        || next_weak.upgrade().is_none()
        || owner.release(first) != Err(ScanoutError::Unavailable)
    {
        return TestResult::Fail("timeout completed or reclaimed an uncertain fetch");
    }
    model.0.borrow_mut().invalidate = false;
    // SAFETY: the modeled engine has stopped; invalidation deliberately fails.
    if unsafe { owner.shutdown_stopped() } != Err(ScanoutError::Unavailable)
        || first_weak.upgrade().is_none()
        || next_weak.upgrade().is_none()
    {
        return TestResult::Fail("failed stopped teardown released a buffer");
    }
    model.0.borrow_mut().invalidate = true;
    shutdown(&mut owner);
    if first_weak.upgrade().is_some() || next_weak.upgrade().is_some() {
        return TestResult::Fail("verified stopped retry failed to reclaim buffers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_timeout_and_failed_stop_retain_pending_and_previous
);

fn scanout_failed_mapping_and_arm_keep_their_owners() -> TestResult {
    for mapping_failure in [true, false] {
        let model = Model::new();
        let mut owner = presenter(&model);
        let object = object(8192);
        let weak = Arc::downgrade(&object);
        model.0.borrow_mut().drop_ptes = mapping_failure;
        let result = owner.prepare_object(object, geometry());
        if mapping_failure {
            if result != Err(ScanoutError::Unavailable) || weak.upgrade().is_none() {
                return TestResult::Fail("failed PTE publication dropped object");
            }
        } else {
            let id = result.expect("prepared");
            model.0.borrow_mut().drop_surface = true;
            if owner.arm(id, 9, 0) != Err(ScanoutError::Unavailable)
                || weak.upgrade().is_none()
                || owner.pending.is_none()
            {
                return TestResult::Fail("failed SURF readback discarded uncertain pending owner");
            }
        }
        model.0.borrow_mut().drop_ptes = false;
        shutdown(&mut owner);
        if weak.upgrade().is_some() {
            return TestResult::Fail("stopped failure cleanup retained object");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_failed_mapping_and_arm_keep_their_owners
);

fn scanout_raced_counter_wrap_and_same_surface_need_new_evidence() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let id = owner.prepare_object(object(8192), geometry()).expect("map");
    model.set(0x70040, 0xfffffffe);
    owner.arm(id, 11, 0).expect("arm");
    model.land(0x0a000000, 0);
    model.0.borrow_mut().frames.extend([0, 1]);
    if owner.poll(1) != Ok(None) {
        return TestResult::Fail("counter changed during sampling yet completed");
    }
    if owner
        .poll(2)
        .expect("wrapped poll")
        .expect("wrapped latch")
        .stamp
        .sequence
        != 0
    {
        return TestResult::Fail("hardware frame-counter wrap lost");
    }
    model.set(0x44408, 8);
    owner.arm(id, 12, 3).expect("same address arm");
    if owner.poll(4) != Ok(None) {
        return TestResult::Fail("same live address reused an earlier flip-done");
    }
    model.land(0x0a000000, 1);
    let completed = owner.poll(5).expect("same poll").expect("same latch");
    if completed.ticket != 12 || completed.retired.is_some() {
        return TestResult::Fail("same surface lost its owner or ticket");
    }
    shutdown(&mut owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_raced_counter_wrap_and_same_surface_need_new_evidence
);

fn scanout_gpu_writer_and_foreign_geometry_refuse_before_surface_arm() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let object = object(8192);
    let id = owner
        .prepare_object(object.clone(), geometry())
        .expect("map");
    let completion = Arc::new(crate::intel_gpu_fence::CompletionFence::new());
    crate::intel_gpu_gem::reserve_gpu(&[(object, true)], &completion).expect("writer");
    let writes = model.0.borrow().writes.len();
    if owner.arm(id, 4, 0) != Err(ScanoutError::Busy) || model.0.borrow().writes.len() != writes {
        return TestResult::Fail("busy GPU writer reached scanout arm");
    }
    completion.signal(Ok(()));
    for (reg, bad, good) in [
        (0x70188, 5, 4),
        (0x70190, 0x001f0040, 0x001f003f),
        (0x701a4, 1, 0),
        (0x70180, 0x84000400, 0x84000000),
        (0x70180, 0x84100000, 0x84000000),
        (0x70180, 0x84008000, 0x84000000),
        (0x70180, 0x84000010, 0x84000000),
        (0x70180, 0x84000100, 0x84000000),
        (0x70180, 0x84000200, 0x84000000),
        (0x70180, 0x84000001, 0x84000000),
        (0x701c0, 4096, 0),
        (0x701c4, 1, 0),
        (0x701c8, 1 << 31, 0),
        (0x701cc, 3 << 4, 0),
    ] {
        model.set(reg, bad);
        if owner.arm(id, 4, 0) != Err(ScanoutError::Unsupported)
            || model.0.borrow().writes.len() != writes
        {
            return TestResult::Fail("surface-only flip changed plane geometry/format");
        }
        model.set(reg, good);
    }
    shutdown(&mut owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_gpu_writer_and_foreign_geometry_refuse_before_surface_arm
);

fn scanout_fault_and_device_loss_never_complete() -> TestResult {
    for unavailable in [false, true] {
        let model = Model::new();
        let mut owner = presenter(&model);
        let object = object(8192);
        let weak = Arc::downgrade(&object);
        let id = owner.prepare_object(object, geometry()).expect("map");
        owner.arm(id, 6, 0).expect("arm");
        model.land(0x0a000000, 41);
        model.set(0x44408, 8 | 128);
        model.0.borrow_mut().unavailable = unavailable;
        if owner.poll(1) != Err(ScanoutError::Unavailable)
            || weak.upgrade().is_none()
            || owner.current.is_some()
            || owner.pending.is_none()
        {
            return TestResult::Fail("fault/device loss manufactured completion or freed pages");
        }
        model.0.borrow_mut().unavailable = false;
        shutdown(&mut owner);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_fault_and_device_loss_never_complete
);

fn scanout_retired_windows_coalesce_after_verified_clear() -> TestResult {
    let model = Model::new();
    let mut owner = presenter(&model);
    let small = Geometry {
        height: 16,
        ..geometry()
    };
    let first = owner.prepare_object(object(4096), small).expect("first");
    let second = owner.prepare_object(object(4096), small).expect("second");
    owner.release(first).expect("release first");
    owner.release(second).expect("release second");
    let full = owner
        .prepare_object(object(8192), geometry())
        .expect("coalesced");
    if owner.surfaces[&full].offset != 0x0a000000
        || owner.free != alloc::vec![(0x0a002000, 24574)]
        || model.0.borrow().invalidations != 5
    {
        return TestResult::Fail("cleared windows were not safely coalesced/reused");
    }
    shutdown(&mut owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_retired_windows_coalesce_after_verified_clear
);

fn scanout_public_prepare_requires_wc_scanout_and_waits_for_writer() -> TestResult {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let result = gem.create_placed(8192, None, Placement::SystemWc, |_, _| Ok(()));
    #[cfg(target_arch = "aarch64")]
    {
        if result != Err(narf_filesystem::FsError::NotImplemented) {
            return TestResult::Fail("aarch64 admitted WC pages without linear-map retyping");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    {
        let Ok(handle) = result else {
            return TestResult::Fail("x86 WC system allocation refused");
        };
        let object = gem.object(handle).expect("WC object");
        let weak = Arc::downgrade(&object);
        let model = Model::new();
        let mut owner = presenter(&model);
        if owner.prepare(object.clone(), geometry()) != Err(ScanoutError::Unsupported)
            || !model.0.borrow().writes.is_empty()
        {
            return TestResult::Fail("non-SCANOUT WC object was published");
        }
        object.mark_scanout();
        let fence = Arc::new(crate::intel_gpu_fence::CompletionFence::new());
        crate::intel_gpu_gem::reserve_gpu(&[(object.clone(), true)], &fence).expect("writer");
        if owner.prepare(object.clone(), geometry()) != Err(ScanoutError::Busy)
            || !model.0.borrow().writes.is_empty()
        {
            return TestResult::Fail("busy public prepare published GGTT pages");
        }
        fence.signal(Ok(()));
        let id = owner
            .prepare(object.clone(), geometry())
            .expect("public WC prepare");
        gem.close(handle).expect("close while pinned");
        drop(object);
        owner.arm(id, 17, 0).expect("public WC arm");
        model.land(0x0a000000, 41);
        if owner.poll(1).expect("WC poll").expect("WC latch").ticket != 17
            || weak.upgrade().is_none()
        {
            return TestResult::Fail("public WC presentation lost latch or pinned storage");
        }
        shutdown(&mut owner);
        if weak.upgrade().is_some() {
            return TestResult::Fail("WC aliases retained after verified stopped release");
        }
        TestResult::Pass
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_public_prepare_requires_wc_scanout_and_waits_for_writer
);

fn scanout_xelpg_pipe_b_pat_and_ats_vectors() -> TestResult {
    for fault in [0, 1 << 18, 1 << 24, 1 << 25] {
        let model = Model::new();
        for (off, value) in [
            (0x71180, 0x84000000),
            (0x71188, 4),
            (0x71190, 0x001f003f),
            (0x711a4, 0),
            (0x7119c, 0x03000000),
            (0x711ac, 0x03000000),
            (0x71040, 100),
            (0x44418, 0),
        ] {
            model.set(off, value);
        }
        // SAFETY: pipe B is exclusively owned in this model, with invalid
        // new windows; PAT2 is the fixture's programmed Xe-LPG policy.
        let mut owner = unsafe {
            Presenter::new(
                model.clone(),
                0x1000000,
                Pipe::B,
                PteFormat::XeLpg,
                2,
                0x03000000,
            )
        }
        .expect("pipe B");
        let object = object(8192);
        let phys = object.pages().next().expect("page");
        let id = owner
            .prepare_object(object, geometry())
            .expect("Xe-LPG map");
        if model.read32(0x850004) != (phys >> 32) as u32 | 0x00200000 {
            return TestResult::Fail("Xe-LPG GGTT PAT2 is not bit53");
        }
        model.set(0x44408, 8); // another pipe's event belongs to its owner
        owner.arm(id, 71, 0).expect("pipe B arm");
        model.set(0x711ac, 0x0a000000);
        model.set(0x71040, 101);
        model.set(0x44418, 8 | fault);
        let result = owner.poll(1);
        if fault == 0 {
            if result.expect("B poll").expect("B latch").stamp.sequence != 101 {
                return TestResult::Fail("pipe B sampled another pipe's counter");
            }
        } else if result != Err(ScanoutError::Unavailable) || owner.pending.is_none() {
            return TestResult::Fail("Xe-LPG ATS/DMC fault completed presentation");
        }
        if model.read32(0x44408) != 8 || !model.0.borrow().writes.contains(&(0x7119c, 0x0a000000)) {
            return TestResult::Fail("pipe B ack/arm touched pipe A ownership");
        }
        shutdown(&mut owner);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    scanout_xelpg_pipe_b_pat_and_ats_vectors
);

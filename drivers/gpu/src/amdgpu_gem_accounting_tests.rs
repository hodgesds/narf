//! The accounting walks against a small owned heap: what the card, each
//! open and a failure report say, and what a full heap does to the next
//! allocation.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const PAGE: u64 = PAGE_SIZE;

struct Heap {
    card: u32,
    memory: Vec<u8>,
}
impl Heap {
    fn new(card: u32, pages: usize) -> Option<Self> {
        let mut memory = alloc::vec![0u8; pages * PAGE as usize];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xbb00_0000),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: the fixture owns these bytes until the heap is withdrawn
        // and every object has been dropped; no hardware reaches them.
        let pool =
            unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.ok()?;
        register_vram_heap(
            card,
            VramHeap {
                pool,
                fb_base: 0x8_0000_0000,
                fb_offset: 0x8_0000_0000,
                unmapped: None,
            },
        );
        Some(Self { card, memory })
    }
}
impl Drop for Heap {
    fn drop(&mut self) {
        unregister_vram_heap(self.card);
        let _ = &self.memory;
    }
}

/// GEM_CREATE of `pages` pages in `domains` with `flags` on `state`.
fn create(
    state: &GemState,
    pages: u64,
    domains: u32,
    flags: u32,
) -> Result<Arc<GemObject>, FsError> {
    let mut request = [0u8; 32];
    request[..8].copy_from_slice(&(pages * PAGE).to_le_bytes());
    request[8..16].copy_from_slice(&PAGE.to_le_bytes());
    request[16..24].copy_from_slice(&u64::from(domains).to_le_bytes());
    request[24..32].copy_from_slice(&u64::from(flags).to_le_bytes());
    dispatch(0xc020_6440, request.as_mut_ptr() as usize, state)?;
    state
        .get(u32::from_le_bytes(request[..4].try_into().unwrap()))
        .ok_or(FsError::NotFound)
}

fn accounting_names_the_heap_its_holders_and_its_pins() -> TestResult {
    const CARD: u32 = 0xe1c2;
    let Some(_heap) = Heap::new(CARD, 16) else {
        return TestResult::Fail("heap");
    };
    let vram = uapi::AMDGPU_GEM_DOMAIN_VRAM;
    let gtt = uapi::AMDGPU_GEM_DOMAIN_GTT;
    let base_gtt = gtt_used();
    let (a, b) = (GemState::for_card(CARD), GemState::for_card(CARD));
    // Open a: one and two pages of VRAM, three pages of system memory.
    // Open b: four pages of VRAM and a's first buffer, imported.
    let (Ok(a1), Ok(_a2), Ok(_a3), Ok(_b1)) = (
        create(&a, 1, vram, 0),
        create(&a, 2, vram, 0),
        create(&a, 3, gtt, 0),
        create(&b, 4, vram, 0),
    ) else {
        return TestResult::Fail("buffers");
    };
    if b.import(&a1).is_err() {
        return TestResult::Fail("import");
    }
    let Ok(pin) = a1.pin_scanout() else {
        return TestResult::Fail("pin");
    };

    let usage = card_usage(CARD);
    if usage.visible != (16 * PAGE, 7 * PAGE, 9 * PAGE)
        || usage.hidden != (0, 0)
        || usage.system.1 != base_gtt + 3 * PAGE
        || usage.buffers != 4
        || usage.pinned != (PAGE, 1)
        || usage.evictable != 6 * PAGE
    {
        return TestResult::Fail("card usage");
    }
    let opens = opens(CARD);
    if opens.len() != 2
        || (opens[0].vram, opens[0].system, opens[0].buffers) != (3 * PAGE, 3 * PAGE, 3)
        || (opens[1].vram, opens[1].system, opens[1].buffers) != (5 * PAGE, 0, 2)
        || opens[0].requested_vram != 3 * PAGE
        || opens[0].requested_gtt != 3 * PAGE
        || opens[0].evicted != 0
        || opens[0].client == opens[1].client
    {
        return TestResult::Fail("per-open usage");
    }
    for (which, want) in [
        (MemInfo::VramTotal, 16 * PAGE),
        (MemInfo::VramUsed, 7 * PAGE),
        (MemInfo::VisVramTotal, 16 * PAGE),
        (MemInfo::VisVramUsed, 7 * PAGE),
        (MemInfo::GttTotal, gtt_limit()),
        (MemInfo::GttUsed, base_gtt + 3 * PAGE),
    ] {
        if mem_info(CARD, which) != want {
            return TestResult::Fail("mem_info value");
        }
    }
    let mut text = String::new();
    fdinfo(&a, Some("0000:03:00.0"), &mut text);
    for line in [
        "drm-pdev:\t0000:03:00.0\n",
        "drm-total-vram:\t12 KiB\n",
        "drm-resident-gtt:\t12 KiB\n",
        "drm-memory-vram:\t12 KiB\n",
        "drm-memory-gtt: \t12 KiB\n",
        "drm-memory-cpu: \t0 KiB\n",
        "amd-evicted-vram:\t0 KiB\n",
        "amd-requested-vram:\t12 KiB\n",
        "amd-requested-gtt:\t12 KiB\n",
    ] {
        if !text.contains(line) {
            return TestResult::Fail("fdinfo line");
        }
    }
    if !text.starts_with("drm-driver:\tamdgpu\ndrm-client-id:\t") {
        return TestResult::Fail("fdinfo driver and client id");
    }
    let report = failure_report(CARD, "GEM_CREATE", 8 * PAGE, 4, 0, FsError::NoSpace, (3, 2));
    for part in [
        "GEM_CREATE of 32 KiB (domains 0x4 flags 0x0) failed NoSpace",
        "; failure 3 on this card, 2 since the last report not reported",
        "vram 64 KiB: used 28 free 36 largest-free 36 pinned 4 (1 buffers) evictable 24;",
        "; 4 buffers",
        "vram 12 KiB system 12 KiB borrowed 0 KiB, 3 buffers]",
        "vram 20 KiB system 0 KiB borrowed 0 KiB, 2 buffers]",
    ] {
        if !report.contains(part) {
            return TestResult::Fail("failure report");
        }
    }
    drop(pin);
    if card_usage(CARD).pinned != (0, 0) || card_usage(CARD).evictable != 7 * PAGE {
        return TestResult::Fail("usage after unpin");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-accounting",
    accounting_names_the_heap_its_holders_and_its_pins
);

/// A full heap, as amdgpu_bo_create treats it: a VRAM-preferred buffer
/// lands in system pages (GTT) and counts there; a VRAM-only DISCARDABLE
/// one is refused with ENOMEM's `NoSpace`, which is counted and reported,
/// and leaves nothing behind.
fn full_heap_falls_back_to_system_pages_or_is_refused_and_counted() -> TestResult {
    const CARD: u32 = 0xe1c3;
    let Some(_heap) = Heap::new(CARD, 4) else {
        return TestResult::Fail("heap");
    };
    let vram = uapi::AMDGPU_GEM_DOMAIN_VRAM;
    let state = GemState::for_card(CARD);
    let base_gtt = gtt_used();
    // Fill the heap with buffers that cannot leave it.
    let mut pins = Vec::new();
    for _ in 0..4 {
        let Ok(object) = create(&state, 1, vram, 0) else {
            return TestResult::Fail("fill");
        };
        if object.system() {
            return TestResult::Fail("fill landed outside VRAM");
        }
        match object.pin_scanout() {
            Ok(pin) => pins.push(pin),
            Err(_) => return TestResult::Fail("pin"),
        }
    }
    if mem_info(CARD, MemInfo::VramUsed) != mem_info(CARD, MemInfo::VramTotal)
        || card_usage(CARD).visible.2 != 0
        || card_usage(CARD).evictable != 0
    {
        return TestResult::Fail("heap is not full");
    }
    let before = failures(CARD);
    let Ok(fallback) = create(&state, 2, vram, 0) else {
        return TestResult::Fail("a VRAM-preferred buffer was refused with the heap full");
    };
    if !fallback.system()
        || gtt_used() != base_gtt + 2 * PAGE
        || opens(CARD).first().map(|o| (o.system, o.evicted)) != Some((2 * PAGE, 2 * PAGE))
        || failures(CARD) != before
    {
        return TestResult::Fail("fallback placement or its accounting");
    }
    let strict = create(&state, 1, vram, uapi::AMDGPU_GEM_CREATE_DISCARDABLE);
    if strict.err() != Some(FsError::NoSpace)
        || failures(CARD) != before + 1
        || gtt_used() != base_gtt + 2 * PAGE
        || card_usage(CARD).buffers != 5
    {
        return TestResult::Fail("a strict VRAM allocation was not refused, counted and clean");
    }
    // Within the report interval the next failure is counted, not logged.
    let again = create(&state, 1, vram, uapi::AMDGPU_GEM_CREATE_DISCARDABLE);
    if again.is_ok() || failures(CARD) != before + 2 {
        return TestResult::Fail("second failure not counted");
    }
    drop(pins);
    drop(fallback);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-accounting",
    full_heap_falls_back_to_system_pages_or_is_refused_and_counted
);

/// A handle table's lock is an IRQ-safe spinlock every lookup of that open
/// takes. A walk (fdinfo, a failure report, an eviction) holds it only to
/// copy the references out: the table is free again while the buffers are
/// counted, a buffer under several handles counts once, and the buffers
/// come out in handle order.
fn a_walk_copies_the_handles_out_and_counts_with_the_table_free() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering as O};
    const CARD: u32 = 0xe1c5;
    struct Probe;
    impl Drop for Probe {
        fn drop(&mut self) {
            *WALK_PROBE.lock() = None;
        }
    }
    let Some(_heap) = Heap::new(CARD, 16) else {
        return TestResult::Fail("heap");
    };
    let vram = uapi::AMDGPU_GEM_DOMAIN_VRAM;
    let state = GemState::for_card(CARD);
    let (Ok(first), Ok(second), Ok(third)) = (
        create(&state, 1, vram, 0),
        create(&state, 2, vram, 0),
        create(&state, 4, vram, 0),
    ) else {
        return TestResult::Fail("buffers");
    };
    // The same buffers again under further handles (GETFB2 hands these
    // out), out of order.
    if state.handle_create(&third).is_err()
        || state.handle_create(&first).is_err()
        || state.handle_create(&third).is_err()
    {
        return TestResult::Fail("duplicate handles");
    }
    static RAN: AtomicU32 = AtomicU32::new(0);
    static LOCKED: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, O::Release);
    LOCKED.store(0, O::Release);
    let table = state.table();
    let _probe = Probe;
    *WALK_PROBE.lock() = Some(Arc::new(move || {
        RAN.fetch_add(1, O::AcqRel);
        if table.try_lock().is_none() {
            LOCKED.fetch_add(1, O::AcqRel);
        }
    }));
    let opens = opens(CARD);
    let mut text = String::new();
    fdinfo(&state, None, &mut text);
    if RAN.load(O::Acquire) != 2 {
        return TestResult::Fail("the walks did not run");
    }
    if LOCKED.load(O::Acquire) != 0 {
        return TestResult::Fail("buffers were counted under the open's handle-table lock");
    }
    if opens.len() != 1
        || (opens[0].vram, opens[0].buffers) != (7 * PAGE, 3)
        || !text.contains("drm-memory-vram:\t28 KiB\n")
    {
        return TestResult::Fail("a buffer under several handles was counted more than once");
    }
    let candidates = eviction_candidates(CARD);
    if candidates.len() != 3
        || !Arc::ptr_eq(&candidates[0], &first)
        || !Arc::ptr_eq(&candidates[1], &second)
        || !Arc::ptr_eq(&candidates[2], &third)
    {
        return TestResult::Fail("eviction candidates are not each buffer once, oldest first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-accounting",
    a_walk_copies_the_handles_out_and_counts_with_the_table_free
);

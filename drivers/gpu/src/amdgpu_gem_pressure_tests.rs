//! What GEM does when memory is short: how system backing walks the buddy
//! orders (ttm_pool_alloc), and where a synchronous relocation copies a
//! buffer (ttm_bo_move_memcpy runs under the buffer's reservation, a
//! sleeping lock, with interrupts on).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// ttm_pool_alloc: the walk starts at the largest order that fits and,
/// once an order fails, never asks for it again
/// (`order = ttm_pool_alloc_find_order(order, alloc)` after `--order`): at
/// most one failed attempt per order, however large the buffer.
fn system_backing_lowers_the_order_once_as_ttm_pool_alloc() -> TestResult {
    // A 3840x2160 XRGB8888 buffer: 8448 pages.
    const PAGES: u64 = 8448;
    let run = |largest_free: u8| {
        let mut attempts: Vec<(u8, bool)> = Vec::new();
        let mut freed = 0u64;
        let mut next = 0x1_0000_0000u64;
        let chunks = alloc_blocks(
            PAGES,
            10,
            |order| {
                let ok = order <= largest_free;
                attempts.push((order, ok));
                ok.then(|| {
                    let at = next;
                    next += PAGE_SIZE << order;
                    at
                })
            },
            |_, order| freed += 1 << order,
        );
        (chunks, attempts, freed)
    };
    // Nothing fragmented: the binary decomposition, largest first.
    let (chunks, attempts, _) = run(10);
    let Ok(chunks) = chunks else {
        return TestResult::Fail("allocation with every order free");
    };
    let orders: Vec<u8> = chunks.iter().map(|c| c.1).collect();
    if orders != [10, 10, 10, 10, 10, 10, 10, 10, 8] || attempts.iter().any(|a| !a.1) {
        return TestResult::Fail("unfragmented walk is not the largest-first decomposition");
    }
    // Nothing above order 3 free: one refusal each for orders 10..=4, then
    // 1056 order-3 blocks.
    let (chunks, attempts, freed) = run(3);
    let Ok(chunks) = chunks else {
        return TestResult::Fail("allocation with only small orders free");
    };
    let pages: u64 = chunks.iter().map(|c| 1u64 << c.1).sum();
    if pages != PAGES || chunks.iter().any(|c| c.1 > 3) || freed != 0 {
        return TestResult::Fail("fragmented walk did not cover the buffer exactly");
    }
    // Buffer order: each block starts where the previous one ended.
    let contiguous = chunks
        .windows(2)
        .all(|w| w[1].0 == w[0].0 + (PAGE_SIZE << w[0].1));
    if !contiguous {
        return TestResult::Fail("blocks are not in buffer order");
    }
    let refused = attempts.iter().filter(|a| !a.1).count();
    if refused != 7 {
        return TestResult::Fail("an order the allocator refused was asked for again");
    }
    // Out of pages: everything taken so far goes back, and it is ENOMEM.
    let mut left = 100u64;
    let mut taken = 0u64;
    let mut freed = 0u64;
    let result = alloc_blocks(
        PAGES,
        10,
        |order| {
            (order == 0 && left > 0).then(|| {
                left -= 1;
                taken += 1;
                0x2_0000_0000 + taken * PAGE_SIZE
            })
        },
        |_, order| freed += 1 << order,
    );
    if result.is_ok() || freed != 100 {
        return TestResult::Fail("a failed walk kept or lost blocks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    system_backing_lowers_the_order_once_as_ttm_pool_alloc
);

struct Heap {
    card: u32,
    memory: Vec<u8>,
}
impl Heap {
    fn new(card: u32, pages: usize) -> Option<Self> {
        let mut memory = alloc::vec![0u8; pages * PAGE_SIZE as usize];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xba00_0000),
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
    fn used(&self) -> u64 {
        vram_heap_usage(self.card).map_or(u64::MAX, |u| u.visible.1)
    }
}
impl Drop for Heap {
    fn drop(&mut self) {
        *RELOCATE_COPY_HOOK.lock() = None;
        unregister_vram_heap(self.card);
        let _ = &self.memory;
    }
}

fn vram_object(state: &GemState, bytes: u64) -> Option<Arc<GemObject>> {
    let mut request = [0u8; 32];
    request[..8].copy_from_slice(&bytes.to_le_bytes());
    request[8..16].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    request[16..24].copy_from_slice(
        &u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM | uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes(),
    );
    dispatch(0xc020_6440, request.as_mut_ptr() as usize, state).ok()?;
    state.get(u32::from_le_bytes(request[..4].try_into().unwrap()))
}

/// A synchronous move (eviction for an allocation, promotion on lookup)
/// copies the whole buffer. The object's placement lock is an IRQ-safe
/// spinlock every reader of the buffer's address takes, so the copy must
/// not run under it: it runs on a leased source, and the new placement is
/// published only if nothing took the buffer's address meanwhile.
fn relocation_copies_outside_the_placement_lock() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering as O};
    const CARD: u32 = 0xe1c1;
    let Some(heap) = Heap::new(CARD, 16) else {
        return TestResult::Fail("heap");
    };
    let state = GemState::for_card(CARD);
    let Some(object) = vram_object(&state, 2 * PAGE_SIZE) else {
        return TestResult::Fail("VRAM object");
    };
    if object.system() || object.store_u64(4096 + 8, 0x6e61_7266_0001).is_none() {
        return TestResult::Fail("object is not in VRAM");
    }
    let (base_vram, base_gtt) = (heap.used(), gtt_used());

    // 1: the lock is free while the bytes are copied.
    static RAN: AtomicU32 = AtomicU32::new(0);
    static LOCKED: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, O::Release);
    LOCKED.store(0, O::Release);
    let probed = object.clone();
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(move || {
        RAN.fetch_add(1, O::AcqRel);
        if probed.placement.try_lock().is_none() {
            LOCKED.fetch_add(1, O::AcqRel);
        }
    }));
    let moved = object.relocate(false);
    *RELOCATE_COPY_HOOK.lock() = None;
    if RAN.load(O::Acquire) != 1 {
        return TestResult::Fail("the move did not copy");
    }
    if LOCKED.load(O::Acquire) != 0 {
        return TestResult::Fail("the buffer was copied under its IRQ-safe placement lock");
    }
    if moved.is_err()
        || !object.system()
        || object.load_u64(4096 + 8) != Some(0x6e61_7266_0001)
        || heap.used() != base_vram - 2 * PAGE_SIZE
        || gtt_used() != base_gtt + 2 * PAGE_SIZE
    {
        return TestResult::Fail("eviction lost the buffer's bytes or its accounting");
    }

    // 2: an address lease taken while the copy runs (a writer the copy
    // cannot see) refuses the move; the buffer stays whole where it was
    // and the unused destination is returned.
    let writer = object.clone();
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(move || {
        let _ = writer.store_u64(8, 0x6e61_7266_0002);
    }));
    let refused = object.relocate(true);
    *RELOCATE_COPY_HOOK.lock() = None;
    if refused != Err(FsError::Busy)
        || !object.system()
        || object.load_u64(8) != Some(0x6e61_7266_0002)
        || object.load_u64(4096 + 8) != Some(0x6e61_7266_0001)
        || heap.used() != base_vram - 2 * PAGE_SIZE
        || gtt_used() != base_gtt + 2 * PAGE_SIZE
    {
        return TestResult::Fail("a move raced by a writer was published or leaked memory");
    }

    // 3: undisturbed, the promotion goes through and nothing is left over.
    if object.relocate(true).is_err()
        || object.system()
        || object.load_u64(8) != Some(0x6e61_7266_0002)
        || object.load_u64(4096 + 8) != Some(0x6e61_7266_0001)
        || heap.used() != base_vram
        || gtt_used() != base_gtt
    {
        return TestResult::Fail("promotion lost bytes or left memory behind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    relocation_copies_outside_the_placement_lock
);

/// A VM owner for the mapped move that has no address spaces to revoke:
/// it commits at once. The previous owner comes back when it drops.
struct CommitAtOnce(Option<narf_filesystem::mmap_relocation::RelocationHook>);
impl CommitAtOnce {
    fn install() -> Self {
        fn commit_at_once(
            _old: &[u64],
            _new: &[u64],
            _aliases: fn(u64) -> usize,
            commit: &mut dyn FnMut() -> Result<(), FsError>,
        ) -> Result<(), FsError> {
            commit()
        }
        Self(narf_filesystem::mmap_relocation::replace(Some(
            commit_at_once,
        )))
    }
}
impl Drop for CommitAtOnce {
    fn drop(&mut self) {
        narf_filesystem::mmap_relocation::replace(self.0.take());
    }
}

/// A lease taken while a buffer's bytes are copied refuses that copy, not
/// the move. A passing reader or writer of the address is gone again, so
/// the buffer is copied once more and published; one that keeps coming
/// is `Busy`, and the lookup path then leaves the buffer alone for a
/// while instead of copying it on every lookup; a CPU mapping that
/// appeared meanwhile makes it a mapped buffer, which moves as one.
fn a_move_survives_a_lease_taken_while_it_copies() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering as O};
    const CARD: u32 = 0xe1c7;
    let Some(heap) = Heap::new(CARD, 16) else {
        return TestResult::Fail("heap");
    };
    let state = GemState::for_card(CARD);
    let Some(object) = vram_object(&state, 2 * PAGE_SIZE) else {
        return TestResult::Fail("VRAM object");
    };
    // The open's first handle.
    if !state
        .get(HANDLE_BASE)
        .is_some_and(|o| Arc::ptr_eq(&o, &object))
    {
        return TestResult::Fail("handle");
    }
    let (in_vram, in_gtt) = (heap.used(), gtt_used());
    if object.relocate(false).is_err() || !object.system() {
        return TestResult::Fail("eviction");
    }
    static COPIES: AtomicU32 = AtomicU32::new(0);

    // 1: a writer during the first copy only.
    COPIES.store(0, O::Release);
    let writer = object.clone();
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(move || {
        if COPIES.fetch_add(1, O::AcqRel) == 0 {
            let _ = writer.store_u64(8, 0x6e61_7266_000a);
        }
    }));
    let moved = object.relocate(true);
    *RELOCATE_COPY_HOOK.lock() = None;
    if moved.is_err()
        || COPIES.load(O::Acquire) != 2
        || object.system()
        || object.load_u64(8) != Some(0x6e61_7266_000a)
        || heap.used() != in_vram
        || gtt_used() != in_gtt
    {
        return TestResult::Fail("a move raced once was not made again, or lost the write");
    }

    // 2: a writer during every copy: Busy after the second, and a lookup
    // does not copy the buffer a third time straight away.
    if object.relocate(false).is_err() {
        return TestResult::Fail("second eviction");
    }
    COPIES.store(0, O::Release);
    let writer = object.clone();
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(move || {
        COPIES.fetch_add(1, O::AcqRel);
        let _ = writer.store_u64(8, 0x6e61_7266_000b);
    }));
    let refused = object.relocate(true);
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(|| {
        COPIES.fetch_add(1, O::AcqRel);
    }));
    let looked_up = state.object(HANDLE_BASE).is_some();
    if refused != Err(FsError::Busy) || COPIES.load(O::Acquire) != 2 {
        return TestResult::Fail("a move raced every time was not given up after two copies");
    }
    if !looked_up || !object.system() {
        return TestResult::Fail("a lookup copied the buffer again right after a refused move");
    }
    // A move asked for by name is not deferred.
    let moved = object.relocate(true);
    *RELOCATE_COPY_HOOK.lock() = None;
    if moved.is_err()
        || COPIES.load(O::Acquire) != 3
        || object.system()
        || object.load_u64(8) != Some(0x6e61_7266_000b)
    {
        return TestResult::Fail("an explicit move after a refused one");
    }

    // 3: a client maps the buffer while its bytes are copied. The unmapped
    // move is refused; the buffer, mapped now, moves through the mapped
    // path instead of failing the caller.
    if object.relocate(false).is_err() {
        return TestResult::Fail("third eviction");
    }
    let _vm = CommitAtOnce::install();
    let mapping: Arc<IrqSafeSpinLock<Option<narf_filesystem::MmapBacking>>> =
        Arc::new(IrqSafeSpinLock::new(None));
    COPIES.store(0, O::Release);
    let (mapper, slot) = (object.clone(), mapping.clone());
    *RELOCATE_COPY_HOOK.lock() = Some(Arc::new(move || {
        if COPIES.fetch_add(1, O::AcqRel) != 0 {
            return;
        }
        if let Ok(map) = cpu_mapping::backing(mapper.clone(), 0, 2 * PAGE_SIZE as usize) {
            cpu_mapping::published(map.lifetime.as_ref());
            *slot.lock() = Some(map);
        }
    }));
    let moved = cpu_mapping::relocate(&object, true);
    *RELOCATE_COPY_HOOK.lock() = None;
    let mapped = mapping.lock().take();
    if mapped.is_none() {
        return TestResult::Fail("the client's mapping was not taken during the copy");
    }
    if moved.is_err()
        || COPIES.load(O::Acquire) != 1
        || object.system()
        || object.load_u64(8) != Some(0x6e61_7266_000b)
        || object.load_u64(4096 + 8) != Some(0)
    {
        return TestResult::Fail("a buffer mapped during its move did not move as a mapped one");
    }
    drop(mapped);
    if heap.used() != in_vram || gtt_used() != in_gtt {
        return TestResult::Fail("a refused copy was not returned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    a_move_survives_a_lease_taken_while_it_copies
);

/// prepare_fb must bring a framebuffer into VRAM even when a client is in
/// the middle of mapping it: the mapping exists but is not yet published
/// into the address space, which refuses the mapped move. The commit tries
/// once more a moment later (Linux's fault path waits on the buffer's
/// reservation while it moves) instead of failing with EBUSY after its
/// TEST_ONLY passed.
fn a_commit_waits_out_a_mapping_that_is_being_published() -> TestResult {
    use core::future::Future;
    use core::task::{Context, Waker};
    const CARD: u32 = 0xe1c8;
    let Some(_heap) = Heap::new(CARD, 16) else {
        return TestResult::Fail("heap");
    };
    let state = GemState::for_card(CARD);
    let Some(object) = vram_object(&state, 2 * PAGE_SIZE) else {
        return TestResult::Fail("VRAM object");
    };
    if object.store_u64(8, 0x6e61_7266_000c).is_none()
        || object.relocate(false).is_err()
        || !object.system()
    {
        return TestResult::Fail("a framebuffer in system pages");
    }
    let _vm = CommitAtOnce::install();
    let Ok(map) = cpu_mapping::backing(object.clone(), 0, 2 * PAGE_SIZE as usize) else {
        return TestResult::Fail("the client's mapping");
    };
    let mut commit = alloc::boxed::Box::pin(prepare_scanout(CARD, alloc::vec![object.clone()]));
    let mut cx = Context::from_waker(Waker::noop());
    if !commit.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("the commit did not wait for the mapping to be published");
    }
    if !object.system() {
        return TestResult::Fail("the buffer moved under an unpublished mapping");
    }
    cpu_mapping::published(map.lifetime.as_ref());
    let Ok(prepared) = narf_scheduler::block_on_spin(commit) else {
        return TestResult::Fail("the commit failed for a mapping that was being published");
    };
    if object.system() || object.load_u64(8) != Some(0x6e61_7266_000c) {
        return TestResult::Fail("the framebuffer did not reach VRAM whole");
    }
    drop(prepared);
    drop(map);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    a_commit_waits_out_a_mapping_that_is_being_published
);

/// ttm_tt_populate allocates a buffer's pages under the buffer's own
/// reservation, never under a device-wide lock. The card's placement gate
/// is taken by every job, VA edit and KMS commit, so a user open's
/// GEM_CREATE allocates and zeroes system pages before it waits for the
/// gate, and holds the gate only to publish the buffer. A create that is
/// cancelled while it waits returns its pages.
fn system_pages_are_allocated_outside_placement_admission() -> TestResult {
    use core::future::Future;
    use core::task::{Context, Waker};
    const CARD: u32 = 0xe1c4;
    let Some(_heap) = Heap::new(CARD, 4) else {
        return TestResult::Fail("heap");
    };
    let state = GemState::for_card(CARD);
    let base = gtt_used();
    let request = || {
        let mut request = [0u8; 32];
        request[..8].copy_from_slice(&(3 * PAGE_SIZE).to_le_bytes());
        request[16..24].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
        request
    };
    let mut cx = Context::from_waker(Waker::noop());
    let Some(gate) = try_placement(CARD) else {
        return TestResult::Fail("placement admission");
    };
    let mut first = request();
    let mut create = alloc::boxed::Box::pin(dispatch_async(
        0xc020_6440,
        first.as_mut_ptr() as usize,
        &state,
    ));
    if !create.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("a buffer was published without placement admission");
    }
    if gtt_used() != base + 3 * PAGE_SIZE {
        return TestResult::Fail("system pages were allocated under the placement gate");
    }
    // A second create is cancelled while it waits: its pages go back.
    let mut second = request();
    let mut cancelled = alloc::boxed::Box::pin(dispatch_async(
        0xc020_6440,
        second.as_mut_ptr() as usize,
        &state,
    ));
    if !cancelled.as_mut().poll(&mut cx).is_pending() || gtt_used() != base + 6 * PAGE_SIZE {
        return TestResult::Fail("second create did not wait with its pages");
    }
    drop(cancelled);
    if gtt_used() != base + 3 * PAGE_SIZE || second != request() {
        return TestResult::Fail("a cancelled create kept its pages or wrote its reply");
    }
    drop(gate);
    if narf_scheduler::block_on_spin(create) != Some(Ok(0)) {
        return TestResult::Fail("create after admission");
    }
    let handle = u32::from_le_bytes(first[..4].try_into().unwrap());
    if state.get(handle).is_none_or(|o| !o.system()) || gtt_used() != base + 3 * PAGE_SIZE {
        return TestResult::Fail("published buffer or its accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    system_pages_are_allocated_outside_placement_admission
);

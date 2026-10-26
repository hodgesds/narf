//! Per-frame central free lists. All accesses require the owning class lock.
//!
//! The permanent PFN descriptor supplies the record: no allocator recursion,
//! address tree, or per-object header is needed. A frame with every object on
//! its central chain is on `empty`; other nonempty chains are on `partial`.

use core::ptr::NonNull;

use super::{canary_check_free, class_size, FreeBlock, PAGE_SIZE_USIZE};

/// Fits in the existing 48 bytes of permanent frame-descriptor padding.
/// Zero is an untracked frame, including slabs grown before publication of
/// that descriptor array. Such frames retain the legacy bounded FIFO path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameState {
    head: Option<NonNull<FreeBlock>>,
    prev: usize,
    next: usize,
    count: usize,
    class: usize,
    list: usize,
}

const _: () = assert!(core::mem::size_of::<FrameState>() == 48);

impl FrameState {
    const fn empty() -> Self {
        Self {
            head: None,
            prev: 0,
            next: 0,
            count: 0,
            class: 0,
            list: 0,
        }
    }
}

const PARTIAL: usize = 1;
const EMPTY: usize = 2;

fn frame_of(node: NonNull<FreeBlock>) -> usize {
    node.as_ptr() as usize & !(PAGE_SIZE_USIZE - 1)
}

fn state(frame: usize) -> Option<*mut FrameState> {
    let physical = crate::PhysAddr::from_kernel_ptr(frame as *const u8);
    crate::frame::cow::slab_frame_state(physical).map(|cell| cell.get())
}

fn required_state(frame: usize) -> *mut FrameState {
    state(frame).expect("tracked slab frame has permanent metadata")
}

fn valid_node(frame: usize, node: NonNull<FreeBlock>, class: usize) -> bool {
    let address = node.as_ptr() as usize;
    address >= frame
        && address - frame < PAGE_SIZE_USIZE
        && ((address - frame) & (class_size(class) - 1)) == 0
}

#[derive(Debug)]
struct FrameList {
    head: usize,
    tail: usize,
}

impl FrameList {
    const fn new() -> Self {
        Self { head: 0, tail: 0 }
    }

    /// # Safety
    /// The class lock owns the unlinked frame and all list records.
    unsafe fn push(&mut self, frame: usize, kind: usize) {
        let record = required_state(frame);
        // SAFETY: exclusive class lock; a newly linked record is not a member
        // of either list, and no whole-record mutable borrow spans a neighbor.
        unsafe {
            assert_eq!((*record).list, 0, "slab frame already linked");
            assert_ne!(self.tail, frame, "slab frame appended twice");
            (*record).prev = self.tail;
            (*record).next = 0;
            (*record).list = kind;
            if self.tail == 0 {
                self.head = frame;
            } else {
                (*required_state(self.tail)).next = frame;
            }
            self.tail = frame;
        }
    }

    /// # Safety
    /// The class lock owns a frame that belongs to this exact list.
    unsafe fn remove(&mut self, frame: usize, kind: usize) {
        let record = required_state(frame);
        // SAFETY: list and record are protected by the same exclusive lock.
        unsafe {
            assert_eq!((*record).list, kind, "wrong slab frame list");
            let prev = (*record).prev;
            let next = (*record).next;
            if prev == 0 {
                assert_eq!(self.head, frame);
                self.head = next;
            } else {
                (*required_state(prev)).next = next;
            }
            if next == 0 {
                assert_eq!(self.tail, frame);
                self.tail = prev;
            } else {
                (*required_state(next)).prev = prev;
            }
            (*record).prev = 0;
            (*record).next = 0;
            (*record).list = 0;
        }
    }

    /// # Safety
    /// Both disjoint lists belong to this class and are exclusively owned.
    unsafe fn append(&mut self, other: &mut Self) {
        if other.head == 0 {
            return;
        }
        // SAFETY: only the two existing boundary records change linkage.
        unsafe {
            if self.tail == 0 {
                self.head = other.head;
            } else {
                (*required_state(self.tail)).next = other.head;
                (*required_state(other.head)).prev = self.tail;
            }
        }
        self.tail = other.tail;
        *other = Self::new();
    }
}

#[derive(Debug)]
pub(super) struct FrameLists {
    partial: FrameList,
    empty: FrameList,
}

impl FrameLists {
    pub const fn new() -> Self {
        Self {
            partial: FrameList::new(),
            empty: FrameList::new(),
        }
    }

    /// # Safety
    /// Fresh buddy frame, before publishing any objects, under the class lock.
    pub unsafe fn register(&mut self, frame: usize, class: usize) {
        let Some(record) = state(frame) else { return };
        // SAFETY: the allocator exclusively owns this newly allocated frame.
        unsafe {
            assert_eq!((*record).class, 0, "buddy returned a tracked slab frame");
            *record = FrameState {
                class: class + 1,
                ..FrameState::empty()
            };
        }
    }

    /// # Safety
    /// The class lock protects every listed frame and its object chain.
    pub unsafe fn front(&self) -> Option<NonNull<FreeBlock>> {
        let frame = if self.partial.head != 0 {
            self.partial.head
        } else {
            self.empty.head
        };
        if frame == 0 {
            return None;
        }
        // SAFETY: the frame is a current member of this class's list.
        unsafe { (*required_state(frame)).head }
    }

    /// Return false only for a frame without an initialized tracking record.
    /// # Safety
    /// Caller exclusively owns a valid free object and holds its class lock.
    pub unsafe fn push(&mut self, mut node: NonNull<FreeBlock>) -> bool {
        let frame = frame_of(node);
        let Some(record) = state(frame) else {
            return false;
        };
        // SAFETY: the owning class lock excludes all other record accesses.
        unsafe {
            if (*record).class == 0 {
                return false;
            }
            let class = (*record).class - 1;
            assert!(valid_node(frame, node, class), "invalid slab object offset");
            let count = (*record).count;
            let capacity = PAGE_SIZE_USIZE / class_size(class);
            assert!(count < capacity, "slab frame central count overflow");
            node.as_mut().next = (*record).head;
            (*record).head = Some(node);
            (*record).count = count + 1;
            if count + 1 == capacity {
                if count != 0 {
                    self.partial.remove(frame, PARTIAL);
                }
                self.empty.push(frame, EMPTY);
            } else if count == 0 {
                self.partial.push(frame, PARTIAL);
            }
        }
        true
    }

    /// # Safety
    /// Class lock held; all published nodes have intact free-state canaries.
    pub unsafe fn pop(&mut self) -> Option<NonNull<FreeBlock>> {
        let frame = if self.partial.head != 0 {
            self.partial.head
        } else {
            self.empty.head
        };
        if frame == 0 {
            return None;
        }
        let record = required_state(frame);
        // SAFETY: this class exclusively owns the record, chain and lists.
        unsafe {
            let mut node = (*record).head.expect("nonempty frame has head");
            let class = (*record).class - 1;
            assert!(valid_node(frame, node, class), "invalid central slab link");
            canary_check_free(node, class);
            let was_empty = (*record).list == EMPTY;
            (*record).head = node.as_ref().next;
            (*record).count -= 1;
            node.as_mut().next = None;
            if was_empty {
                self.empty.remove(frame, EMPTY);
                if (*record).count != 0 {
                    self.partial.push(frame, PARTIAL);
                }
            } else if (*record).count == 0 {
                self.partial.remove(frame, PARTIAL);
            }
            Some(node)
        }
    }

    /// Confirm an incoming canary match using only this frame's bounded chain.
    /// # Safety
    /// Class lock held; node denotes a block belonging to this size class.
    pub unsafe fn contains(&self, node: NonNull<FreeBlock>) -> bool {
        let frame = frame_of(node);
        let Some(record) = state(frame) else {
            return false;
        };
        // SAFETY: all chain reads are protected by the owning class lock.
        unsafe {
            if (*record).class == 0 {
                return false;
            }
            let class = (*record).class - 1;
            let mut current = (*record).head;
            for _ in 0..(*record).count {
                let Some(candidate) = current else { break };
                assert!(
                    valid_node(frame, candidate, class),
                    "invalid central slab link"
                );
                if candidate == node {
                    return true;
                }
                current = candidate.as_ref().next;
            }
        }
        false
    }

    /// Select empty frames in O(1), then validate only their own object chains.
    /// No more than `node_budget` links are examined under one class lock.
    /// # Safety
    /// Class lock held; output frames must be returned to buddy exactly once,
    /// after unlocking. `class` is the owning size class.
    pub unsafe fn detach(
        &mut self,
        class: usize,
        frames: &mut [usize],
        node_budget: usize,
    ) -> (usize, usize) {
        let capacity = PAGE_SIZE_USIZE / class_size(class);
        let mut detached = 0;
        let mut examined = 0;
        while self.empty.head != 0 && detached < frames.len() && capacity <= node_budget - examined
        {
            let frame = self.empty.head;
            let record = required_state(frame);
            // SAFETY: this complete frame and all its nodes belong to the class.
            unsafe {
                assert_eq!((*record).class, class + 1);
                assert_eq!((*record).count, capacity);
                let mut seen = [0u64; 4];
                let mut current = (*record).head;
                for _ in 0..capacity {
                    let node = current.expect("short full-frame free chain");
                    assert!(valid_node(frame, node, class), "cross-frame free link");
                    let slot = (node.as_ptr() as usize - frame) / class_size(class);
                    let bit = 1u64 << (slot % 64);
                    assert_eq!(seen[slot / 64] & bit, 0, "duplicate central slab object");
                    seen[slot / 64] |= bit;
                    canary_check_free(node, class);
                    current = node.as_ref().next;
                }
                assert!(current.is_none(), "long full-frame free chain");
                self.empty.remove(frame, EMPTY);
                *record = FrameState::empty();
            }
            frames[detached] = frame;
            detached += 1;
            examined += capacity;
        }
        (detached, examined)
    }

    /// # Safety
    /// Quiescent same-class lists with disjoint frame memberships.
    pub unsafe fn append(&mut self, other: &mut Self) {
        // SAFETY: caller owns both complete list states exclusively.
        unsafe {
            self.partial.append(&mut other.partial);
            self.empty.append(&mut other.empty);
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::frame::{alloc_frame, free_frame, PhysFrame};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Raw test frames never escape to magazines or production central lists.
    /// Drop clears their private records before returning pages outside locks.
    struct Pages<const N: usize> {
        frames: [Option<PhysFrame>; N],
        class: usize,
    }

    impl<const N: usize> Pages<N> {
        fn new(class: usize) -> Option<Self> {
            let mut pages = Self {
                frames: [None; N],
                class,
            };
            for slot in &mut pages.frames {
                *slot = Some(alloc_frame().ok()?);
            }
            if pages
                .frames
                .iter()
                .flatten()
                .any(|f| state(f.start_address().kernel_mut_ptr::<u8>() as usize).is_none())
            {
                return None;
            }
            Some(pages)
        }

        fn base(&self, index: usize) -> usize {
            self.frames[index]
                .expect("allocated test frame")
                .start_address()
                .kernel_mut_ptr::<u8>() as usize
        }
    }

    impl<const N: usize> Drop for Pages<N> {
        fn drop(&mut self) {
            {
                let _guard = super::super::CLASSES[self.class].head.lock();
                for frame in self.frames.iter().flatten() {
                    if let Some(record) =
                        state(frame.start_address().kernel_mut_ptr::<u8>() as usize)
                    {
                        // SAFETY: test exclusively owns these raw frames and
                        // their lists have not escaped this lexical scenario.
                        unsafe { *record = FrameState::empty() };
                    }
                }
            }
            for frame in self.frames.iter_mut().filter_map(Option::take) {
                free_frame(frame);
            }
        }
    }

    /// # Safety
    /// Exclusively owned raw page; slot is within its chosen class layout.
    unsafe fn fresh_node(base: usize, slot: usize, class: usize) -> NonNull<FreeBlock> {
        let node = NonNull::new((base + slot * class_size(class)) as *mut FreeBlock).unwrap();
        // SAFETY: this raw frame is not published to the real allocator.
        unsafe { super::super::canary_set_fresh(node) };
        node
    }

    fn smoke_slab_empty_frame_selection_skips_partial_pool() -> TestResult {
        const PARTIAL_FRAMES: usize = 40;
        let class = 2; // 64-byte objects; 40 * 63 unrelated central objects.
        let Some(pages) = Pages::<41>::new(class) else {
            return TestResult::Fail("test frame allocation/metadata");
        };
        let _guard = super::super::CLASSES[class].head.lock();
        let capacity = PAGE_SIZE_USIZE / class_size(class);
        let complete = pages.base(PARTIAL_FRAMES);
        let mut output = [0usize; 1];
        {
            // Negative control: the prior FIFO search cannot complete its first
            // partial candidate within the same 2,048-node budget.
            let mut legacy = super::super::CentralList::new();
            for i in 0..=PARTIAL_FRAMES {
                let count = if i == PARTIAL_FRAMES {
                    capacity
                } else {
                    capacity - 1
                };
                for slot in 0..count {
                    // SAFETY: owned test pages under their class lock.
                    unsafe { legacy.push_back(fresh_node(pages.base(i), slot, class)) };
                }
            }
            // SAFETY: all private chains are valid, class lock is held.
            if unsafe { legacy.detach_pages(class, &mut output, 2048) } != 0 {
                return TestResult::Fail("legacy negative control unexpectedly finished");
            }
        }
        let mut tracked = super::super::CentralList::new();
        for i in 0..=PARTIAL_FRAMES {
            // SAFETY: raw pages are exclusively owned; old private FIFO has
            // been discarded, so it retains no references to these objects.
            unsafe { tracked.frames.register(pages.base(i), class) };
            let count = if i == PARTIAL_FRAMES {
                capacity
            } else {
                capacity - 1
            };
            for slot in 0..count {
                // SAFETY: fresh class nodes, never published elsewhere.
                unsafe { tracked.push_back(fresh_node(pages.base(i), slot, class)) };
            }
        }
        // SAFETY: class lock owns this private tracked set.
        if unsafe { tracked.detach_pages(class, &mut output, 2048) } != 1 || output[0] != complete {
            return TestResult::Fail("empty-frame selection searched unrelated partial frames");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_frames",
        smoke_slab_empty_frame_selection_skips_partial_pool
    );

    fn smoke_slab_frame_budget_and_cached_object_exclusion() -> TestResult {
        let class = 2;
        let Some(pages) = Pages::<1>::new(class) else {
            return TestResult::Fail("test frame allocation/metadata");
        };
        let _guard = super::super::CLASSES[class].head.lock();
        let mut lists = FrameLists::new();
        let capacity = PAGE_SIZE_USIZE / class_size(class);
        let mut output = [0usize; 1];
        // SAFETY: private raw frame under its class lock.
        unsafe {
            lists.register(pages.base(0), class);
            for slot in 0..capacity - 1 {
                lists.push(fresh_node(pages.base(0), slot, class));
            }
            if lists.detach(class, &mut output, 2048) != (0, 0) {
                return TestResult::Fail("reclaimed a frame with a cached/live object");
            }
            lists.push(fresh_node(pages.base(0), capacity - 1, class));
            if lists.detach(class, &mut output, capacity - 1) != (0, 0) {
                return TestResult::Fail("frame validation exceeded node budget");
            }
            if lists.detach(class, &mut output, capacity) != (1, capacity) {
                return TestResult::Fail("complete frame did not consume exact bounded work");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_frames",
        smoke_slab_frame_budget_and_cached_object_exclusion
    );

    fn smoke_slab_partial_frame_allocations_preserve_empty_frames() -> TestResult {
        let class = 6;
        let Some(pages) = Pages::<2>::new(class) else {
            return TestResult::Fail("test frame allocation/metadata");
        };
        let _guard = super::super::CLASSES[class].head.lock();
        let mut lists = FrameLists::new();
        let capacity = PAGE_SIZE_USIZE / class_size(class);
        // SAFETY: the class lock owns both private test frames.
        unsafe {
            for i in 0..2 {
                lists.register(pages.base(i), class);
                for slot in 0..if i == 0 { capacity - 1 } else { capacity } {
                    lists.push(fresh_node(pages.base(i), slot, class));
                }
            }
            let node = lists.pop().expect("partial frame nonempty");
            if frame_of(node) != pages.base(0) || lists.contains(node) {
                return TestResult::Fail("allocation consumed an empty frame or retained its node");
            }
            lists.push(node);
            if !lists.contains(node) {
                return TestResult::Fail("returned object is absent");
            }
            let mut output = [0usize; 1];
            if lists.detach(class, &mut output, 2048).0 != 1 || output[0] != pages.base(1) {
                return TestResult::Fail("partial allocations destroyed empty-frame eligibility");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_frames",
        smoke_slab_partial_frame_allocations_preserve_empty_frames
    );

    fn smoke_slab_detached_metadata_rebinds_to_another_class() -> TestResult {
        let Some(mut pages) = Pages::<1>::new(6) else {
            return TestResult::Fail("test frame allocation/metadata");
        };
        let before = crate::frame::cow::count(pages.frames[0].unwrap().start_address());
        for class in [6, 7, 8] {
            pages.class = class;
            let _guard = super::super::CLASSES[class].head.lock();
            let mut lists = FrameLists::new();
            // SAFETY: the preceding stage retired all private central objects;
            // this raw page remains exclusively owned throughout reuse.
            unsafe {
                lists.register(pages.base(0), class);
                for slot in 0..PAGE_SIZE_USIZE / class_size(class) {
                    lists.push(fresh_node(pages.base(0), slot, class));
                }
                let mut output = [0usize; 1];
                if lists.detach(class, &mut output, 2048).0 != 1 {
                    return TestResult::Fail("class reuse did not detach the complete page");
                }
                if (*required_state(pages.base(0))).class != 0 {
                    return TestResult::Fail("detached frame retained its old slab identity");
                }
            }
        }
        if crate::frame::cow::count(pages.frames[0].unwrap().start_address()) != before {
            return TestResult::Fail("slab bookkeeping changed COW ownership");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_frames",
        smoke_slab_detached_metadata_rebinds_to_another_class
    );
}

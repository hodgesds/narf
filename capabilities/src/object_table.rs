//! Stable indexed object metadata. Published directories/leaves are never
//! moved or reclaimed. Readers perform three pointer loads and one epoch
//! load, without a lock.
//!
//! An index is reused once its object is [`release`]d (the EROS design the
//! 128-bit slot exists for: generation + index, AGENTS.md invariant 6). The
//! epoch's parity says what an entry is: **odd = live**, **even = released**
//! (zero = never allocated or exhausted). Registration publishes an odd
//! epoch, revocation (`bump_epoch`) adds two, release adds one and puts the
//! index on a lock-free free list, re-registration rewrites the kind and
//! adds one again. `check_live` is an equality test against a live epoch, so
//! every capability minted before a release keeps failing it after the index
//! is reused, whatever the new object is; readers never read the kind of an
//! entry that is not live. An epoch that would wrap retires the entry for
//! good (epoch 0), so a generation can never recur.

use crate::{CapError, CapKind};
use alloc::alloc::{alloc, dealloc};
use core::{
    alloc::Layout,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

struct Directory {
    children: [AtomicPtr<()>; 256],
}
struct Entry {
    /// `CapKind as u32`; written only while the entry is not live
    /// (registration precedes the release-store of the odd epoch).
    kind: AtomicU32,
    epoch: AtomicU32,
    /// Next index on the free list while this one is released; `NONE`
    /// otherwise.
    next_free: AtomicU32,
}
struct Leaf {
    entries: [Entry; 256],
}

/// Free-list terminator.
const NONE: u32 = u32::MAX;

/// Head of the free list: the index in the low word, an ABA tag in the
/// high word (entries are never deallocated, so a stale `next_free` read is
/// benign and the tag makes a stale head lose its CAS).
static FREE_HEAD: AtomicU64 = AtomicU64::new(NONE as u64);

fn pack(index: u32, tag: u32) -> u64 {
    (u64::from(tag) << 32) | u64::from(index)
}

fn push_free(index: u32, entry: &Entry) {
    let mut head = FREE_HEAD.load(Ordering::Acquire);
    loop {
        entry.next_free.store(head as u32, Ordering::Relaxed);
        let new = pack(index, (head >> 32) as u32 + 1);
        match FREE_HEAD.compare_exchange_weak(head, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(seen) => head = seen,
        }
    }
}

fn pop_free() -> Option<(u32, &'static Entry)> {
    let mut head = FREE_HEAD.load(Ordering::Acquire);
    loop {
        let index = head as u32;
        if index == NONE {
            return None;
        }
        let entry = entry(index, false).ok()??;
        let next = entry.next_free.load(Ordering::Acquire);
        let new = pack(next, (head >> 32) as u32 + 1);
        match FREE_HEAD.compare_exchange_weak(head, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                entry.next_free.store(NONE, Ordering::Relaxed);
                return Some((index, entry));
            }
            Err(seen) => head = seen,
        }
    }
}

fn is_live(epoch: u32) -> bool {
    epoch & 1 == 1
}

static ROOT: [AtomicPtr<()>; 256] = [const { AtomicPtr::new(ptr::null_mut()) }; 256];
static NEXT: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

fn allocate(leaf: bool) -> Result<*mut (), CapError> {
    let layout = if leaf {
        Layout::new::<Leaf>()
    } else {
        Layout::new::<Directory>()
    };
    // SAFETY: valid nonzero layout. The null case publishes nothing.
    let allocation = unsafe { alloc(layout) };
    if allocation.is_null() {
        return Err(CapError::CapTableFull);
    }
    // Initialize in place, avoiding multi-kilobyte temporaries on task stacks.
    // SAFETY: this allocation is private and has the selected type's layout.
    unsafe {
        if leaf {
            let entries = ptr::addr_of_mut!((*(allocation.cast::<Leaf>())).entries).cast::<Entry>();
            for index in 0..256 {
                entries.add(index).write(Entry {
                    kind: AtomicU32::new(0),
                    epoch: AtomicU32::new(0),
                    next_free: AtomicU32::new(NONE),
                });
            }
        } else {
            let children = ptr::addr_of_mut!((*(allocation.cast::<Directory>())).children)
                .cast::<AtomicPtr<()>>();
            for index in 0..256 {
                children.add(index).write(AtomicPtr::new(ptr::null_mut()));
            }
        }
    }
    Ok(allocation.cast())
}

fn entry_in(
    root: &[AtomicPtr<()>; 256],
    index: u32,
    create: bool,
) -> Result<Option<&'static Entry>, CapError> {
    let mut directory = root;
    for shift in [24, 16, 8] {
        let slot = &directory[((index >> shift) & 255) as usize];
        let mut address = slot.load(Ordering::Acquire);
        if address.is_null() && create {
            let fresh = allocate(shift == 8)?;
            match slot.compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => address = fresh,
                Err(published) => {
                    // SAFETY: our unpublished allocation contains no owners or
                    // child pointers. Its winning peer owns different storage.
                    unsafe {
                        dealloc(
                            fresh.cast(),
                            if shift == 8 {
                                Layout::new::<Leaf>()
                            } else {
                                Layout::new::<Directory>()
                            },
                        );
                    }
                    address = published;
                }
            }
        }
        if address.is_null() {
            return Ok(None);
        }
        // SAFETY: the acquire load observes a fully initialized allocation of
        // the type selected by this fixed tree level. Published storage is
        // permanent, so the reference needs neither a refcount nor RCU pin.
        unsafe {
            if shift == 8 {
                return Ok(Some(
                    &(*address.cast::<Leaf>()).entries[(index & 255) as usize],
                ));
            }
            directory = &(*address.cast::<Directory>()).children;
        }
    }
    unreachable!()
}

fn entry(index: u32, create: bool) -> Result<Option<&'static Entry>, CapError> {
    entry_in(&ROOT, index, create)
}

/// Register an object of `kind`: a released index when one is free, else
/// the next never-used one. Returns `(index, generation)`; the generation
/// is odd and greater than every one the index carried before.
///
/// A failed allocation consumes a fresh index, leaving a permanently invalid
/// hole. No creator can obtain a capability until entry publication succeeds.
pub fn try_register(kind: CapKind) -> Result<(u32, u32), CapError> {
    if let Some((index, entry)) = pop_free() {
        // Sole owner between pop and publication: nothing else reaches a
        // released entry's kind (readers stop at the even epoch).
        entry.kind.store(kind as u32, Ordering::Relaxed);
        let released = entry.epoch.load(Ordering::Relaxed);
        debug_assert!(released != 0 && !is_live(released));
        let generation = released.wrapping_add(1);
        entry.epoch.store(generation, Ordering::Release);
        COUNT.fetch_add(1, Ordering::Relaxed);
        return Ok((index, generation));
    }
    let index = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            (next <= u64::from(u32::MAX)).then_some(next + 1)
        })
        .map_err(|_| CapError::CapTableFull)? as u32;
    let entry = entry(index, true)?.ok_or(CapError::CapTableFull)?;
    // NEXT gives this creator exclusive write ownership of the slot; the
    // release store of the odd epoch publishes the kind.
    entry.kind.store(kind as u32, Ordering::Relaxed);
    entry.epoch.store(1, Ordering::Release);
    COUNT.fetch_add(1, Ordering::Relaxed);
    Ok((index, 1))
}

/// Legacy infallible mint retains its existing allocation-failure policy.
pub fn register(kind: CapKind) -> (u32, u32) {
    try_register(kind).expect("capability object metadata exhausted")
}

/// The live epoch and kind of `index`, or `None` for an index that is not
/// live (never allocated, released, exhausted). The kind is read between
/// two loads of the epoch so it belongs to the incarnation reported.
pub fn epoch_and_kind(index: u32) -> Option<(u32, CapKind)> {
    let entry = entry(index, false).ok()??;
    loop {
        let epoch = entry.epoch.load(Ordering::Acquire);
        if !is_live(epoch) {
            return None;
        }
        let kind = entry.kind.load(Ordering::Relaxed);
        if entry.epoch.load(Ordering::Acquire) != epoch {
            continue;
        }
        // SAFETY: `kind` was stored from a `CapKind as u32` by the
        // registration that published `epoch` (acquire pairs with its
        // release store, and the epoch did not move in between), and
        // `CapKind` is `repr(u32)`, so the value is one of its discriminants.
        return Some((epoch, unsafe { core::mem::transmute::<u32, CapKind>(kind) }));
    }
}

/// The live epoch of `index`, or `None` when it is not live.
pub fn current_epoch(index: u32) -> Option<u32> {
    let entry = entry(index, false).ok()??;
    let epoch = entry.epoch.load(Ordering::Acquire);
    is_live(epoch).then_some(epoch)
}

/// Revoke every capability of a live object without releasing its index:
/// the epoch moves by two (it stays odd / live). Returns the new epoch; `0`
/// when the epoch space is exhausted and the entry retired for good; `None`
/// for an index that is not live.
pub fn bump_epoch(index: u32) -> Option<u32> {
    let entry = entry(index, false).ok()??;
    entry
        .epoch
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            is_live(epoch).then(|| epoch.checked_add(2).unwrap_or(0))
        })
        .ok()
        .map(|previous| previous.checked_add(2).unwrap_or(0))
}

/// Release a live object's index for reuse: every capability of it fails
/// `check_live` from now on (the epoch moves to the next, even, value),
/// and the next registration may hand the index out again under a greater
/// generation. Returns the released epoch; `0` when the epoch space is
/// exhausted (the entry retires instead of joining the free list); `None`
/// for an index that is not live (a second release is refused).
pub fn release(index: u32) -> Option<u32> {
    let entry = entry(index, false).ok()??;
    let released = entry
        .epoch
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            // `+ 1` is even; keep headroom so the re-registration's `+ 1`
            // cannot wrap either.
            is_live(epoch).then(|| if epoch >= u32::MAX - 2 { 0 } else { epoch + 1 })
        })
        .ok()
        .map(|previous| {
            if previous >= u32::MAX - 2 {
                0
            } else {
                previous + 1
            }
        })?;
    COUNT.fetch_sub(1, Ordering::Relaxed);
    if released != 0 {
        push_free(index, entry);
    }
    Some(released)
}

pub fn kind_at(index: u32) -> Option<CapKind> {
    epoch_and_kind(index).map(|(_, kind)| kind)
}

/// Live objects.
pub fn len() -> usize {
    COUNT.load(Ordering::Relaxed)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_cap_stable_index_sparse_boundaries() -> TestResult {
        let root = alloc::boxed::Box::new([const { AtomicPtr::new(ptr::null_mut()) }; 256]);
        for index in [0, 255, 256, 65535, 65536, 0x0100_0000, u32::MAX] {
            if entry_in(&root, index, false)
                .unwrap()
                .is_some_and(|entry| entry.epoch.load(Ordering::Acquire) != 0)
            {
                return TestResult::Fail("unpublished sparse entry is live");
            }
            let entry = entry_in(&root, index, true).unwrap().unwrap();
            entry
                .kind
                .store(CapKind::Endpoint as u32, Ordering::Relaxed);
            entry.epoch.store(1, Ordering::Release);
            let again = entry_in(&root, index, false).unwrap().unwrap();
            if !ptr::eq(entry, again) || again.epoch.load(Ordering::Acquire) != 1 {
                return TestResult::Fail("indexed entry moved or aliased");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("capabilities", smoke_cap_stable_index_sparse_boundaries);

    fn smoke_cap_object_epoch_wrap_stays_revoked() -> TestResult {
        let (index, _) = register(CapKind::Endpoint);
        let entry = entry(index, false).unwrap().unwrap();
        entry.epoch.store(u32::MAX, Ordering::Release);
        if bump_epoch(index) != Some(0) {
            return TestResult::Fail("epoch exhaustion did not retire entry");
        }
        if current_epoch(index).is_some()
            || epoch_and_kind(index).is_some()
            || bump_epoch(index).is_some()
        {
            return TestResult::Fail("exhausted entry revived");
        }
        TestResult::Pass
    }
    kernel_test_in!("capabilities", smoke_cap_object_epoch_wrap_stays_revoked);

    /// A released index is handed out again under a greater generation; the
    /// capability minted before the release keeps failing, a second release
    /// is refused, and the kind follows the new object.
    fn smoke_cap_object_index_reused_after_release() -> TestResult {
        let (index, generation) = register(CapKind::Endpoint);
        let released = release(index);
        if released != Some(generation + 1) || current_epoch(index).is_some() {
            return TestResult::Fail("a released entry still reads live");
        }
        if release(index).is_some() || bump_epoch(index).is_some() {
            return TestResult::Fail("a released entry was released or revoked again");
        }
        let (again, generation_2) = register(CapKind::Ring);
        if again != index {
            // Another CPU may have taken the slot first; still, nothing of
            // the old generation may be live.
            let _ = release(again);
            if current_epoch(index) == Some(generation) {
                return TestResult::Fail("the old generation came back");
            }
            return TestResult::Pass;
        }
        if generation_2 != generation + 2 || current_epoch(index) != Some(generation_2) {
            return TestResult::Fail("a reused index did not advance its generation");
        }
        if epoch_and_kind(index) != Some((generation_2, CapKind::Ring)) {
            return TestResult::Fail("a reused index kept the old kind");
        }
        if current_epoch(index) == Some(generation) {
            return TestResult::Fail("a stale generation passes on a reused index");
        }
        let _ = release(index);
        TestResult::Pass
    }
    kernel_test_in!("capabilities", smoke_cap_object_index_reused_after_release);

    /// Many register / release cycles stay within a handful of indices.
    fn smoke_cap_object_release_bounds_the_table() -> TestResult {
        let (first, _) = register(CapKind::Endpoint);
        let _ = release(first);
        let next_before = NEXT.load(Ordering::Relaxed);
        let count_before = len();
        for _ in 0..1_000_000u32 {
            let (index, _) = register(CapKind::Endpoint);
            if release(index).is_none() {
                return TestResult::Fail("release refused a live index");
            }
        }
        if NEXT.load(Ordering::Relaxed) != next_before || len() != count_before {
            return TestResult::Fail("register / release cycles consumed new indices");
        }
        TestResult::Pass
    }
    kernel_test_in!("capabilities", smoke_cap_object_release_bounds_the_table);
}

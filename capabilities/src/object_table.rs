//! Stable indexed object metadata. Published directories/leaves are never
//! moved or reclaimed; the existing object-index policy never reuses slots.
//! Readers perform three pointer loads and one epoch load, without a lock.

use crate::{CapError, CapKind};
use alloc::alloc::{alloc, dealloc};
use core::{
    alloc::Layout,
    cell::UnsafeCell,
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

struct Directory {
    children: [AtomicPtr<()>; 256],
}
struct Entry {
    kind: UnsafeCell<MaybeUninit<CapKind>>,
    epoch: AtomicU32,
}
struct Leaf {
    entries: [Entry; 256],
}

// SAFETY: kind is written exactly once, before the release publication of
// epoch=1. Every reader acquire-loads a nonzero epoch before reading kind.
// Epoch zero is never republished as live, and object indices are never reused.
unsafe impl Sync for Entry {}

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
                    kind: UnsafeCell::new(MaybeUninit::uninit()),
                    epoch: AtomicU32::new(0),
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

/// A failed allocation consumes an index, leaving a permanently invalid hole.
/// No creator can obtain a capability until entry publication succeeds.
pub fn try_register(kind: CapKind) -> Result<(u32, u32), CapError> {
    let index = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            (next <= u64::from(u32::MAX)).then_some(next + 1)
        })
        .map_err(|_| CapError::CapTableFull)? as u32;
    let entry = entry(index, true)?.ok_or(CapError::CapTableFull)?;
    // SAFETY: NEXT gives this creator exclusive write ownership of the slot;
    // kind stays immutable after the release epoch publication below.
    unsafe {
        (*entry.kind.get()).write(kind);
    }
    entry.epoch.store(1, Ordering::Release);
    COUNT.fetch_add(1, Ordering::Relaxed);
    Ok((index, 1))
}

/// Legacy infallible mint retains its existing allocation-failure policy.
pub fn register(kind: CapKind) -> (u32, u32) {
    try_register(kind).expect("capability object metadata exhausted")
}

pub fn epoch_and_kind(index: u32) -> Option<(u32, CapKind)> {
    let entry = entry(index, false).ok()??;
    let epoch = entry.epoch.load(Ordering::Acquire);
    if epoch == 0 {
        return None;
    }
    // SAFETY: nonzero acquire epoch publishes kind, which is never changed.
    Some((epoch, unsafe { (*entry.kind.get()).assume_init() }))
}

pub fn current_epoch(index: u32) -> Option<u32> {
    let entry = entry(index, false).ok()??;
    let epoch = entry.epoch.load(Ordering::Acquire);
    (epoch != 0).then_some(epoch)
}

pub fn bump_epoch(index: u32) -> Option<u32> {
    let entry = entry(index, false).ok()??;
    entry
        .epoch
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            (epoch != 0).then_some(epoch.wrapping_add(1))
        })
        .ok()
        .map(|previous| previous.wrapping_add(1))
}

pub fn kind_at(index: u32) -> Option<CapKind> {
    epoch_and_kind(index).map(|(_, kind)| kind)
}
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
            // SAFETY: this test owns a private root and initializes each
            // selected slot exactly once, as registration does.
            unsafe {
                (*entry.kind.get()).write(CapKind::Endpoint);
            }
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
}

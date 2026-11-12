//! Where each live user address space was created.
//!
//! A soak can end with thousands of user page-table roots that no scheduled
//! task owns (`/proc/narf/pgtables`: `user_roots_live` far above
//! `sched_address_spaces`). Each such root keeps its page tables and mapped
//! pages. This table records, per live root, the source location of the
//! call that built its address space (`AddressSpace::new_for_user`'s or
//! `clone_for_fork`'s caller), so the orphans can be grouped by what made
//! them — fork, exec, spawn — and the owner that never let go found.
//!
//! Lock-free open addressing over a fixed `.bss` table: allocation-free, so
//! it is safe on every path that creates or tears down a root. A full table
//! drops the record (counted).

use core::panic::Location;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

const SLOTS: usize = 1 << 16;
/// Slot key states besides a root's physical address.
const EMPTY: u64 = 0;
const TOMBSTONE: u64 = 1;

static ROOTS: [AtomicU64; SLOTS] = [const { AtomicU64::new(EMPTY) }; SLOTS];
static ORIGINS: [AtomicPtr<Location<'static>>; SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS];
static DROPPED: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn home(root: u64) -> usize {
    ((root >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 48) as usize & (SLOTS - 1)
}

/// Record that the user root `root` was built at `origin`.
pub fn record(root: u64, origin: &'static Location<'static>) {
    let mut i = home(root);
    for _ in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if (key == EMPTY || key == TOMBSTONE)
            && ROOTS[i]
                .compare_exchange(key, root, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            ORIGINS[i].store(origin as *const _ as *mut _, Ordering::Release);
            return;
        }
        i = (i + 1) & (SLOTS - 1);
    }
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Forget `root` (its tree is being freed).
pub fn forget(root: u64) {
    let mut i = home(root);
    for _ in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if key == EMPTY {
            return;
        }
        if key == root {
            ORIGINS[i].store(core::ptr::null_mut(), Ordering::Release);
            ROOTS[i].store(TOMBSTONE, Ordering::Release);
            return;
        }
        i = (i + 1) & (SLOTS - 1);
    }
}

/// Visit every recorded live root with its origin (racy snapshot).
pub fn for_each(mut visit: impl FnMut(u64, Option<&'static Location<'static>>)) {
    for i in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if key == EMPTY || key == TOMBSTONE {
            continue;
        }
        let origin = ORIGINS[i].load(Ordering::Acquire);
        // SAFETY: only `&'static Location` pointers are stored.
        visit(key, unsafe { origin.as_ref() });
    }
}

/// Records dropped because the table was full.
pub fn dropped() -> usize {
    DROPPED.load(Ordering::Relaxed)
}

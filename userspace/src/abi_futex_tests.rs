//! Linux syscall ABI conformance — futex keying and wake filtering.
//!
//! `kernel/futex/core.c::get_futex_key` decides WHICH waiters a wake can
//! reach, and `kernel/futex/waitwake.c::futex_wake` decides which of those
//! it may take. These cases drive the real `futex(2)` / `futex_wake(2)`
//! syscalls against waiters queued through the same key funnel a parked
//! `FUTEX_WAIT` uses (`__test_futex_register_current` — the harness has no
//! yield hook, so a real wait returns synchronously without queueing).
use crate::abi_test_support::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};
use narf_memory::AddressSpace;

const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const MATCH_ANY: u32 = 0xffff_ffff;
const FUTEX2_SIZE_U32: u64 = 0x02;
const FUTEX2_PRIVATE: u64 = 128;

const PROT_RW: u64 = 0x3;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;

fn counting_waker(counter: Arc<AtomicU32>) -> Waker {
    unsafe fn clone_raw(d: *const ()) -> RawWaker {
        // SAFETY: `d` came from Arc::into_raw below; balanced reconstruction.
        let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
        let cloned = arc.clone();
        let _ = Arc::into_raw(arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTAB)
    }
    unsafe fn wake_raw(d: *const ()) {
        // SAFETY: consumes the strong reference owned by this waker.
        let arc = unsafe { Arc::<AtomicU32>::from_raw(d as *const AtomicU32) };
        arc.fetch_add(1, Ordering::AcqRel);
    }
    unsafe fn wake_ref_raw(d: *const ()) {
        // SAFETY: the waker retains its strong reference across this call.
        unsafe { (*(d as *const AtomicU32)).fetch_add(1, Ordering::AcqRel) };
    }
    unsafe fn drop_raw(d: *const ()) {
        // SAFETY: releases the strong reference owned by this waker.
        unsafe { drop(Arc::<AtomicU32>::from_raw(d as *const AtomicU32)) };
    }
    static VTAB: RawWakerVTable = RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
    // SAFETY: the vtable matches the Arc<AtomicU32> representation.
    unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTAB)) }
}

// ── A switchable "current" address space ─────────────────────────────

static CUR_AS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn cur_as_lookup() -> Option<Arc<AddressSpace>> {
    CUR_AS.lock().clone()
}

fn new_as() -> Result<Arc<AddressSpace>, &'static str> {
    // SAFETY: kernel tests run with paging live; the new root is inactive
    // and only its region table is consulted here.
    unsafe { AddressSpace::new_for_user() }
        .map(Arc::new)
        .map_err(|_| "AddressSpace::new_for_user failed")
}

fn switch_to(space: &Arc<AddressSpace>) {
    *CUR_AS.lock() = Some(Arc::clone(space));
    crate::handlers::install_address_space_lookup(cur_as_lookup);
}

fn release_as() {
    *CUR_AS.lock() = None;
}

fn mmap(addr: u64, len: u64, flags: u64, fd: u64) -> Result<u64, &'static str> {
    let r = call(
        Syscall::Mmap.raw(),
        SyscallArgs {
            arg0: addr,
            arg1: len,
            arg2: PROT_RW,
            arg3: flags,
            arg4: fd,
            arg5: 0,
        },
    );
    match r {
        Some(v) if v > 0 => Ok(v as u64),
        _ => Err("mmap failed"),
    }
}

fn futex(uaddr: u64, op: u64, val: u64, val3: u64) -> Option<i64> {
    call(
        Syscall::Futex.raw(),
        SyscallArgs {
            arg0: uaddr,
            arg1: op,
            arg2: val,
            arg3: 0,
            arg4: 0,
            arg5: val3,
        },
    )
}

fn queue(private: bool, uaddr: u64, bitset: u32, tid: u64) -> Result<Arc<AtomicU32>, &'static str> {
    let hits = Arc::new(AtomicU32::new(0));
    crate::handlers::__test_futex_register_current(
        private,
        uaddr,
        bitset,
        tid,
        counting_waker(hits.clone()),
    )
    .map_err(|_| "queueing a futex waiter failed")?;
    Ok(hits)
}

// ════════════════════════════════════════════════════════════════════
// Bug: non-private futexes were keyed globally by virtual address.
// ════════════════════════════════════════════════════════════════════

/// A non-`FUTEX_PRIVATE` futex in a PRIVATE mapping is keyed by
/// `(mm, address)` (`get_futex_key`: `folio_test_anon` →
/// `key->private.mm = mm`). Two unrelated processes that both use the same
/// virtual address must not share a wait queue: a `FUTEX_WAKE(1)` from
/// one used to wake — and be counted against — the other's waiter.
fn smoke_abi_futex_shared_op_private_mapping_isolated_per_mm() -> TestResult {
    with_setup(|| {
        const VA: u64 = 0x0000_0100_5f10_0000;
        const TID: u64 = 0x7e_0001;
        let a = new_as()?;
        let b = new_as()?;
        let body = || -> Result<(), &'static str> {
            switch_to(&a);
            mmap(VA, 4096, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, u64::MAX)?;
            let hits = queue(false, VA, MATCH_ANY, TID)?;
            switch_to(&b);
            mmap(VA, 4096, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, u64::MAX)?;
            let cross = futex(VA, FUTEX_WAKE, 1, 0);
            if cross != Some(0) || hits.load(Ordering::Acquire) != 0 {
                switch_to(&a);
                crate::handlers::__test_futex_drop_current(false, VA, TID);
                return Err("FUTEX_WAKE from an unrelated mm woke a same-VA waiter");
            }
            switch_to(&a);
            if futex(VA, FUTEX_WAKE, 1, 0) != Some(1) || hits.load(Ordering::Acquire) != 1 {
                crate::handlers::__test_futex_drop_current(false, VA, TID);
                return Err("FUTEX_WAKE in the waiter's own mm did not wake it");
            }
            Ok(())
        };
        let r = body();
        release_as();
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_shared_op_private_mapping_isolated_per_mm
);

/// `FUTEX_PRIVATE_FLAG` keeps its meaning: `(mm, address)` with no VMA
/// walk, and a different key from the non-private op on the same word
/// (Linux adds `FUT_OFF_MMSHARED` to the shared-op key of an anonymous
/// page, so a private wake never takes a shared waiter and vice versa).
fn smoke_abi_futex_private_op_unchanged_and_distinct_from_shared_op() -> TestResult {
    with_setup(|| {
        const VA: u64 = 0x0000_0100_5f14_0000;
        const TID_PRIV: u64 = 0x7e_0011;
        const TID_SHARED: u64 = 0x7e_0012;
        let a = new_as()?;
        let b = new_as()?;
        let body = || -> Result<(), &'static str> {
            switch_to(&a);
            mmap(VA, 4096, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, u64::MAX)?;
            let p = queue(true, VA, MATCH_ANY, TID_PRIV)?;
            let s = queue(false, VA, MATCH_ANY, TID_SHARED)?;
            switch_to(&b);
            if futex(VA, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0) != Some(0) {
                return Err("private FUTEX_WAKE crossed into another mm");
            }
            switch_to(&a);
            let woke = futex(VA, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 2, 0);
            if woke != Some(1) || p.load(Ordering::Acquire) != 1 || s.load(Ordering::Acquire) != 0 {
                return Err("private FUTEX_WAKE must take exactly the private waiter");
            }
            if futex(VA, FUTEX_WAKE, 2, 0) != Some(1) || s.load(Ordering::Acquire) != 1 {
                return Err("shared FUTEX_WAKE must take the shared-op waiter");
            }
            Ok(())
        };
        let r = body();
        crate::handlers::__test_futex_drop_current(true, VA, TID_PRIV);
        crate::handlers::__test_futex_drop_current(false, VA, TID_SHARED);
        release_as();
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_private_op_unchanged_and_distinct_from_shared_op
);

/// A memfd mapped `MAP_SHARED` at two DIFFERENT virtual addresses — in one
/// process and in a second one — is one futex object: `get_futex_key`
/// keys a file page by `(inode, pgoff)`, so `FUTEX_WAKE` through any
/// mapping reaches a waiter queued through any other. This is the
/// `PTHREAD_PROCESS_SHARED` / `sem_t` contract (Firefox's
/// CrossProcessSemaphore). A different word offset is a different futex.
fn smoke_abi_futex_shared_memfd_keyed_by_object_not_va() -> TestResult {
    with_setup(|| {
        const TID: u64 = 0x7e_0021;
        let a = new_as()?;
        let b = new_as()?;
        let body = || -> Result<(), &'static str> {
            switch_to(&a);
            let name = b"futexkey\0";
            let fd = match call(Syscall::MemfdCreate.raw(), a1(name.as_ptr() as u64, 0)) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("memfd_create failed"),
            };
            if call(Syscall::Ftruncate.raw(), a1(fd, 8192)) != Some(0) {
                return Err("ftruncate(memfd) failed");
            }
            let va1 = mmap(0, 8192, MAP_SHARED, fd)?;
            let va2 = mmap(0, 8192, MAP_SHARED, fd)?;
            if va1 == va2 {
                return Err("two mmaps returned the same address");
            }
            let hits = queue(false, va1 + 4096 + 8, MATCH_ANY, TID)?;
            // Same object, wrong word: nobody.
            if futex(va2 + 4096 + 12, FUTEX_WAKE, 1, 0) != Some(0) {
                crate::handlers::__test_futex_drop_current(false, va1 + 4096 + 8, TID);
                return Err("a different offset in the memfd shared the queue");
            }
            // Other process, third address, same (memfd, offset).
            switch_to(&b);
            let va3 = mmap(0, 8192, MAP_SHARED, fd)?;
            let woke = futex(va3 + 4096 + 8, FUTEX_WAKE, 1, 0);
            switch_to(&a);
            if woke != Some(1) || hits.load(Ordering::Acquire) != 1 {
                crate::handlers::__test_futex_drop_current(false, va1 + 4096 + 8, TID);
                return Err("FUTEX_WAKE via another mapping of the memfd missed the waiter");
            }
            // And within one process at a second address.
            let hits2 = queue(false, va2 + 16, MATCH_ANY, TID)?;
            if futex(va1 + 16, FUTEX_WAKE, 1, 0) != Some(1) || hits2.load(Ordering::Acquire) != 1 {
                crate::handlers::__test_futex_drop_current(false, va2 + 16, TID);
                return Err("FUTEX_WAKE via a second mapping in one mm missed the waiter");
            }
            // `FUTEX_PRIVATE_FLAG` opts out of object keying: (mm, address).
            let hits3 = queue(true, va2 + 16, MATCH_ANY, TID)?;
            let cross = futex(va1 + 16, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);
            crate::handlers::__test_futex_drop_current(true, va2 + 16, TID);
            if cross != Some(0) || hits3.load(Ordering::Acquire) != 0 {
                return Err("a FUTEX_PRIVATE wake was keyed by object, not address");
            }
            Ok(())
        };
        let r = body();
        release_as();
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_shared_memfd_keyed_by_object_not_va
);

/// Anonymous `MAP_SHARED` is one shmem object shared across `fork`: the
/// parent's waiter is reached from the child. An UNRELATED process with its
/// own anonymous shared mapping at the same address is a different object
/// and must not reach it.
fn smoke_abi_futex_shared_anon_follows_fork_not_va() -> TestResult {
    with_setup(|| {
        const VA: u64 = 0x0000_0100_5f20_0000;
        const TID: u64 = 0x7e_0031;
        let parent = new_as()?;
        let stranger = new_as()?;
        let body = || -> Result<(), &'static str> {
            switch_to(&parent);
            mmap(VA, 4096, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, u64::MAX)?;
            // SAFETY: paging is live; the child is an inactive copy whose
            // region table is all this test consults.
            let child = unsafe { parent.clone_for_fork() }
                .map(Arc::new)
                .map_err(|_| "clone_for_fork failed")?;
            let hits = queue(false, VA + 4, MATCH_ANY, TID)?;
            switch_to(&stranger);
            mmap(VA, 4096, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, u64::MAX)?;
            if futex(VA + 4, FUTEX_WAKE, 1, 0) != Some(0) || hits.load(Ordering::Acquire) != 0 {
                switch_to(&parent);
                crate::handlers::__test_futex_drop_current(false, VA + 4, TID);
                return Err("an unrelated anonymous shared mapping reached the waiter");
            }
            switch_to(&child);
            let woke = futex(VA + 4, FUTEX_WAKE, 1, 0);
            switch_to(&parent);
            if woke != Some(1) || hits.load(Ordering::Acquire) != 1 {
                crate::handlers::__test_futex_drop_current(false, VA + 4, TID);
                return Err("the fork child's FUTEX_WAKE missed the parent's waiter");
            }
            Ok(())
        };
        let r = body();
        release_as();
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_shared_anon_follows_fork_not_va
);

// ════════════════════════════════════════════════════════════════════
// Bug: FUTEX_WAKE_BITSET ignored the waiters' bitsets.
// ════════════════════════════════════════════════════════════════════

/// `futex_wake`: `if (!(this->bitset & bitset)) continue;` — a waiter whose
/// bitset does not intersect the wake's is skipped, stays queued, and does
/// not count toward `nr_wake`. Waiter 1 (queued first, bitset 0x2) must be
/// passed over by `FUTEX_WAKE_BITSET(nr=1, 0x1)` in favour of waiter 2
/// (bitset 0x1); a disjoint bitset wakes nobody; `FUTEX_WAKE` (MATCH_ANY)
/// then takes the remaining one.
fn smoke_abi_futex_wake_bitset_filters_waiters() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        const T1: u64 = 0x7e_0041;
        const T2: u64 = 0x7e_0042;
        let w1 = queue(true, p, 0x2, T1)?;
        let w2 = queue(true, p, 0x1, T2)?;
        let r = (|| {
            if futex(p, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0x1) != Some(1) {
                return Err("FUTEX_WAKE_BITSET(nr=1, 0x1) must wake one matching waiter");
            }
            if w1.load(Ordering::Acquire) != 0 || w2.load(Ordering::Acquire) != 1 {
                return Err("FUTEX_WAKE_BITSET woke a waiter whose bitset does not match");
            }
            if futex(p, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 8, 0x4) != Some(0) {
                return Err("a disjoint bitset must wake (and count) nobody");
            }
            if futex(p, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 8, 0) != Some(1)
                || w1.load(Ordering::Acquire) != 1
            {
                return Err("FUTEX_WAKE (MATCH_ANY) must take the skipped waiter");
            }
            Ok(())
        })();
        crate::handlers::__test_futex_drop_current(true, p, T1);
        crate::handlers::__test_futex_drop_current(true, p, T2);
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_wake_bitset_filters_waiters
);

/// futex2 `futex_wake(uaddr, mask, nr, flags)` is `futex_wake(..., mask)`:
/// the same bitset filter, and the return value is the number actually
/// woken (`ret`), not the `nr` requested.
fn smoke_abi_futex2_wake_mask_filters_and_counts() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        const T1: u64 = 0x7e_0051;
        const T2: u64 = 0x7e_0052;
        let w1 = queue(true, p, 0x2, T1)?;
        let w2 = queue(true, p, 0x1, T2)?;
        let wake = |mask: u64, nr: u64| {
            call(
                Syscall::FutexWake.raw(),
                a3(p, mask, nr, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE),
            )
        };
        let r = (|| {
            if wake(0x1, 1) != Some(1) || w2.load(Ordering::Acquire) != 1 {
                return Err("futex_wake(mask=0x1, nr=1) must wake the matching waiter");
            }
            if w1.load(Ordering::Acquire) != 0 {
                return Err("futex_wake woke a waiter outside its mask");
            }
            if wake(0x4, 5) != Some(0) {
                return Err("futex_wake must return the number woken, not nr");
            }
            if wake(MATCH_ANY as u64, 5) != Some(1) || w1.load(Ordering::Acquire) != 1 {
                return Err("futex_wake(MATCH_ANY) must take the remaining waiter, return 1");
            }
            Ok(())
        })();
        crate::handlers::__test_futex_drop_current(true, p, T1);
        crate::handlers::__test_futex_drop_current(true, p, T2);
        r
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex2_wake_mask_filters_and_counts
);

/// `futex_requeue` wakes and moves waiters WITHOUT consulting their bitsets
/// (only `futex_wake` filters). A waiter that `FUTEX_WAKE_BITSET` skipped is
/// still woken by `FUTEX_REQUEUE`'s wake half.
fn smoke_abi_futex_requeue_ignores_bitset() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let word2: u32 = 0;
        let p = &word as *const u32 as u64;
        let p2 = &word2 as *const u32 as u64;
        const T1: u64 = 0x7e_0061;
        let w1 = queue(true, p, 0x2, T1)?;
        let r = call(
            Syscall::Futex.raw(),
            SyscallArgs {
                arg0: p,
                arg1: FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG,
                arg2: 1,
                arg3: 0,
                arg4: p2,
                arg5: 0,
            },
        );
        crate::handlers::__test_futex_drop_current(true, p, T1);
        if r != Some(1) || w1.load(Ordering::Acquire) != 1 {
            return Err("FUTEX_REQUEUE must wake regardless of the waiter's bitset");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/futex", smoke_abi_futex_requeue_ignores_bitset);

// ════════════════════════════════════════════════════════════════════
// PI futexes (`kernel/futex/pi.c`).
// ════════════════════════════════════════════════════════════════════

const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;
const FUTEX_TRYLOCK_PI: u64 = 8;
const FUTEX_LOCK_PI2: u64 = 13;
const FUTEX_CLOCK_REALTIME: u64 = 256;
const PI_WAITERS: u32 = 0x8000_0000;
const PI_OWNER_DIED: u32 = 0x4000_0000;

fn futex_timeout(uaddr: u64, op: u64, timeout: u64) -> Option<i64> {
    call(
        Syscall::Futex.raw(),
        SyscallArgs {
            arg0: uaddr,
            arg1: op,
            arg3: timeout,
            ..Default::default()
        },
    )
}

/// The PI futex protocol behind every glibc `PTHREAD_PRIO_INHERIT` mutex.
/// glibc probes for it once with `futex(&zero, FUTEX_UNLOCK_PI)`: ENOSYS
/// means "no PI", and then every `pthread_mutex_init(PRIO_INHERIT)` fails
/// ENOTSUP. NARF answered ENOSYS for all PI ops, so PipeWire's data loop
/// ("can't create loop: Operation not supported") — and with it the whole
/// session audio stack — never started.
///
/// The non-blocking decisions, in `futex_lock_pi_atomic` / `futex_lock_pi` /
/// `futex_unlock_pi` order; the blocking handoff is the boot's to prove.
fn smoke_abi_futex_pi_lock_unlock_protocol() -> TestResult {
    with_setup(|| {
        let me = call(Syscall::Gettid.raw(), a0(0)).ok_or("gettid")? as u32;
        let word = core::sync::atomic::AtomicU32::new(0);
        let p = &word as *const _ as u64;
        let set = |v: u32| word.store(v, Ordering::SeqCst);
        let get = || word.load(Ordering::SeqCst);
        let p_op = |op: u64| futex(p, op | FUTEX_PRIVATE_FLAG, 0, 0);

        // glibc's probe: not the owner of an unowned word → EPERM, not ENOSYS.
        if p_op(FUTEX_UNLOCK_PI) != Some(EPERM) {
            return Err("FUTEX_UNLOCK_PI on an unowned word must be EPERM (glibc's PI probe)");
        }
        // A free word is taken: it holds the caller's TID.
        if p_op(FUTEX_LOCK_PI) != Some(0) || get() != me {
            return Err("FUTEX_LOCK_PI on a free word must take it with the caller's TID");
        }
        // Owned by the caller: EDEADLK, for trylock too.
        if p_op(FUTEX_LOCK_PI) != Some(EDEADLK) || p_op(FUTEX_TRYLOCK_PI) != Some(EDEADLK) {
            return Err("locking a PI futex the caller owns must be EDEADLK");
        }
        // Unlock with nobody parked: the word returns to 0.
        if p_op(FUTEX_UNLOCK_PI) != Some(0) || get() != 0 {
            return Err("FUTEX_UNLOCK_PI with no waiters must clear the word");
        }
        // OWNER_DIED survives the take.
        set(PI_OWNER_DIED);
        if p_op(FUTEX_TRYLOCK_PI) != Some(0) || get() != (PI_OWNER_DIED | me) {
            return Err("taking a free word must keep FUTEX_OWNER_DIED");
        }
        set(0);
        // An owner TID that names no task: ESRCH.
        set(0x3fff_fff0);
        if p_op(FUTEX_LOCK_PI) != Some(ESRCH) || p_op(FUTEX_TRYLOCK_PI) != Some(ESRCH) {
            return Err("a PI futex owned by a nonexistent TID must be ESRCH");
        }
        // Owned by another live task.
        const OTHER: u64 = 0x7e_0051;
        crate::handlers::register_pid_task_mapping(OTHER, OTHER);
        crate::handlers::register_task_to_pid(OTHER, OTHER);
        let held = (|| {
            set(OTHER as u32);
            if p_op(FUTEX_TRYLOCK_PI) != Some(EAGAIN) || get() != OTHER as u32 {
                return Err("TRYLOCK_PI on a held lock must be EWOULDBLOCK and leave the word");
            }
            if p_op(FUTEX_UNLOCK_PI) != Some(EPERM) {
                return Err("unlocking a lock another task holds must be EPERM");
            }
            // An absolute deadline already past: the locker flags itself as
            // a waiter, then times out.
            let zero = [0u64; 2];
            if futex_timeout(p, FUTEX_LOCK_PI2 | FUTEX_PRIVATE_FLAG, zero.as_ptr() as u64)
                != Some(ETIMEDOUT)
                || get() != (OTHER as u32 | PI_WAITERS)
            {
                return Err("LOCK_PI2 past its deadline must set FUTEX_WAITERS and time out");
            }
            Ok(())
        })();
        crate::handlers::release_reaped_task(OTHER);
        held?;
        // FUTEX_CLOCK_REALTIME is for LOCK_PI2 only.
        set(0);
        if futex_timeout(p, FUTEX_LOCK_PI | FUTEX_CLOCK_REALTIME, 0) != Some(ENOSYS) {
            return Err("FUTEX_LOCK_PI | FUTEX_CLOCK_REALTIME must be ENOSYS");
        }
        // With a task parked: taking keeps FUTEX_WAITERS set, and the unlock
        // hands the word to the waiters (no owner, WAITERS) and wakes one.
        const T1: u64 = 0x7e_0052;
        let parked = queue(true, p, MATCH_ANY, T1)?;
        let r = (|| {
            if p_op(FUTEX_LOCK_PI) != Some(0) || get() != (me | PI_WAITERS) {
                return Err("taking a PI futex with a parked waiter must set FUTEX_WAITERS");
            }
            if p_op(FUTEX_UNLOCK_PI) != Some(0) || get() != PI_WAITERS {
                return Err("unlocking with a parked waiter must leave FUTEX_WAITERS, no owner");
            }
            if parked.load(Ordering::Acquire) != 1 {
                return Err("unlocking with a parked waiter must wake it");
            }
            Ok(())
        })();
        crate::handlers::__test_futex_drop_current(true, p, T1);
        r
    })
}
kernel_test_in!("syscall_abi/futex", smoke_abi_futex_pi_lock_unlock_protocol);

//! Bump allocator over `brk`. Validation-grade only — `free` is a
//! no-op. A real freelist allocator (and a `realloc`/`calloc`
//! pair) is a Stage-4 follow-up; the goal here is to give the
//! validate binary a concrete `malloc` to call so we know the
//! brk-syscall round-trip works.
//!
//! The bump cursor is initialised lazily on first call so we don't
//! have to wire a constructor into `__libc_start_main`. `brk(0)`
//! reads the current break (the kernel guarantees a stable initial
//! value); subsequent `brk(target)` grows it page-aligned.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Initial break value, captured on first `malloc`. Used as a
/// sentinel for lazy init (0 = not yet sampled).
static HEAP_INITIAL: AtomicUsize = AtomicUsize::new(0);
/// Current bump cursor. Always `>= HEAP_INITIAL`; grows on each
/// successful allocation, never shrinks (free is a no-op).
static HEAP_TOP: AtomicUsize = AtomicUsize::new(0);

/// Allocate `size` bytes with 16-byte alignment. Returns null on
/// `size == 0` (POSIX permits this) and on `brk` failure.
///
/// Concurrency: `fetch_add` on `HEAP_TOP` reserves the slot, then
/// we ask the kernel to grow `brk` if needed. Two racing callers
/// both succeed because the second `brk(new_top)` is a no-op
/// (kernel honours the highest target).
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    // Round up to 16-byte alignment so consecutive blocks satisfy
    // the SysV-AMD64 max-align requirement (e.g. for `__int128` /
    // `long double` buffers a future caller might want).
    let size = (size + 15) & !15;

    let initial = HEAP_INITIAL.load(Ordering::Acquire);
    if initial == 0 {
        // Lazy initialise. brk(0) returns the current break — the
        // kernel guarantees this is non-zero on a successful
        // address-space init, so we can use 0 as a sentinel.
        let cur = narf_user_runtime::brk(0);
        if cur == 0 || cur == usize::MAX {
            return core::ptr::null_mut();
        }
        // CAS so two racing callers agree on the same initial.
        if HEAP_INITIAL.compare_exchange(0, cur, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            HEAP_TOP.store(cur, Ordering::Release);
        }
    }

    let old_top = HEAP_TOP.fetch_add(size, Ordering::AcqRel);
    let new_top = old_top + size;

    // Grow brk if we crossed the current break. Re-querying the
    // break each call is cheap (one syscall) and guards against the
    // kernel having grown it for some other reason.
    let cur_break = narf_user_runtime::brk(0);
    if new_top > cur_break {
        let grown = narf_user_runtime::brk(new_top);
        if grown < new_top {
            // brk failed — roll the bump cursor back so the slot
            // can be reused. Note this is best-effort: another
            // racing allocation may have already moved past us, in
            // which case the rollback is a no-op (the sub-add still
            // leaves a hole the next allocation skips).
            HEAP_TOP.fetch_sub(size, Ordering::AcqRel);
            return core::ptr::null_mut();
        }
    }

    old_top as *mut u8
}

/// Free is a no-op for the bump allocator. Documented as a
/// Stage-4 limitation; a freelist allocator follows.
pub fn free(_ptr: *mut u8) {}

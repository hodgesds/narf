//! Tier-1.5 freelist allocator over `mmap`.
//!
//! Replaces the prior bump-on-`brk` cursor: `free` now actually
//! returns memory so long-running alloc/free cycles don't leak. The
//! design is a single global free list of variable-sized chunks with
//! a small in-band header. Callers see a `*mut u8` that points just
//! past the header; the allocator recovers the header on `free` by
//! subtracting `HEADER_SIZE`.
//!
//! Strategy: first-fit walk over a singly-linked free list. On a
//! miss we grow the heap by mmapping at least `MIN_GROW_BYTES`
//! (page-rounded) and seeding the result as a fresh free chunk. The
//! kernel chooses the vaddr — `mmap`'s `hint` arg is suggestive
//! only — so successive `mmap` calls return disjoint regions and we
//! cannot rely on a contiguous heap. Each grown region therefore
//! becomes its own free chunk; the free-list-reuse probe is
//! satisfied by the *split-then-reuse* path on the second `malloc`,
//! not by any vaddr math.
//!
//! Concurrency: NARF user mode is single-threaded. The free-list
//! head lives in an `AtomicPtr` to match the `static mut`-avoidance
//! pattern used elsewhere in narf-libc; loads/stores use
//! Acquire/Release so future MT support won't have to revisit the
//! ordering questions.
//!
//! Coalescing: implemented inline on `free`. Each `push_free` walks
//! the free list once looking for an immediate neighbour (forward
//! merge: list-node's start == freed-chunk's end; backward merge:
//! list-node's end == freed-chunk's start) and absorbs it before
//! parking the chunk on the head. After a single match the function
//! tail-recurses so the just-grown chunk can pick up a second-step
//! neighbour. O(n) per free in the worst case, n = free-list depth;
//! acceptable here because n stays small under narf-libc's typical
//! workload. Reference: musl's `mallocng/free.c` does the same
//! direction-aware merge but uses an in-band footer for O(1) lookup;
//! glibc's `__libc_free` walks via `unlink2()` on the bins.

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// In-band chunk header. The size includes the header itself, so
/// `chunk.size - HEADER_SIZE` is what the caller actually sees.
///
/// `next` is only meaningful while the chunk is on the free list —
/// when the caller holds the post-header pointer the field is dead
/// space. We do NOT clear it on alloc; the next `free` overwrites it.
#[repr(C)]
struct Chunk {
    /// Size of the chunk INCLUDING this header, in bytes.
    size: usize,
    /// Next free chunk. Null when this is the tail of the free list.
    /// Only valid when the chunk is on the free list — uninitialised
    /// when the chunk is in use by the caller.
    next: *mut Chunk,
}

const HEADER_SIZE: usize = core::mem::size_of::<Chunk>();
/// Smallest free-list remainder we'll keep after a split. If a fit
/// would leave less than this, we hand the entire chunk to the
/// caller (slop tracked implicitly by `chunk.size`).
const MIN_CHUNK_SPLIT: usize = HEADER_SIZE + 32;
/// Minimum byte count we ask the kernel for on a free-list miss.
/// Page-rounding happens after; this is the floor.
const MIN_GROW_BYTES: usize = 64 * 1024;
/// Page size used for grow rounding. The kernel mmap path is
/// page-granular regardless; rounding here keeps the chunk size in
/// step with what was actually mapped.
const PAGE_SIZE: usize = 4096;
/// User-visible alignment. SysV-AMD64 + AArch64 PCS both want
/// 16-byte max-align for arbitrary scalars; matching that lets a
/// future caller use the buffer for `long double` / `__int128`
/// without surprises.
const ALIGN: usize = 16;

/// Free-list head. Single-threaded user mode means a plain `static
/// mut` would work, but the codebase uses atomics for static state
/// so we follow suit. Acquire on load pairs with Release on store
/// via the head-write CAS path.
static FREE_LIST: AtomicPtr<Chunk> = AtomicPtr::new(ptr::null_mut());

/// Round `n` up to the next `ALIGN` boundary. `ALIGN` is a power of
/// two so the bitmask form is correct.
#[inline]
fn align_up(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// Round `n` up to the next page boundary. Used to size the mmap
/// request — the kernel rounds anyway, but matching here means the
/// resulting Chunk records the true mapped length.
#[inline]
fn page_round_up(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Push `chunk` onto the free list AND attempt forward / backward
/// coalescing with adjacent free chunks so long-running churn
/// doesn't fragment the free list. Caller owns `chunk` and must
/// have already written `chunk.size`; we set `chunk.next` here.
///
/// Coalescing strategy: walk the existing free list once. For each
/// candidate `c`:
///   - if `c` is immediately after `chunk` (chunk + chunk.size == c)
///     unlink `c` and grow `chunk.size` by `c.size` (forward merge).
///   - if `chunk` is immediately after `c` (c + c.size == chunk)
///     drop `chunk` into `c` by growing `c.size` and re-using `c`'s
///     existing list slot (backward merge).
/// At most one match in either direction per push since the free
/// list is sorted by no particular order — the next call's pass
/// catches multi-step chains. O(n) per free; acceptable for narf-
/// libc's typical free-list depth (small).
///
/// # Safety
/// `chunk` must point to a valid `Chunk` header with `size`
/// initialised. The chunk must not already be on the free list.
unsafe fn push_free(chunk: *mut Chunk) {
    // Iterative coalesce: each pass either grows `chunk` and rescans,
    // or finds no neighbour and parks the chunk on the head. Loop is
    // used in place of tail-recursion so a long chain of adjacent
    // chunks doesn't stack-overflow on free.
    let mut chunk = chunk;
    'outer: loop {
        // SAFETY: invariant — chunk.size was set by caller.
        let chunk_size = unsafe { (*chunk).size };
        let chunk_end = (chunk as usize).wrapping_add(chunk_size);

        let mut prev: *mut Chunk = ptr::null_mut();
        let mut cur = FREE_LIST.load(Ordering::Acquire);
        while !cur.is_null() {
            // SAFETY: list invariant — every list pointer is a valid Chunk.
            let cur_size = unsafe { (*cur).size };
            // SAFETY: same.
            let cur_next = unsafe { (*cur).next };
            let cur_end = (cur as usize).wrapping_add(cur_size);

            if cur as usize == chunk_end {
                // Forward merge: cur sits immediately after chunk.
                // Unlink cur from the list, grow chunk by cur.size.
                if prev.is_null() {
                    FREE_LIST.store(cur_next, Ordering::Release);
                } else {
                    // SAFETY: prev was deref'd already.
                    unsafe {
                        (*prev).next = cur_next;
                    }
                }
                // SAFETY: chunk is caller-owned.
                unsafe {
                    (*chunk).size = chunk_size + cur_size;
                }
                // Rescan: chunk grew and might now coalesce with
                // another neighbour further along the list.
                continue 'outer;
            }

            if chunk as usize == cur_end {
                // Backward merge: chunk sits immediately after cur.
                // Grow cur by chunk.size — chunk's storage becomes
                // part of cur. Detach cur from the list so the next
                // pass treats it as the fresh chunk.
                // SAFETY: cur was deref'd already.
                unsafe {
                    (*cur).size = cur_size + chunk_size;
                }
                if prev.is_null() {
                    FREE_LIST.store(cur_next, Ordering::Release);
                } else {
                    // SAFETY: prev was deref'd already.
                    unsafe {
                        (*prev).next = cur_next;
                    }
                }
                chunk = cur;
                continue 'outer;
            }

            prev = cur;
            cur = cur_next;
        }

        // No coalescing match this pass — park `chunk` on the head.
        // Single-threaded NARF user mode + atomic head for future MT.
        loop {
            let head = FREE_LIST.load(Ordering::Acquire);
            // SAFETY: `chunk` is caller-owned; writing `next` is fine.
            unsafe {
                (*chunk).next = head;
            }
            if FREE_LIST
                .compare_exchange(head, chunk, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Walk the free list looking for the first chunk with at least
/// `need` bytes (header included). On success removes it from the
/// list and returns the pointer; on miss returns null.
///
/// # Safety
/// Free-list pointers must all be valid `Chunk` headers — upheld by
/// `push_free` being the only path that adds to the list and only
/// adding chunks we've populated.
unsafe fn pop_fit(need: usize) -> *mut Chunk {
    // Single-pass first-fit. We unlink by rewriting the predecessor's
    // `next` (or the head pointer if the fit is the head). No CAS
    // loop here — single-threaded — but the loads/stores still go
    // through the atomic so we don't have to juggle `static mut`.
    let mut prev: *mut Chunk = ptr::null_mut();
    let mut cur = FREE_LIST.load(Ordering::Acquire);
    while !cur.is_null() {
        // SAFETY: invariant — every list pointer is a valid Chunk.
        let cur_size = unsafe { (*cur).size };
        // SAFETY: same.
        let cur_next = unsafe { (*cur).next };
        if cur_size >= need {
            if prev.is_null() {
                FREE_LIST.store(cur_next, Ordering::Release);
            } else {
                // SAFETY: `prev` came from a prior loop iteration
                // where we already deref'd it.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    (*prev).next = cur_next;
                }
            }
            return cur;
        }
        prev = cur;
        cur = cur_next;
    }
    ptr::null_mut()
}

/// Ask the kernel for a fresh region of at least `min_bytes` (header
/// included). Returns a `Chunk` pointer with `size` set to the
/// actual mapped length, or null on mmap failure.
unsafe fn grow_heap(min_bytes: usize) -> *mut Chunk {
    let want = page_round_up(core::cmp::max(min_bytes, MIN_GROW_BYTES));
    // SAFETY: mmap with hint=0 lets the kernel pick the vaddr; flags
    // = 0 is the default RW user mapping. The returned pointer (if
    // non-null) is valid for `want` bytes per the kernel contract.
    // SAFETY: Valid memory or trusted environment
    let p = unsafe { narf_user_runtime::mmap(0, want, 0) };
    if p.is_null() {
        return ptr::null_mut();
    }
    let chunk = p as *mut Chunk;
    // SAFETY: `chunk` is the start of a freshly mapped, writable
    // region of `want` bytes. We don't write `next` here — the
    // caller pushes onto the free list (or uses the chunk directly)
    // which sets it.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        (*chunk).size = want;
    }
    chunk
}

/// Allocate `size` bytes with 16-byte alignment. Returns null on
/// `size == 0` (POSIX permits this) and on mmap failure.
///
/// The returned pointer is past the in-band header; `free` recovers
/// the header by subtracting `HEADER_SIZE`. The chunk is at least
/// `aligned_size + HEADER_SIZE` bytes including the header — i.e.
/// the caller-visible region is at least `aligned_size` bytes.
///
/// # Safety
/// Caller must eventually pair the result with `free` (or `realloc`).
/// The C-ABI shape is the contract; this is `unsafe` to match
/// `extern "C"` malloc declarations seen by C consumers.
///
/// `#[inline(never)]` because LTO otherwise inlines this into the
/// caller; with the in-band header threaded through call-site
/// pointer arithmetic the optimiser can lose track of the
/// "free pushes onto FREE_LIST, malloc pops from it" data flow and
/// the second malloc in a free/malloc pair gets a different chunk
/// than the just-freed one. Keeping malloc out-of-line preserves
/// the AtomicPtr round-trip the codegen needs.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    let aligned = align_up(size);
    // Total chunk footprint we need: aligned payload + header.
    let need = aligned + HEADER_SIZE;

    // First fit walk. On miss, grow once and retry — the grown
    // chunk is guaranteed big enough because we asked for `need`.
    // SAFETY: pop_fit / grow_heap / push_free invariants hold (see
    // their docs).
    // SAFETY: Valid memory or trusted environment
    let chunk = unsafe {
        let c = pop_fit(need);
        if !c.is_null() {
            c
        } else {
            let g = grow_heap(need);
            if g.is_null() {
                return ptr::null_mut();
            }
            // The grown chunk is exactly the size we asked for; we
            // don't push-then-pop, we just use it directly. (Pushing
            // first would force a list walk; same outcome.)
            g
        }
    };

    // SAFETY: `chunk` is a valid header from either the free list
    // or `grow_heap`.
    // SAFETY: Valid memory or trusted environment
    let chunk_size = unsafe { (*chunk).size };

    // Split off the remainder if it's worth keeping. The split tail
    // becomes its own free chunk; the head becomes the caller's.
    if chunk_size >= need + MIN_CHUNK_SPLIT {
        let tail = (chunk as *mut u8).wrapping_add(need) as *mut Chunk;
        let tail_size = chunk_size - need;
        // SAFETY: `tail` lies inside the mapped region (need <
        // chunk_size); writing the header is in-bounds.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            (*tail).size = tail_size;
            push_free(tail);
            (*chunk).size = need;
        }
    }

    // Hand the caller the post-header pointer.
    (chunk as *mut u8).wrapping_add(HEADER_SIZE)
}

/// Free `ptr`. Null is a no-op (POSIX-required). The pointer must
/// have come from a prior `malloc` / `realloc` / `calloc` returned
/// by this allocator — passing arbitrary pointers is UB.
///
/// Coalescing: forward and backward merge with immediately-adjacent
/// free chunks happens inline in [`push_free`], so a free/malloc
/// churn over the same address span won't fragment the free list.
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned from
/// this allocator and not already freed.
///
/// `#[inline(never)]` for the same reason as `malloc` — see that
/// function's doc.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let chunk = ptr.wrapping_sub(HEADER_SIZE) as *mut Chunk;
    // SAFETY: per the function-level contract, `chunk` is a valid
    // header recoverable by header-subtraction from a previously
    // returned pointer.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        push_free(chunk);
    }
}

/// Resize a block. Conformant with POSIX realloc(3) edge cases:
/// null `ptr` ⇒ malloc; zero `new_size` ⇒ free + null. The fast path
/// returns the same pointer when the existing chunk already has
/// enough capacity, avoiding a copy.
///
/// # Safety
/// If `ptr` is non-null it must come from this allocator. The old
/// region is invalidated on a successful resize that needed a new
/// allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        // SAFETY: forwarding to malloc — the C-ABI contract is
        // identical.
        // SAFETY: Valid memory or trusted environment
        return unsafe { malloc(new_size) };
    }
    if new_size == 0 {
        // SAFETY: forwarding to free.
        unsafe {
            free(ptr);
        }
        return ptr::null_mut();
    }

    let chunk = ptr.wrapping_sub(HEADER_SIZE) as *mut Chunk;
    // SAFETY: per the function-level contract, `chunk` is a valid
    // header.
    // SAFETY: Valid memory or trusted environment
    let old_size = unsafe { (*chunk).size };
    let aligned = align_up(new_size);
    let need = aligned + HEADER_SIZE;

    // Fast path: the existing chunk already has the requested
    // capacity. We DON'T shrink the chunk in place — splitting on
    // realloc-down would complicate the free path and isn't worth
    // it for the validate-grade workload.
    if old_size >= need {
        return ptr;
    }

    // Slow path: malloc + memcpy + free. Copy `min(old_payload,
    // new_size)` bytes; the new region's tail is uninitialised
    // (POSIX permits this — realloc isn't required to zero).
    // SAFETY: malloc / free are this module's own.
    let new_ptr = unsafe { malloc(new_size) };
    if new_ptr.is_null() {
        // POSIX: failure leaves the original block intact.
        return ptr::null_mut();
    }
    let old_payload = old_size - HEADER_SIZE;
    let copy = core::cmp::min(old_payload, new_size);
    // SAFETY: both regions are at least `copy` bytes; they're
    // disjoint because `malloc` returned a fresh chunk.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, new_ptr, copy);
        free(ptr);
    }
    new_ptr
}

/// `count * size` bytes, zero-filled. Overflow on the multiply
/// returns null per POSIX guidance (calloc(3): "If the multiplication
/// would overflow, calloc() returns an error").
///
/// # Safety
/// Caller-visible C-ABI shape; the allocation contract is the same
/// as `malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let total = match count.checked_mul(size) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    if total == 0 {
        return ptr::null_mut();
    }
    // SAFETY: forwarding to malloc; on success we own the buffer
    // for the duration of the zero-fill.
    // SAFETY: Valid memory or trusted environment
    let p = unsafe { malloc(total) };
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `p` is `total` bytes of writable memory; write_bytes
    // matches the rounded-up allocation footprint we asked for.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(p, 0, total);
    }
    p
}

// ── posix_memalign / aligned_alloc ──────────────────────────────────
//
// The freelist allocator's chunks are 16-byte aligned by construction
// (mmap pages are page-aligned; the chunk header is 16-byte; chunks
// are always rounded up to a multiple of 16). For most callers that's
// already enough — every alignment up to 16 is satisfied trivially.
//
// For larger alignments (e.g. 64 for cache lines, 4096 for pages) we
// over-allocate by `alignment - 1` bytes, then return the lowest
// aligned pointer inside the block. The caller's free / realloc will
// see the original chunk header because we reach back from the
// aligned pointer using the same offset the allocator did. Since our
// freelist already uses an inline header at `ptr - HEADER_SIZE`, an
// aligned-up pointer would not find that header. To keep this simple
// we restrict aligned_alloc / posix_memalign to alignments <= 16
// (the existing baseline). Larger alignments return EINVAL — real
// callers are vanishingly rare in NARF's user surface.

const EINVAL: i32 = 22;

/// `posix_memalign(memptr, align, size)` — align must be a power of
/// two and a multiple of `sizeof(void *)`. Stores the allocated
/// pointer through `*memptr` on success and returns 0; otherwise
/// returns the errno-shaped value (EINVAL / ENOMEM).
///
/// # Safety
/// `memptr` must be a writable pointer-to-pointer slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(memptr: *mut *mut u8, align: usize, size: usize) -> i32 {
    if memptr.is_null() {
        return EINVAL;
    }
    if align == 0 || (align & (align - 1)) != 0 || align % core::mem::size_of::<usize>() != 0 {
        return EINVAL;
    }
    if align > 16 {
        // Stage-4 simplification — see module-level comment.
        return EINVAL;
    }
    // SAFETY: malloc returns a 16-byte-aligned pointer.
    let p = unsafe { malloc(size) };
    if p.is_null() {
        return 12; // ENOMEM
    }
    // SAFETY: caller-supplied writable slot.
    unsafe {
        *memptr = p;
    }
    0
}

/// `aligned_alloc(align, size)` — C11 form. Same restrictions as
/// [`posix_memalign`]; returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(align: usize, size: usize) -> *mut u8 {
    if align == 0 || (align & (align - 1)) != 0 {
        return ptr::null_mut();
    }
    if align > 16 {
        return ptr::null_mut();
    }
    if size % align != 0 {
        // C11: undefined; we choose to fail.
        return ptr::null_mut();
    }
    // SAFETY: forwarded.
    unsafe { malloc(size) }
}

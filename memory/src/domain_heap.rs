//! Per-domain tagged heap for module allocations (aarch64 MTE).
//!
//! Module *images* carry their domain's MTE tag (`module_text`), so a pointer
//! into one derived from another domain faults. Their *allocations* did not:
//! `narf_kmalloc` returns ordinary kernel heap memory, which is plain Normal
//! and unchecked, so a module's buffers were reachable from every domain. This
//! closes that for the one allocation path modules have.
//!
//! # Why not tag the kernel heap
//!
//! Because tag checks are per page and `SCTLR_EL1.TCF` is per CPU. Marking the
//! general heap `ATTR_TAGGED` would make every untagged kernel access to heap
//! memory inside any domain scope fault — and the kernel touches the heap
//! constantly inside those scopes. The blast radius has to stay bounded to
//! memory whose every access the kernel controls, which is what a dedicated
//! region gives.
//!
//! # Why not reuse `slab`
//!
//! `slab` threads its free list through the objects themselves — it writes
//! `FreeBlock { next }` into freed memory. Those writes come from allocator
//! code holding an untagged pointer, so over a tagged region every free would
//! fault. An allocator for tagged memory must keep its metadata *out of band*,
//! which is why this is a bitmap rather than a free list.
//!
//! # Shape
//!
//! One 512 GiB slot, carved into a fixed 1 MiB window per domain, so an
//! address identifies its domain by arithmetic alone. That matters for `free`:
//! a buffer may be released outside the scope that allocated it, or from a
//! different domain entirely, and deriving the owner from the pointer avoids
//! depending on who happens to be running.
//!
//! Allocation is a first-fit run over 64-byte blocks with the bitmap in
//! ordinary kernel memory. Coarse, and deliberately so: modules allocate
//! rarely, and the property being bought is isolation, not throughput.
//!
//! # What it does not do
//!
//! Tags are written once, when a domain's window is first mapped, and are not
//! rotated on free. This buys domain isolation — a pointer derived outside the
//! domain carries a different tag — not use-after-free detection, which would
//! need a fresh tag per allocation and a matching pointer handed back.

#![cfg(target_arch = "aarch64")]

use core::alloc::Layout;

use narf_arch::aarch64::mte;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// L0 slot holding the per-domain heap. Above the poke window (277).
pub const HEAP_L0_SLOT: usize = 278;
/// Base kernel VA of the region.
pub const HEAP_BASE: u64 = 0xFFFF_8B00_0000_0000;

const _: () = assert!(
    ((HEAP_BASE >> 39) & 0x1FF) as usize == HEAP_L0_SLOT,
    "HEAP_BASE does not decode to HEAP_L0_SLOT"
);

/// Bytes of window per domain.
pub const DOMAIN_STRIDE: u64 = 1 << 20;
/// Allocation granularity. Also the minimum alignment any allocation gets.
pub const BLOCK: u64 = 64;
/// Blocks in one domain's window.
const BLOCKS: usize = (DOMAIN_STRIDE / BLOCK) as usize;
const WORDS: usize = BLOCKS / 64;
const NUM_DOMAINS: usize = 16;

struct DomainPool {
    /// One bit per 64-byte block; 1 = in use.
    used: [u64; WORDS],
    /// Whether this domain's window has been mapped and tagged.
    mapped: bool,
}

impl DomainPool {
    const fn new() -> Self {
        Self {
            used: [0; WORDS],
            mapped: false,
        }
    }
}

static POOLS: IrqSafeSpinLock<[DomainPool; NUM_DOMAINS]> =
    IrqSafeSpinLock::new([const { DomainPool::new() }; NUM_DOMAINS]);

/// Base VA of `domain`'s window, untagged.
#[inline]
const fn window_base(domain: u8) -> u64 {
    HEAP_BASE + (domain as u64) * DOMAIN_STRIDE
}

/// Whether `ptr` points inside this region. Tag-insensitive: callers hold the
/// tagged pointer, and the answer must not depend on that.
#[inline]
#[must_use]
pub fn owns(ptr: *const u8) -> bool {
    let a = mte::with_tag(ptr as u64, mte::UNTAGGED_KERNEL_TAG);
    (HEAP_BASE..HEAP_BASE + (NUM_DOMAINS as u64) * DOMAIN_STRIDE).contains(&a)
}

/// The domain owning `ptr`, or `None` when it is outside the region.
#[inline]
#[must_use]
pub fn owner(ptr: *const u8) -> Option<DomainId> {
    if !owns(ptr) {
        return None;
    }
    let a = mte::with_tag(ptr as u64, mte::UNTAGGED_KERNEL_TAG);
    Some(DomainId::new(((a - HEAP_BASE) / DOMAIN_STRIDE) as u8))
}

/// Map and tag `domain`'s window. Idempotent via the caller's `mapped` flag.
///
/// # Safety
/// Caller holds the pool lock and has established the window is not mapped.
unsafe fn map_window(domain: u8, tag: u8) -> bool {
    use crate::aarch64::paging::{map_4kb, PtFlags};
    let Some(root) = crate::bpf_text::kernel_root_for_mapping() else {
        return false;
    };
    let base = window_base(domain);
    // Tagged Normal, RW at EL1, never executable. `ATTR_TAGGED` replaces
    // `ATTR_NORMAL` rather than joining it: AttrIndx is a 3-bit field.
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN | PtFlags::ATTR_TAGGED;
    let pages = (DOMAIN_STRIDE / 4096) as usize;
    for i in 0..pages {
        let Ok(frame) = crate::frame::alloc_frame() else {
            return false;
        };
        let va = crate::VirtAddr::new(base + (i as u64) * 4096);
        // SAFETY: `root` is the live kernel root, the slot was reserved at
        // boot, and `frame` is freshly allocated and exclusively ours.
        if unsafe { map_4kb(root, va, frame.start_address(), flags) }.is_err() {
            crate::frame::free_frame(frame);
            return false;
        }
    }
    // Tag every granule AFTER mapping. Same ordering `bpf_arena` and
    // `module_text` need: a store through a non-tagged alias may leave a
    // granule's tag UNKNOWN, so tagging has to be the last write.
    let tagged = mte::with_tag(base, tag);
    let mut off = 0u64;
    while off < DOMAIN_STRIDE {
        // SAFETY: inside the window just mapped RW at EL1.
        unsafe { mte::stg((tagged + off) as *mut u8) };
        off += 16;
    }
    true
}

#[inline]
fn bit(w: &[u64; WORDS], i: usize) -> bool {
    w[i / 64] & (1 << (i % 64)) != 0
}

#[inline]
fn set(w: &mut [u64; WORDS], i: usize) {
    w[i / 64] |= 1 << (i % 64);
}

#[inline]
fn clear(w: &mut [u64; WORDS], i: usize) {
    w[i / 64] &= !(1 << (i % 64));
}

/// Allocate `layout` from `domain`'s window, returning a pointer carrying the
/// domain's MTE tag.
///
/// Returns `None` when MTE is off, the domain is untaggable, the request is
/// larger than a window, or the window is full — every one of which the caller
/// must treat as "use the ordinary heap", not as an error.
#[must_use]
pub fn alloc(layout: Layout, domain: DomainId) -> Option<*mut u8> {
    if !mte::supported() {
        return None;
    }
    let tag = crate::module_text::domain_tag_of(domain)?;
    if layout.size() == 0 || layout.size() as u64 > DOMAIN_STRIDE {
        return None;
    }
    let need = layout.size().div_ceil(BLOCK as usize);
    // Alignments up to BLOCK are free; beyond it, only every Nth block starts
    // on a suitable boundary.
    let step = if layout.align() as u64 <= BLOCK {
        1
    } else {
        (layout.align() as u64 / BLOCK) as usize
    };

    let d = domain.raw();
    let mut g = POOLS.lock();
    if !g[d as usize].mapped {
        // SAFETY: lock held; window not yet mapped.
        if !unsafe { map_window(d, tag) } {
            return None;
        }
        g[d as usize].mapped = true;
    }
    let pool = &mut g[d as usize];

    let mut start = 0usize;
    while start + need <= BLOCKS {
        if start % step != 0 {
            start += 1;
            continue;
        }
        let mut ok = true;
        for i in start..start + need {
            if bit(&pool.used, i) {
                start = i + 1;
                ok = false;
                break;
            }
        }
        if ok {
            for i in start..start + need {
                set(&mut pool.used, i);
            }
            let va = window_base(d) + (start as u64) * BLOCK;
            return Some(mte::with_tag(va, tag) as *mut u8);
        }
    }
    None
}

/// Release a pointer obtained from [`alloc`].
///
/// The domain is derived from the address, not from whoever is running: a
/// buffer may be freed outside the scope that allocated it.
///
/// # Safety
/// `ptr` and `layout` must be a matched pair from [`alloc`].
pub unsafe fn free(ptr: *mut u8, layout: Layout) {
    let Some(domain) = owner(ptr) else {
        return;
    };
    let a = mte::with_tag(ptr as u64, mte::UNTAGGED_KERNEL_TAG);
    let off = a - window_base(domain.raw());
    if off % BLOCK != 0 {
        return;
    }
    let start = (off / BLOCK) as usize;
    let need = layout.size().div_ceil(BLOCK as usize);
    if start + need > BLOCKS {
        return;
    }
    let mut g = POOLS.lock();
    let pool = &mut g[domain.raw() as usize];
    for i in start..start + need {
        clear(&mut pool.used, i);
    }
}

/// Blocks currently allocated to `domain`. Diagnostics and tests.
#[must_use]
pub fn blocks_in_use(domain: DomainId) -> usize {
    let g = POOLS.lock();
    g[domain.raw() as usize]
        .used
        .iter()
        .map(|w| w.count_ones() as usize)
        .sum()
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// A module allocation carries its domain's tag, and the tag is the same one
/// the domain's image carries.
///
/// Those must be the identical value, not merely both non-zero: module code
/// reaches its buffers with pointers derived from its own tagged image, so a
/// heap tagged differently would make a module fault on memory it just
/// allocated.
fn smoke_domain_heap_allocation_carries_the_domain_tag() -> TestResult {
    use core::alloc::Layout;

    if !mte::supported() {
        return TestResult::Skip("no MTE on this CPU");
    }
    let d = DomainId::SCRATCH;
    let Some(want) = crate::module_text::domain_tag_of(d) else {
        return TestResult::Fail("SCRATCH has no tag, so its heap cannot be tagged");
    };
    let layout = Layout::from_size_align(128, 8).unwrap();
    let Some(p) = alloc(layout, d) else {
        return TestResult::Fail("domain_heap::alloc returned None for a small request");
    };
    let tag_ok = mte::tag_of(p as u64) == want;
    let owned = owner(p).map(|o| o.raw()) == Some(d.raw());
    // Writable through the tagged pointer — the granules must actually carry
    // the tag, not just the pointer.
    // SAFETY: 128 bytes just allocated to this domain.
    unsafe { core::ptr::write_volatile(p as *mut u64, 0x5EED_5EED) };
    // SAFETY: same allocation.
    let read = unsafe { core::ptr::read_volatile(p as *const u64) };
    // SAFETY: matched pair.
    unsafe { free(p, layout) };

    if !tag_ok {
        return TestResult::Fail("allocation does not carry the domain's image tag");
    }
    if !owned {
        return TestResult::Fail("owner() did not attribute the allocation to its domain");
    }
    if read != 0x5EED_5EED {
        return TestResult::Fail("the tagged allocation did not hold what was written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_allocation_carries_the_domain_tag
);

/// Two domains' allocations get different tags and never overlap.
fn smoke_domain_heap_domains_are_separated() -> TestResult {
    use core::alloc::Layout;

    if !mte::supported() {
        return TestResult::Skip("no MTE on this CPU");
    }
    let layout = Layout::from_size_align(64, 8).unwrap();
    let (a, b) = (DomainId::SCRATCH, DomainId::KEYS);
    let (Some(pa), Some(pb)) = (alloc(layout, a), alloc(layout, b)) else {
        return TestResult::Fail("domain_heap::alloc failed for one of two domains");
    };
    let distinct_tags = mte::tag_of(pa as u64) != mte::tag_of(pb as u64);
    let distinct_windows = owner(pa) != owner(pb);
    // SAFETY: matched pairs.
    unsafe {
        free(pa, layout);
        free(pb, layout);
    }
    if !distinct_tags {
        return TestResult::Fail("two domains' allocations share a tag");
    }
    if !distinct_windows {
        return TestResult::Fail("two domains' allocations landed in one window");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_domains_are_separated
);

/// Freed blocks are reused, so a module that allocates in a loop does not
/// exhaust its window.
///
/// The bitmap makes this true where a bump allocator would not have. Worth an
/// assertion rather than an argument: leaking here would not fail anything
/// until a long-running module had run for a while.
fn smoke_domain_heap_frees_are_reusable() -> TestResult {
    use core::alloc::Layout;

    if !mte::supported() {
        return TestResult::Skip("no MTE on this CPU");
    }
    let d = DomainId::SCRATCH;
    let layout = Layout::from_size_align(256, 8).unwrap();
    let before = blocks_in_use(d);
    for _ in 0..64 {
        let Some(p) = alloc(layout, d) else {
            return TestResult::Fail("allocation failed inside the reuse loop");
        };
        // SAFETY: matched pair.
        unsafe { free(p, layout) };
    }
    let after = blocks_in_use(d);
    if after != before {
        return TestResult::Fail("64 alloc/free pairs did not return every block");
    }
    TestResult::Pass
}
kernel_test_in!("memory/domain_heap", smoke_domain_heap_frees_are_reusable);

/// An untagged pointer to a module allocation faults inside a domain scope.
///
/// The point of the whole file. Without it the tagging is bookkeeping: pages
/// marked Tagged Normal, granules carrying a tag, and nothing ever checking.
fn smoke_domain_heap_untagged_access_faults_in_scope() -> TestResult {
    use core::alloc::Layout;
    use core::arch::asm;
    use narf_arch::aarch64::probe;

    if !mte::supported() {
        return TestResult::Skip("no MTE on this CPU");
    }
    let d = DomainId::SCRATCH;
    let layout = Layout::from_size_align(64, 8).unwrap();
    let Some(p) = alloc(layout, d) else {
        return TestResult::Fail("domain_heap::alloc failed");
    };
    let plain = mte::with_tag(p as u64, mte::UNTAGGED_KERNEL_TAG);

    // Control: untagged access is fine while TCF is Ignore.
    // SAFETY: inside the allocation just made.
    let before = unsafe { core::ptr::read_volatile(plain as *const u64) };

    let caught = {
        let saved = {
            use narf_arch::DomainPrimitive;
            // SAFETY: MTE present; this scope touches only this allocation.
            unsafe { narf_arch::aarch64::Mte::enter_domain(DomainId::FRAME.raw(), d.raw()) }
        };
        let recovery: u64;
        // SAFETY: ADR of a local label.
        unsafe {
            asm!("adr {r}, 99f", r = out(reg) recovery, options(nostack, preserves_flags));
        }
        probe::arm(recovery);
        // SAFETY: expected to raise a synchronous tag check fault; the armed
        // probe redirects ELR_EL1 to `99:` rather than taking the fatal path.
        unsafe {
            asm!(
                "ldr {t}, [{q}]",
                "99:",
                q = in(reg) plain,
                t = out(reg) _,
                options(nostack),
            );
        }
        let c = probe::disarm();
        {
            use narf_arch::DomainPrimitive;
            // SAFETY: matched with the enter above.
            unsafe { narf_arch::aarch64::Mte::exit_domain(saved) };
        }
        c
    };

    // SAFETY: matched pair.
    unsafe { free(p, layout) };

    if !caught.fired {
        return TestResult::Fail("untagged access to a module allocation did not fault in scope");
    }
    const DFSC_TAG_CHECK: u64 = 0b01_0001;
    if caught.esr & 0x3F != DFSC_TAG_CHECK {
        return TestResult::Fail("the fault was not a synchronous tag check fault");
    }
    let _ = before;
    TestResult::Pass
}
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_untagged_access_faults_in_scope
);

//! Per-domain heap for module allocations.
//!
//! Module *images* carry their domain's MTE tag (`module_text`), so a pointer
//! into one derived from another domain faults. Their *allocations* did not:
//! `narf_kmalloc` returns ordinary kernel heap memory, which is plain Normal
//! and unchecked, so a module's buffers were reachable from every domain. This
//! closes that for the one allocation path modules have.
//!
//! # Two mechanisms, one shape
//!
//! aarch64 protects the region with MTE: pages are `ATTR_TAGGED`, granules
//! carry the domain's tag, and allocations come back as tagged pointers.
//! x86_64 protects it with PKS: pages carry `PtFlags::pk(D)` and `IA32_PKRS`
//! denies that key outside the domain's scope, so the pointer itself stays
//! ordinary. Same region layout, same allocator, same `owns`/`owner`
//! arithmetic — only how a page is made unreachable differs.
//!
//! Worth having in one file rather than two. The interesting parts — that the
//! owner is derived from the address, that windows are fixed-stride, that the
//! allocator's metadata is out of band — are properties of the design, not of
//! either mechanism, and they were getting restated per architecture
//! elsewhere in this tree.
//!
//! # Why not tag the kernel heap
//!
//! Because protection is per page while the enabling state is per CPU. Marking
//! the general heap `ATTR_TAGGED` (or `pk(D)`) would make ordinary kernel
//! accesses to heap memory inside a domain scope fault — and the kernel
//! touches the heap constantly inside those scopes. The protected set has to
//! stay bounded to memory whose every access the kernel controls, which is
//! what a dedicated region gives.
//!
//! # Why not reuse `slab`
//!
//! `slab` threads its free list through the objects themselves — it writes
//! `FreeBlock { next }` into freed memory. On aarch64 those writes come from
//! allocator code holding an untagged pointer, so over a tagged region every
//! free would fault. An allocator for protected memory must keep its metadata
//! *out of band*, which is why this is a bitmap rather than a free list.
//!
//! The x86 side could have tolerated inline metadata — a free running inside
//! the domain's own scope has `pk(D)` permitted — but only there, and only for
//! frees that happen in-scope. `free` deliberately does not require that, so
//! the bitmap is what makes both architectures behave the same way.
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

use core::alloc::Layout;

#[cfg(target_arch = "aarch64")]
use narf_arch::aarch64::mte;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// PML4 (x86_64) / L0 (aarch64) slot holding the per-domain heap. Above the
/// poke window (277).
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
    let a = canonical(ptr as u64);
    (HEAP_BASE..HEAP_BASE + (NUM_DOMAINS as u64) * DOMAIN_STRIDE).contains(&a)
}

/// An address with any MTE tag removed, so range checks and offsets do not
/// depend on which alias the caller happens to hold. Identity on x86, where
/// the protection lives in the PTE and the pointer is ordinary.
#[inline]
fn canonical(a: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        mte::with_tag(a, mte::UNTAGGED_KERNEL_TAG)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        a
    }
}

/// The domain owning `ptr`, or `None` when it is outside the region.
#[inline]
#[must_use]
pub fn owner(ptr: *const u8) -> Option<DomainId> {
    if !owns(ptr) {
        return None;
    }
    let a = canonical(ptr as u64);
    Some(DomainId::new(((a - HEAP_BASE) / DOMAIN_STRIDE) as u8))
}

/// Map `domain`'s window and give it the domain's protection.
///
/// # Safety
/// Caller holds the pool lock and has established the window is not mapped.
#[cfg(target_arch = "aarch64")]
unsafe fn map_window(domain: u8, key: u8) -> bool {
    use crate::aarch64::paging::PtFlags;
    let Some(root) = crate::bpf_text::kernel_root_for_mapping() else {
        return false;
    };
    let base = window_base(domain);
    // Tagged Normal, RW at EL1, never executable. `ATTR_TAGGED` replaces
    // `ATTR_NORMAL` rather than joining it: AttrIndx is a 3-bit field.
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN | PtFlags::ATTR_TAGGED;
    if !unsafe { map_run(root, base, flags) } {
        return false;
    }
    // Tag every granule AFTER mapping. Same ordering `bpf_arena` and
    // `module_text` need: a store through a non-tagged alias may leave a
    // granule's tag UNKNOWN, so tagging has to be the last write.
    let tagged = mte::with_tag(base, key);
    let mut off = 0u64;
    while off < DOMAIN_STRIDE {
        // SAFETY: inside the window just mapped RW at EL1.
        unsafe { mte::stg((tagged + off) as *mut u8) };
        off += 16;
    }
    true
}

/// x86_64: the domain travels in the leaf as a protection key, so there is no
/// second pass over the memory. `IA32_PKRS` denies key `D` outside `D`'s
/// scope, which is what makes another domain's access fault.
///
/// # Safety
/// Same as the aarch64 arm.
#[cfg(target_arch = "x86_64")]
unsafe fn map_window(domain: u8, key: u8) -> bool {
    use crate::x86_64::paging::PtFlags;
    let Ok(root) = kernel_root_x86() else {
        return false;
    };
    let flags = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_EXEC | PtFlags::pk(key);
    // SAFETY: forwarded.
    unsafe { map_run(root, window_base(domain), flags) }
}

/// The live kernel PML4, as `bpf_text` recorded it at boot.
#[cfg(target_arch = "x86_64")]
fn kernel_root_x86() -> Result<crate::PhysAddr, ()> {
    crate::bpf_text::kernel_root_for_mapping().ok_or(())
}

/// Map `DOMAIN_STRIDE` bytes of fresh frames at `base` with `flags`.
///
/// # Safety
/// `base` must name an unmapped run inside the reserved slot.
unsafe fn map_run(root: crate::PhysAddr, base: u64, flags: crate::paging::PtFlags) -> bool {
    let pages = (DOMAIN_STRIDE / 4096) as usize;
    for i in 0..pages {
        let Ok(frame) = crate::frame::alloc_frame() else {
            return false;
        };
        let va = crate::VirtAddr::new(base + (i as u64) * 4096);
        // SAFETY: `root` is the live kernel root, the slot was reserved at
        // boot, and `frame` is freshly allocated and exclusively ours.
        if unsafe { crate::paging::map_4kb(root, va, frame.start_address(), flags) }.is_err() {
            crate::frame::free_frame(frame);
            return false;
        }
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

/// Whether this CPU can protect the region at all. Without it every caller
/// must fall through to the ordinary heap.
#[inline]
fn protection_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        mte::supported()
    }
    #[cfg(target_arch = "x86_64")]
    {
        narf_arch::x86_64::pks::is_active()
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

/// The per-domain protection value: an MTE tag on aarch64, a PKS protection
/// key on x86. `None` for a domain that cannot be protected.
#[inline]
fn domain_key(domain: DomainId) -> Option<u8> {
    #[cfg(target_arch = "aarch64")]
    {
        // Must be the tag the domain's *image* carries: module code reaches
        // its buffers through pointers derived from that image.
        crate::module_text::domain_tag_of(domain)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // PKS has all sixteen keys available — no value is reserved the way
        // MTE's 15 is by untagged kernel pointers — so every domain including
        // FRAME gets its own. FRAME's key is 0, which `enter_domain` always
        // permits, so a FRAME allocation is reachable everywhere by design.
        Some(domain.raw())
    }
}

/// Turn a window offset into the pointer a caller should hold.
#[inline]
fn protected_ptr(va: u64, key: u8) -> *mut u8 {
    #[cfg(target_arch = "aarch64")]
    {
        mte::with_tag(va, key) as *mut u8
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // x86: protection is in the PTE, so the pointer is ordinary.
        let _ = key;
        va as *mut u8
    }
}

/// Allocate `layout` from `domain`'s window.
///
/// The pointer carries the domain's MTE tag on aarch64; on x86 it is an
/// ordinary address whose *page* carries the domain's protection key.
///
/// Returns `None` when MTE is off, the domain is untaggable, the request is
/// larger than a window, or the window is full — every one of which the caller
/// must treat as "use the ordinary heap", not as an error.
#[must_use]
pub fn alloc(layout: Layout, domain: DomainId) -> Option<*mut u8> {
    if !protection_available() {
        return None;
    }
    let key = domain_key(domain)?;
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
        if !unsafe { map_window(d, key) } {
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
        if let Some(i) = (start..start + need).find(|&i| bit(&pool.used, i)) {
            start = i + 1;
        } else {
            for i in start..start + need {
                set(&mut pool.used, i);
            }
            let va = window_base(d) + (start as u64) * BLOCK;
            return Some(protected_ptr(va, key));
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
    let a = canonical(ptr as u64);
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

/// An allocation belongs to its domain's window and is usable.
///
/// Arch-neutral: the window layout and owner arithmetic are properties of the
/// design, not of MTE or PKS. The mechanism-specific half — that the pointer
/// carries the domain's tag — is asserted on aarch64 only, because on x86 the
/// protection is in the PTE and the pointer is deliberately ordinary.
fn smoke_domain_heap_allocation_is_protected() -> TestResult {
    use core::alloc::Layout;

    if !protection_available() {
        return TestResult::Skip("no domain protection backend on this CPU");
    }
    let d = DomainId::SCRATCH;
    let Some(key) = domain_key(d) else {
        return TestResult::Fail("SCRATCH has no protection key");
    };
    let layout = Layout::from_size_align(128, 8).unwrap();
    let Some(p) = alloc(layout, d) else {
        return TestResult::Fail("domain_heap::alloc returned None for a small request");
    };
    let owned = owner(p).map(|o| o.raw()) == Some(d.raw());
    // SAFETY: 128 bytes just allocated to this domain.
    unsafe { core::ptr::write_volatile(p as *mut u64, 0x5EED_5EED) };
    // SAFETY: same allocation.
    let read = unsafe { core::ptr::read_volatile(p as *const u64) };

    #[cfg(target_arch = "aarch64")]
    let tag_ok = {
        // Must equal the tag the domain's *image* carries: module code reaches
        // its buffers through pointers derived from that image, so a heap
        // tagged differently would fault on memory it just allocated.
        mte::tag_of(p as u64) == key && crate::module_text::domain_tag_of(d) == Some(key)
    };
    #[cfg(not(target_arch = "aarch64"))]
    let tag_ok = {
        let _ = key;
        true
    };

    // SAFETY: matched pair.
    unsafe { free(p, layout) };

    if !owned {
        return TestResult::Fail("owner() did not attribute the allocation to its domain");
    }
    if read != 0x5EED_5EED {
        return TestResult::Fail("the allocation did not hold what was written");
    }
    if !tag_ok {
        return TestResult::Fail("allocation does not carry the domain's image tag");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_allocation_is_protected
);

/// Two domains' allocations land in different windows and get different keys.
fn smoke_domain_heap_domains_are_separated() -> TestResult {
    use core::alloc::Layout;

    if !protection_available() {
        return TestResult::Skip("no domain protection backend on this CPU");
    }
    let layout = Layout::from_size_align(64, 8).unwrap();
    let (a, b) = (DomainId::SCRATCH, DomainId::KEYS);
    let (Some(pa), Some(pb)) = (alloc(layout, a), alloc(layout, b)) else {
        return TestResult::Fail("domain_heap::alloc failed for one of two domains");
    };
    let distinct_windows = owner(pa) != owner(pb);
    let distinct_keys = domain_key(a) != domain_key(b);
    // SAFETY: matched pairs.
    unsafe {
        free(pa, layout);
        free(pb, layout);
    }
    if !distinct_windows {
        return TestResult::Fail("two domains' allocations landed in one window");
    }
    if !distinct_keys {
        return TestResult::Fail("two domains share a protection key");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_domains_are_separated
);

/// Freed blocks are reused, so a module allocating in a loop does not exhaust
/// its window.
///
/// Worth asserting rather than arguing: a bump allocator would satisfy every
/// other test in this file and leak until a long-running module ran out.
fn smoke_domain_heap_frees_are_reusable() -> TestResult {
    use core::alloc::Layout;

    if !protection_available() {
        return TestResult::Skip("no domain protection backend on this CPU");
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
    if blocks_in_use(d) != before {
        return TestResult::Fail("64 alloc/free pairs did not return every block");
    }
    TestResult::Pass
}
kernel_test_in!("memory/domain_heap", smoke_domain_heap_frees_are_reusable);

/// aarch64: an untagged pointer to a module allocation faults inside a domain
/// scope. Without this the tagging is bookkeeping.
#[cfg(target_arch = "aarch64")]
fn smoke_domain_heap_untagged_access_faults_in_scope() -> TestResult {
    use core::alloc::Layout;
    use core::arch::asm;
    use narf_arch::aarch64::probe;
    use narf_arch::DomainPrimitive;

    if !mte::supported() {
        return TestResult::Skip("no MTE on this CPU");
    }
    let d = DomainId::SCRATCH;
    let layout = Layout::from_size_align(64, 8).unwrap();
    let Some(p) = alloc(layout, d) else {
        return TestResult::Fail("domain_heap::alloc failed");
    };
    let plain = mte::with_tag(p as u64, mte::UNTAGGED_KERNEL_TAG);

    let caught = {
        // SAFETY: MTE present; this scope touches only this allocation.
        let saved =
            unsafe { narf_arch::aarch64::Mte::enter_domain(DomainId::FRAME.raw(), d.raw()) };
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
        // SAFETY: matched with the enter above.
        unsafe { narf_arch::aarch64::Mte::exit_domain(saved) };
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
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_untagged_access_faults_in_scope
);

/// x86_64: one domain's allocation is unreachable from inside another
/// domain's scope, because `IA32_PKRS` denies its protection key.
///
/// The PKS mirror of the aarch64 test above, and the same load-bearing
/// assertion: without it, `pk(D)` on the leaves is a field nothing consults.
/// Note the shape differs — MTE denies a *mismatched pointer*, PKS denies a
/// *key in the wrong scope* — so this enters a DIFFERENT domain's scope and
/// touches SCRATCH's memory, where the aarch64 test enters SCRATCH's own
/// scope and uses a wrong pointer.
#[cfg(target_arch = "x86_64")]
fn smoke_domain_heap_cross_domain_access_faults() -> TestResult {
    use core::alloc::Layout;
    use core::arch::asm;
    use narf_arch::x86_64::probe;
    use narf_arch::DomainPrimitive;

    if !narf_arch::x86_64::pks::is_active() {
        return TestResult::Skip("PKS not active on this CPU");
    }
    let owner_domain = DomainId::SCRATCH;
    let other = DomainId::KEYS;
    let layout = Layout::from_size_align(64, 8).unwrap();
    let Some(p) = alloc(layout, owner_domain) else {
        return TestResult::Fail("domain_heap::alloc failed");
    };

    // Control: reachable with PKRS all-allow, so a fault below is the key
    // being denied rather than the page being absent.
    // SAFETY: 64 bytes just allocated.
    unsafe { core::ptr::write_volatile(p as *mut u64, 0xA5A5_A5A5) };

    let caught = {
        // SAFETY: PKS is active; entering another domain's scope narrows PKRS
        // to FRAME + that domain, which must exclude SCRATCH's key.
        let saved =
            unsafe { narf_arch::x86_64::Pks::enter_domain(DomainId::FRAME.raw(), other.raw()) };
        let recovery: u64;
        // SAFETY: LEA of a local label.
        unsafe {
            asm!("lea {r}, [99f + rip]", r = out(reg) recovery, options(nostack, preserves_flags));
        }
        probe::arm(recovery);
        // SAFETY: expected to #PF on the protection key; the armed probe
        // redirects RIP to `99:` instead of taking the fatal path.
        unsafe {
            asm!(
                "mov {t}, qword ptr [{q}]",
                "99:",
                q = in(reg) p,
                t = out(reg) _,
                options(nostack),
            );
        }
        let c = probe::disarm();
        // SAFETY: matched with the enter above.
        unsafe { narf_arch::x86_64::Pks::exit_domain(saved) };
        c
    };

    // SAFETY: matched pair.
    unsafe { free(p, layout) };

    match caught.vector {
        Some(14) => TestResult::Pass,
        Some(_) => TestResult::Fail("a fault other than #PF was raised"),
        None => TestResult::Fail("another domain reached this domain's allocation"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/domain_heap",
    smoke_domain_heap_cross_domain_access_faults
);

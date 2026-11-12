//! `kstack` — virtually mapped kernel stacks with unmapped guards
//! (Linux `CONFIG_VMAP_STACK`).
//!
//! Spec: `memory/specification/spec.md` §3 (kernel stacks) and §4 (guard
//! invariant).
//!
//! A kernel task stack used to be a heap `Box<[u8]>`: an order-3 direct-map
//! block with live memory on both sides. A stack that grew past its base wrote
//! into whatever frame sat below it — a free frame, a slab page, another
//! stack — and the damage surfaced later, somewhere else. Linux closed the same
//! hole with `CONFIG_VMAP_STACK` (2016): stacks live in vmalloc space, the page
//! below each one is never mapped, and an overflow is a page fault on that
//! page, reported by the double-fault handler on its own IST stack.
//!
//! NARF does the same in a dedicated top-level slot ([`KSTACK_L0_SLOT`]):
//!
//! ```text
//!   window base                                          (randomized, 2 MiB)
//!   │ slot 0: never allocated — the guard below slot 1          │
//!   │ slot k: [ stack (≤ 128 KiB, mapped) | unmapped to slot end ] │
//!   │ slot k+1: …                                                │
//! ```
//!
//! Every slot is [`KSTACK_SLOT_BYTES`] (256 KiB) and 256 KiB aligned; a stack
//! occupies the *bottom* of its slot. So below every stack lie at least
//! [`KSTACK_MAX_BYTES`] of unmapped VA (the upper half of the slot under it),
//! and above it the rest of its own slot. Two consequences are load-bearing:
//!
//! * x86_64: any write below a stack's base faults, whatever the frame size —
//!   Rust's inline stack probes touch every page of a large frame, and the
//!   first page below the base is always unmapped. The fault arrives as #PF or,
//!   when the push of the exception frame itself faults, as #DF on its IST
//!   stack; both consult [`guard_hit`].
//! * aarch64: the exception entry has no hardware stack switch, so it must
//!   check the stack pointer before it stores anything. A stack pointer inside
//!   a stack has bit [`KSTACK_SHIFT`] clear (the stack is in the lower half of a
//!   256 KiB-aligned slot); one that has run off the bottom is in the upper half
//!   of the slot below, where the bit is set. `vec.S` tests exactly that, for
//!   stack pointers in this slot only (Linux's `THREAD_ALIGN` test, scoped to
//!   the stacks that have the alignment).
//!
//! The page-table entries for the slot are installed at boot before the first
//! user address space copies the kernel half (`bpf_text::reserve_kernel_slots`),
//! so the leaves are shared by every address space, exactly like vmalloc's.
//! Leaves are non-global and non-executable with the same flags as `valloc`
//! (protection key 0 on x86_64, identical to the direct-map heap pages the
//! stacks used to be): mapping a stack here changes no domain's rights.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, PhysFrame, VirtAddr};

/// Top-level (PML4 / L0) slot holding every kernel stack. Free in both
/// arches' layouts: see the slot map in `bpf_text.rs` (273..=278 taken,
/// 279..=383 free).
pub const KSTACK_L0_SLOT: usize = 279;

/// Base of the slot (`KSTACK_L0_SLOT << 39`, sign-extended).
const KSTACK_SLOT_VA: u64 = 0xFFFF_8B80_0000_0000;
const _: () = assert!(((KSTACK_SLOT_VA >> 39) & 0x1FF) as usize == KSTACK_L0_SLOT);

/// log2 of [`KSTACK_MAX_BYTES`]: the bit the aarch64 entry tests.
pub const KSTACK_SHIFT: u32 = 17;
/// Largest stack this area hands out.
pub const KSTACK_MAX_BYTES: usize = 1 << KSTACK_SHIFT;
/// VA per stack: the stack plus at least `KSTACK_MAX_BYTES` of guard.
pub const KSTACK_SLOT_BYTES: u64 = 2 << KSTACK_SHIFT;

/// VA the area spans: 65536 slots, i.e. that many simultaneous stacks.
const AREA_BYTES: u64 = 16 << 30;
const SLOTS: usize = (AREA_BYTES / KSTACK_SLOT_BYTES) as usize;
const WORDS: usize = SLOTS / 64;

/// Live base of the area, 0 before it is chosen.
static AREA_BASE: AtomicU64 = AtomicU64::new(0);
/// Set by the first allocation; the base cannot move after it.
static AREA_FROZEN: AtomicBool = AtomicBool::new(false);

/// Mapped pages of each slot's stack, 0 = free. Written under `MAP` (alloc)
/// or by the owner (free); read lock-free by the fault path.
static PAGES: [AtomicU8; SLOTS] = [const { AtomicU8::new(0) }; SLOTS];

/// Allocation bitmap (bit set = slot in use) plus a rotating search hint.
struct SlotMap {
    words: [u64; WORDS],
    hint: usize,
}

static MAP: IrqSafeSpinLock<SlotMap> = IrqSafeSpinLock::new(SlotMap {
    // Slot 0 is permanently reserved: it is the guard under slot 1.
    words: {
        let mut w = [0u64; WORDS];
        w[0] = 1;
        w
    },
    hint: 1,
});

impl SlotMap {
    fn take(&mut self) -> Option<usize> {
        let start = self.hint / 64;
        for step in 0..WORDS {
            let wi = (start + step) % WORDS;
            let w = self.words[wi];
            if w != u64::MAX {
                let bit = (!w).trailing_zeros() as usize;
                self.words[wi] |= 1 << bit;
                let slot = wi * 64 + bit;
                self.hint = slot + 1;
                return Some(slot);
            }
        }
        None
    }
    fn put(&mut self, slot: usize) {
        self.words[slot / 64] &= !(1u64 << (slot % 64));
    }
}

/// Base of the area in force (the fixed default until one is chosen).
#[inline]
pub fn area_base() -> u64 {
    match AREA_BASE.load(Ordering::Acquire) {
        0 => KSTACK_SLOT_VA,
        b => b,
    }
}

/// Choose this boot's area base inside the slot, before the first stack.
///
/// 2 MiB granularity like the vmalloc and module windows. A no-op once any
/// stack exists or when entropy is unavailable.
pub fn randomize_window() {
    const GRAN: u64 = 2 << 20;
    const SLOT_SPAN: u64 = 1 << 39;
    if AREA_FROZEN.load(Ordering::Acquire) {
        return;
    }
    let choices = (SLOT_SPAN - AREA_BYTES) / GRAN + 1;
    let (r, src) = crate::kaslr::random_u64();
    if src == crate::kaslr::EntropySource::TscMix && r == 0 {
        return;
    }
    AREA_BASE.store(KSTACK_SLOT_VA + (r % choices) * GRAN, Ordering::Release);
}

/// Whether `addr` lies anywhere in the kernel-stack area.
#[inline]
pub fn area_contains(addr: u64) -> bool {
    let base = area_base();
    addr >= base && addr - base < AREA_BYTES
}

/// The stack whose guard `addr` lies in, as the fault path reports it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GuardHit {
    /// Lowest byte of the overflowed stack.
    pub stack_base: u64,
    /// One past its highest byte.
    pub stack_top: u64,
}

/// Classify a faulting address. `Some` when `addr` is unmapped guard VA lying
/// directly below a live stack — i.e. that stack overflowed into it. Lock-free
/// and allocation-free: called from #PF / #DF / the aarch64 bad-stack path.
pub fn guard_hit(addr: u64) -> Option<GuardHit> {
    if !area_contains(addr) {
        return None;
    }
    let base = area_base();
    let off = addr - base;
    let slot = (off / KSTACK_SLOT_BYTES) as usize;
    let within = off % KSTACK_SLOT_BYTES;
    let mapped = PAGES[slot].load(Ordering::Acquire) as u64 * 4096;
    if within < mapped {
        return None; // inside a live stack: not a guard
    }
    // Unmapped part of `slot`: the guard under the stack of the next slot.
    let owner = slot + 1;
    if owner >= SLOTS {
        return None;
    }
    let pages = PAGES[owner].load(Ordering::Acquire) as u64;
    if pages == 0 {
        return None;
    }
    let stack_base = base + owner as u64 * KSTACK_SLOT_BYTES;
    Some(GuardHit {
        stack_base,
        stack_top: stack_base + pages * 4096,
    })
}

/// Bounds of the live stack containing `addr`, if any.
pub fn stack_containing(addr: u64) -> Option<(u64, u64)> {
    if !area_contains(addr) {
        return None;
    }
    let base = area_base();
    let slot = ((addr - base) / KSTACK_SLOT_BYTES) as usize;
    let pages = PAGES[slot].load(Ordering::Acquire) as u64;
    let lo = base + slot as u64 * KSTACK_SLOT_BYTES;
    (pages != 0 && addr < lo + pages * 4096).then_some((lo, lo + pages * 4096))
}

/// Live stacks, diagnostic only.
pub fn live_stacks() -> usize {
    let m = MAP.lock();
    m.words
        .iter()
        .map(|w| w.count_ones() as usize)
        .sum::<usize>()
        - 1
}

/// Leaf flags: identical to `vmalloc::valloc`'s (writable, never executable,
/// non-global because the leaf is unmapped at runtime, protection key 0).
#[inline]
fn leaf_flags() -> crate::paging::PtFlags {
    use crate::paging::PtFlags;
    #[cfg(target_arch = "x86_64")]
    {
        PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_EXEC
    }
    #[cfg(target_arch = "aarch64")]
    {
        PtFlags::AP_RW_EL1 | PtFlags::ATTR_NORMAL | PtFlags::UXN | PtFlags::PXN
    }
}

/// One kernel stack: `len` bytes of zeroed, virtually contiguous memory with
/// unmapped guard VA below (≥ 128 KiB) and above (the rest of its slot).
///
/// Moving a `KernelStack` moves only its handle — the mapping "travels" with
/// it, which is what lets the scheduler's stack cache recycle it. Dropping it
/// unmaps the pages (global invalidation), frees the frames and the slot.
pub struct KernelStack {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: a `KernelStack` uniquely owns its mapping; the handle is a pointer
// and a length, with no thread affinity.
unsafe impl Send for KernelStack {}
// SAFETY: shared access is read-only through `Deref`.
unsafe impl Sync for KernelStack {}

impl core::fmt::Debug for KernelStack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KernelStack[{:#x}+{:#x}]", self.base(), self.len)
    }
}

impl Default for KernelStack {
    fn default() -> Self {
        Self::empty()
    }
}

/// Why a stack could not be allocated.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KstackError {
    /// Zero, or more than [`KSTACK_MAX_BYTES`].
    BadLen,
    /// The area is not reserved yet (`bpf_text::reserve_kernel_slots`).
    NoRoot,
    /// Every slot is in use.
    NoSlot,
    /// The frame allocator or a page-table allocation failed.
    NoMemory,
}

impl KernelStack {
    /// The non-allocating placeholder (`len() == 0`); dropping it is a no-op.
    pub const fn empty() -> Self {
        Self {
            base: NonNull::dangling(),
            len: 0,
        }
    }

    /// Allocate a zeroed `len`-byte stack (`0 < len ≤ KSTACK_MAX_BYTES`).
    pub fn alloc(len: usize) -> Result<Self, KstackError> {
        if len == 0 || len > KSTACK_MAX_BYTES {
            return Err(KstackError::BadLen);
        }
        let root = crate::bpf_text::kernel_root_for_mapping().ok_or(KstackError::NoRoot)?;
        AREA_FROZEN.store(true, Ordering::Release);
        let pages = len.div_ceil(4096);
        let slot = MAP.lock().take().ok_or(KstackError::NoSlot)?;
        let base = area_base() + slot as u64 * KSTACK_SLOT_BYTES;
        for i in 0..pages {
            let frame = match crate::frame::alloc_frame() {
                Ok(f) => f,
                Err(_) => {
                    // SAFETY: the first `i` pages were mapped below.
                    unsafe { unmap_pages(root, base, i) };
                    MAP.lock().put(slot);
                    return Err(KstackError::NoMemory);
                }
            };
            let phys = frame.start_address();
            // SAFETY: fresh, exclusively owned frame; zero it through the
            // direct map before it becomes reachable through the stack VA.
            unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
            let va = VirtAddr::new(base + i as u64 * 4096);
            // SAFETY: `va` is in the reserved kernel-stack slot, in a slot this
            // call owns and whose pages are unmapped; `phys` is ours.
            if unsafe { crate::paging::map_4kb(root, va, phys, leaf_flags()) }.is_err() {
                crate::frame::free_frame(frame);
                // SAFETY: the first `i` pages were mapped above.
                unsafe { unmap_pages(root, base, i) };
                MAP.lock().put(slot);
                return Err(KstackError::NoMemory);
            }
        }
        // Publish the extent only once every page is mapped: the fault path
        // never reports a half-built stack.
        PAGES[slot].store(pages as u8, Ordering::Release);
        Ok(Self {
            // SAFETY: area addresses are non-null kernel VA.
            base: unsafe { NonNull::new_unchecked(base as *mut u8) },
            len,
        })
    }

    /// Lowest byte.
    #[inline]
    pub fn base(&self) -> u64 {
        self.base.as_ptr() as u64
    }
    /// One past the highest byte.
    #[inline]
    pub fn top(&self) -> u64 {
        self.base() + self.len as u64
    }
    /// Usable bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether this is the empty placeholder.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::ops::Deref for KernelStack {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `len` bytes from `base` are mapped and owned by `self`
        // (dangling + 0 for the placeholder, which is a valid empty slice).
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.len) }
    }
}

impl core::ops::DerefMut for KernelStack {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `Deref`; `&mut self` is the unique owner.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        let base = self.base();
        let slot = ((base - area_base()) / KSTACK_SLOT_BYTES) as usize;
        PAGES[slot].store(0, Ordering::Release);
        if let Some(root) = crate::bpf_text::kernel_root_for_mapping() {
            // SAFETY: `alloc` mapped exactly these pages; the owner is being
            // dropped, so nothing runs on or references the stack any more.
            unsafe { unmap_pages(root, base, self.len.div_ceil(4096)) };
        }
        MAP.lock().put(slot);
    }
}

/// Unmap and free `count` pages from `base`, then any page table the range
/// left empty.
///
/// # Safety
/// The pages must have been mapped by [`KernelStack::alloc`] and be unused.
unsafe fn unmap_pages(root: PhysAddr, base: u64, count: usize) {
    for i in 0..count {
        let va = VirtAddr::new(base + i as u64 * 4096);
        // SAFETY: forwarded; `unmap_4kb` performs the global invalidation.
        if let Ok(phys) = unsafe { crate::paging::unmap_4kb(root, va) } {
            if phys.raw() != 0 {
                crate::frame::free_frame(PhysFrame::new(phys));
            }
        }
    }
    if count != 0 {
        // SAFETY: every leaf above was unmapped and flushed; a table still
        // holding another stack's leaves is kept by `free_empty_pt`.
        let _ = unsafe { crate::paging::free_empty_pt(root, VirtAddr::new(base & !0x1F_FFFF)) };
    }
}

// ── tests ─────────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn mapped(va: u64) -> bool {
    let Some(root) = crate::bpf_text::kernel_root_for_mapping() else {
        return false;
    };
    // SAFETY: read-only walk of the live kernel root.
    unsafe { crate::paging::translate(root, VirtAddr::new(va)) }.is_some()
}

/// A stack is mapped, zeroed, slot-aligned, and has unmapped guards on both
/// sides; `guard_hit` attributes the page below it to it and nothing else.
fn smoke_kstack_guards_and_lookup() -> TestResult {
    let mut s = match KernelStack::alloc(32 * 1024) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("alloc"),
    };
    let base = s.base();
    if (base - area_base()) % KSTACK_SLOT_BYTES != 0 || base & (1 << KSTACK_SHIFT) != 0 {
        return TestResult::Fail("stack not at the bottom of an aligned slot");
    }
    if s.iter().any(|&b| b != 0) {
        return TestResult::Fail("fresh stack not zeroed");
    }
    let last = s.len() - 1;
    s[0] = 1;
    s[last] = 2;
    if !mapped(base) || !mapped(s.top() - 1) {
        return TestResult::Fail("stack page unmapped");
    }
    if mapped(base - 8) || mapped(base - KSTACK_MAX_BYTES as u64) || mapped(s.top()) {
        return TestResult::Fail("guard page mapped");
    }
    let hit = guard_hit(base - 8);
    if hit
        != Some(GuardHit {
            stack_base: base,
            stack_top: s.top(),
        })
    {
        return TestResult::Fail("guard below not attributed");
    }
    if guard_hit(base + 64).is_some() || guard_hit(0xFFFF_8000_0000_0000).is_some() {
        return TestResult::Fail("non-guard address classified as guard");
    }
    if stack_containing(base + 100) != Some((base, s.top())) {
        return TestResult::Fail("stack_containing");
    }
    // The bit the aarch64 entry tests: clear inside, set just below.
    if (s.top() - 16) & (1 << KSTACK_SHIFT) != 0 || (base - 16) & (1 << KSTACK_SHIFT) == 0 {
        return TestResult::Fail("overflow bit does not separate stack from guard");
    }
    drop(s);
    if mapped(base) || guard_hit(base - 8).is_some() {
        return TestResult::Fail("freed stack still mapped / attributed");
    }
    TestResult::Pass
}
kernel_test_in!("memory/kstack", smoke_kstack_guards_and_lookup);

/// Alloc/free churn returns every slot and frame (no VA or frame leak), and
/// sizes outside (0, 128 KiB] are refused.
fn smoke_kstack_churn_reclaims() -> TestResult {
    if KernelStack::alloc(0).is_ok() || KernelStack::alloc(KSTACK_MAX_BYTES + 1).is_ok() {
        return TestResult::Fail("bad length accepted");
    }
    let live = live_stacks();
    for _ in 0..4 {
        let mut v = alloc::vec::Vec::new();
        for i in 0..64 {
            let len = [4096, 16 * 1024, 32 * 1024, KSTACK_MAX_BYTES][i % 4];
            match KernelStack::alloc(len) {
                Ok(s) => v.push(s),
                Err(_) => return TestResult::Fail("alloc under churn"),
            }
        }
        drop(v);
    }
    if live_stacks() != live {
        return TestResult::Fail("slots leaked");
    }
    TestResult::Pass
}
kernel_test_in!("memory/kstack", smoke_kstack_churn_reclaims);

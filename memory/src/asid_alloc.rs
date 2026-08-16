//! Per-domain ASID / PCID allocator.
//!
//! Spec: `memory/specification/asid-pcid-isolation.md` §2.
//!
//! Generation-tagged mapping from `DomainId` to a hardware tag, plus
//! lifetime-scoped process ASIDs on aarch64. Domain and process partitions are
//! disjoint; a process tag is not reusable until a system-wide tag
//! invalidation completes.

#![allow(dead_code)]

#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::AtomicU16;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// Number of NARF driver domains (matches `narf_lib::id::DomainId`).
pub const N_DOMAINS: usize = 16;

/// Reserved tag value: 0 means "no tag" / bootstrap state.
pub const TAG_RESERVED: u16 = 0;

#[derive(Copy, Clone, Debug, Default)]
pub struct DomainTag {
    pub tag: u16,
    /// Generation this tag was allocated in. The current
    /// `current_generation()` must match for the tag to be live.
    pub generation: u64,
}

impl DomainTag {
    pub const RESERVED: Self = Self {
        tag: TAG_RESERVED,
        generation: 0,
    };
}

#[cfg(target_arch = "x86_64")]
const MAX_TAG: u16 = 0xFFF; // 12-bit PCID

#[cfg(target_arch = "aarch64")]
fn max_tag_runtime() -> u16 {
    // SAFETY: `MRS` from `ID_AA64MMFR0_EL1` is a read of an
    // architecturally-defined feature ID register, always legal at
    // EL1 with no side effects; `nomem`/`nostack` hold and the only
    // output is the register value moved into `v`.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // SAFETY: Valid memory or trusted environment
    let bits = unsafe {
        let v: u64;
        core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack));
        if (v >> 4) & 0xF == 2 {
            16u8
        } else {
            8u8
        }
    };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    if bits == 16 {
        0xFFFF
    } else {
        0xFF
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const MAX_TAG: u16 = 0xFF;

/// Per-domain tag table. Initialised lazily.
static TAGS: IrqSafeSpinLock<[DomainTag; N_DOMAINS]> = IrqSafeSpinLock::new(
    [DomainTag {
        tag: TAG_RESERVED,
        generation: 0,
    }; N_DOMAINS],
);

/// Monotonic generation counter. Bumps on rollover.
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Boot initialization is one-shot: resetting live process tags would permit
/// stale-tag reuse. Kernel tests use the explicit reset hook below.
/// Values: 0 = uninitialized, 1 = initialization in progress, 2 = ready.
static INIT_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(not(target_arch = "aarch64"))]
static NEXT_TAG: AtomicU16 = AtomicU16::new(1);

// Domain roots permanently occupy tags 1..=16. Process address spaces use the
// remainder of the architectural namespace, so the two root classes can never
// cache different translations under the same live tag.
#[cfg(target_arch = "aarch64")]
const PROCESS_ASID_FIRST: u16 = N_DOMAINS as u16 + 1;
#[cfg(target_arch = "aarch64")]
const ASID_BITMAP_WORDS: usize = 1024; // complete 16-bit ASID namespace

#[cfg(target_arch = "aarch64")]
struct ProcessAsidState {
    used: [u64; ASID_BITMAP_WORDS],
    cursor: u16,
}

#[cfg(target_arch = "aarch64")]
impl ProcessAsidState {
    const fn new() -> Self {
        Self {
            used: [0; ASID_BITMAP_WORDS],
            cursor: PROCESS_ASID_FIRST,
        }
    }
}

#[cfg(target_arch = "aarch64")]
static PROCESS_ASIDS: IrqSafeSpinLock<ProcessAsidState> =
    IrqSafeSpinLock::new(ProcessAsidState::new());
#[cfg(target_arch = "aarch64")]
static PROCESS_CONTEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Initialise the allocator once, before any tagged address space is created.
/// Later calls are no-ops so they cannot reset live process-ASID ownership.
pub fn allocator_init() {
    match INIT_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            reset_all_state();
            INIT_STATE.store(2, Ordering::Release);
        }
        Err(1) => {
            while INIT_STATE.load(Ordering::Acquire) != 2 {
                core::hint::spin_loop();
            }
        }
        Err(2) => {}
        Err(_) => unreachable!(),
    }
}

fn reset_domain_state() {
    GENERATION.store(1, Ordering::Release);
    #[cfg(not(target_arch = "aarch64"))]
    NEXT_TAG.store(1, Ordering::Release);
    let mut t = TAGS.lock();
    for slot in t.iter_mut() {
        *slot = DomainTag {
            tag: TAG_RESERVED,
            generation: 0,
        };
    }
}

fn reset_all_state() {
    reset_domain_state();
    #[cfg(target_arch = "aarch64")]
    {
        *PROCESS_ASIDS.lock() = ProcessAsidState::new();
        PROCESS_CONTEXT_GENERATION.store(1, Ordering::Release);
    }
}

/// Current generation.
pub fn current_generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

#[cfg(target_arch = "x86_64")]
fn arch_max_tag() -> u16 {
    MAX_TAG
}

#[cfg(target_arch = "aarch64")]
fn arch_max_tag() -> u16 {
    max_tag_runtime()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn arch_max_tag() -> u16 {
    MAX_TAG
}

/// Allocate (or refresh) the tag for `domain`. Returns the
/// `DomainTag` valid in the current generation.
pub fn alloc(domain: DomainId) -> DomainTag {
    allocator_init();
    let gen_now = current_generation();
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS {
        return DomainTag {
            tag: TAG_RESERVED,
            generation: gen_now,
        };
    }
    {
        let g = TAGS.lock();
        let cur = g[idx];
        if cur.generation == gen_now && cur.tag != TAG_RESERVED {
            return cur;
        }
    }
    // aarch64 domain tags are stable and permanently disjoint from process
    // ASIDs. Other architectures retain the existing generation allocator.
    #[cfg(target_arch = "aarch64")]
    let tag = idx as u16 + 1;
    #[cfg(not(target_arch = "aarch64"))]
    let tag = {
        let max = arch_max_tag();
        let mut tag = NEXT_TAG.fetch_add(1, Ordering::AcqRel);
        if tag > max {
            rollover_now();
            tag = NEXT_TAG.fetch_add(1, Ordering::AcqRel);
        }
        tag
    };
    let issued = DomainTag {
        tag,
        generation: current_generation(),
    };
    let mut g = TAGS.lock();
    g[idx] = issued;
    issued
}

/// Look up the cached tag for `domain` without allocating. Returns
/// `None` if the cached entry is stale (different generation) or
/// unallocated.
pub fn cached(domain: DomainId) -> Option<DomainTag> {
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS {
        return None;
    }
    let g = TAGS.lock();
    let cur = g[idx];
    if cur.tag == TAG_RESERVED {
        return None;
    }
    if cur.generation != current_generation() {
        return None;
    }
    Some(cur)
}

/// x86_64 alias.
#[cfg(target_arch = "x86_64")]
pub fn pcid_for(domain: DomainId) -> u16 {
    alloc(domain).tag
}

/// aarch64 alias.
#[cfg(target_arch = "aarch64")]
pub fn asid_for(domain: DomainId) -> u16 {
    alloc(domain).tag
}

/// Force a rollover: every cached tag becomes stale, the global
/// counter bumps, and a global TLB flush is requested. The actual
/// flush is the caller's job (it depends on which arch primitive
/// is reachable from this scope).
pub fn rollover_now() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    #[cfg(not(target_arch = "aarch64"))]
    NEXT_TAG.store(1, Ordering::Release);
    let mut g = TAGS.lock();
    for slot in g.iter_mut() {
        *slot = DomainTag {
            tag: TAG_RESERVED,
            generation: 0,
        };
    }
}

/// Allocate one lifetime-scoped ASID for a process address space.
///
/// Tags 1..=16 are permanently reserved for domain roots. A process tag is
/// removed from the bitmap only after [`release_process_asid`] has invalidated
/// it across the inner-shareable domain. Exhaustion returns ASID 0, whose
/// caller must use the flushing switch path.
#[cfg(target_arch = "aarch64")]
pub(crate) fn allocate_process_asid() -> DomainTag {
    allocator_init();
    let max = arch_max_tag();
    if max < PROCESS_ASID_FIRST {
        return DomainTag::RESERVED;
    }
    let mut state = PROCESS_ASIDS.lock();
    let candidates = max as usize - PROCESS_ASID_FIRST as usize + 1;
    for _ in 0..candidates {
        let tag = state.cursor;
        state.cursor = if tag == max {
            PROCESS_ASID_FIRST
        } else {
            tag + 1
        };
        let word = tag as usize / 64;
        let bit = 1u64 << (tag as usize % 64);
        if state.used[word] & bit != 0 {
            continue;
        }
        state.used[word] |= bit;
        let generation = PROCESS_CONTEXT_GENERATION.fetch_add(1, Ordering::AcqRel);
        return DomainTag { tag, generation };
    }
    DomainTag::RESERVED
}

/// Retire a process ASID and make it available for safe reuse.
///
/// The caller must prove that no CPU can still execute the owning address
/// space. `AddressSpace::drop` provides that proof through last-`Arc`
/// ownership. Invalidation happens before the bitmap bit is cleared, so an
/// allocator cannot reissue the tag while stale translations remain.
#[cfg(target_arch = "aarch64")]
pub(crate) fn release_process_asid(context: DomainTag) {
    if context.tag < PROCESS_ASID_FIRST || context.tag > arch_max_tag() {
        return;
    }
    // SAFETY: the tag was allocated from the architectural ASID range and the
    // last AddressSpace owner guarantees it can no longer be repopulated.
    unsafe { narf_arch::aarch64::sysreg::tlbi_asid_inner_shareable(context.tag) };
    let mut state = PROCESS_ASIDS.lock();
    let word = context.tag as usize / 64;
    let bit = 1u64 << (context.tag as usize % 64);
    state.used[word] &= !bit;
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn process_asid_live_for_test(tag: u16) -> bool {
    if tag < PROCESS_ASID_FIRST || tag > arch_max_tag() {
        return false;
    }
    let state = PROCESS_ASIDS.lock();
    state.used[tag as usize / 64] & (1u64 << (tag as usize % 64)) != 0
}

/// Invalidate the cached tag for `domain`. The next `alloc(domain)`
/// will issue a fresh one. Useful when a domain's address space
/// has been torn down.
pub fn invalidate_tag(domain: DomainId) {
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS {
        return;
    }
    let mut g = TAGS.lock();
    #[cfg(target_arch = "aarch64")]
    if g[idx].tag != TAG_RESERVED {
        // SAFETY: the tag came from the architectural domain-tag partition.
        // Holding TAGS prevents reissue until the broadcast invalidation has
        // completed.
        unsafe { narf_arch::aarch64::sysreg::tlbi_asid_inner_shareable(g[idx].tag) };
    }
    g[idx] = DomainTag {
        tag: TAG_RESERVED,
        generation: 0,
    };
}

#[doc(hidden)]
pub fn __reset_for_test() {
    // Domain-allocation tests may run while another test-owned AddressSpace is
    // still retained by a scheduler/global registry. Never reset process-ASID
    // ownership here: doing so could reissue a live tag without retirement.
    reset_domain_state();
    INIT_STATE.store(2, Ordering::Release);
}

//! Per-domain ASID / PCID allocator.
//!
//! Spec: `memory/specification/asid-pcid-isolation.md` §2.
//!
//! Generation-tagged mapping from `DomainId` to a hardware tag.
//! When the architectural tag space is exhausted (12-bit on
//! x86_64, 8/16-bit on aarch64), the generation counter bumps
//! and every per-domain root must be re-tagged with a fresh
//! value before use; a tag-scoped TLBI / INVPCID precedes the
//! next use.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

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

#[cfg(target_arch = "x86_64")]
const MAX_TAG: u16 = 0xFFF; // 12-bit PCID

#[cfg(target_arch = "aarch64")]
fn max_tag_runtime() -> u16 {
    let bits = unsafe {
        // narf-arch dependency would create a cycle; read directly.
        let v: u64;
        core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack));
        if (v >> 4) & 0xF == 2 {
            16u8
        } else {
            8u8
        }
    };
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

/// Next free tag in the current generation.
static NEXT_TAG: AtomicU16 = AtomicU16::new(1);

/// Initialise the allocator. Idempotent.
pub fn allocator_init() {
    GENERATION.store(1, Ordering::Release);
    NEXT_TAG.store(1, Ordering::Release);
    let mut t = TAGS.lock();
    for slot in t.iter_mut() {
        *slot = DomainTag {
            tag: TAG_RESERVED,
            generation: 0,
        };
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
    // Need a fresh tag.
    let max = arch_max_tag();
    let mut tag = NEXT_TAG.fetch_add(1, Ordering::AcqRel);
    if tag > max {
        // Rollover.
        rollover_now();
        tag = NEXT_TAG.fetch_add(1, Ordering::AcqRel);
    }
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
    NEXT_TAG.store(1, Ordering::Release);
    let mut g = TAGS.lock();
    for slot in g.iter_mut() {
        *slot = DomainTag {
            tag: TAG_RESERVED,
            generation: 0,
        };
    }
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
    g[idx] = DomainTag {
        tag: TAG_RESERVED,
        generation: 0,
    };
}

#[doc(hidden)]
pub fn __reset_for_test() {
    allocator_init();
}

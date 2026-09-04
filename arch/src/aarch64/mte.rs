//! aarch64 MTE (Memory Tagging Extension) implementation.
//!
//! aarch64 MTE implements domain isolation via pointer tags and granule
//! tags. The `DomainPrimitive` trait on aarch64 manages the Tag Check
//! Fault (TCF) mode and TBI/ATA configuration.
//!
//! References (clean-room, public-spec only):
//!   * ARM DDI0487 D6.2 — Tagged addresses (TBI / logical-tag field).
//!   * ARM DDI0487 D6.5 — Allocation tags (granule tags in tag storage).
//!   * ARM DDI0487 C6.2.{IRG, STG, LDG, GMI} — instruction encodings.
//!   * Arm "Memory Tagging Extension" whitepaper (public).

use crate::aarch64::sysreg;
use core::arch::asm;
use core::fmt;

/// Saved MTE state.
///
/// Stage 2 saves both `SCTLR_EL1` (the TCF mode + ATA bit) and
/// `GCR_EL1` (the random-tag seed + exclusion list used by `IRG`).
/// `GCR_EL1` access requires MTE level ≥ 2 and `SCTLR_EL1.ATA = 1`
/// — both established at boot in `frame/aarch64/boot.S`. On CPUs
/// without MTE, calling save/restore would #UD, so the caller must
/// gate on `Features::probe().mte >= 2` (the probe is already the
/// boot-path gate for enabling ATA).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SavedMteState {
    pub sctlr: u64,
    pub gcr: u64,
}

/// Per-domain access rights. On aarch64 MTE, "rights" are enforced via
/// page-table AP bits for R/W vs RO, and tag-match for access-deny.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct DomainRights {
    pub no_write: bool,
    pub no_access: bool,
}

impl DomainRights {
    pub const ALLOW_ALL: Self = Self {
        no_write: false,
        no_access: false,
    };
    pub const READ_ONLY: Self = Self {
        no_write: true,
        no_access: false,
    };
    pub const DENY_ALL: Self = Self {
        no_write: true,
        no_access: true,
    };
}

impl fmt::Display for DomainRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.no_access, self.no_write) {
            (true, _) => f.write_str("deny"),
            (false, true) => f.write_str("r-"),
            (false, false) => f.write_str("rw"),
        }
    }
}

/// aarch64's concrete `DomainPrimitive` type.
#[derive(Debug)]
pub struct Mte;

impl crate::DomainPrimitive for Mte {
    const BACKEND: crate::DomainBackend = crate::DomainBackend::Mte;
    type SavedState = SavedMteState;
    type Rights = DomainRights;

    const ALLOW_ALL: DomainRights = DomainRights::ALLOW_ALL;
    const READ_ONLY: DomainRights = DomainRights::READ_ONLY;
    const DENY_ALL: DomainRights = DomainRights::DENY_ALL;

    #[inline]
    unsafe fn save() -> Self::SavedState {
        // SAFETY: MRS SCTLR_EL1 always legal; MRS GCR_EL1 legal once
        // SCTLR_EL1.ATA=1 (set at boot when MTE is present).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            SavedMteState {
                sctlr: sysreg::read_sctlr_el1(),
                gcr: sysreg::read_gcr_el1(),
            }
        }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        // SAFETY: see `save`; MSR is the reverse.
        unsafe {
            sysreg::write_sctlr_el1(s.sctlr);
            sysreg::write_gcr_el1(s.gcr);
        }
    }

    #[inline]
    unsafe fn get_rights(_domain: u8) -> Self::Rights {
        // MTE doesn't have a per-tag rights register. DomainRights are
        // established at mapping time via AP bits.
        DomainRights::ALLOW_ALL
    }

    #[inline]
    unsafe fn set_rights(_domain: u8, _rights: Self::Rights) {
        // No-op on aarch64 MTE; see design notes.
    }

    #[inline]
    unsafe fn enter_domain(_kernel_domain: u8, _driver_domain: u8) -> Self::SavedState {
        // Stage-2 scope: structural save only.
        //
        // A real MTE "enter scope" would flip SCTLR_EL1.TCF from
        // Ignore to Sync so tag mismatches fault, but that requires
        // the kernel's live tag storage and tagged pointers to already
        // be consistent — otherwise every memory access after the
        // flip tag-faults, recurses into the fault handler (which
        // also tag-faults), and we loop. Tag storage bring-up is a
        // Stage-3 task that pairs with the MTE-tag-aware allocator.
        //
        // SAFETY: pure MRS of SCTLR_EL1 — always legal at EL1.
        unsafe { Self::save() }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        // SAFETY: restore previous SCTLR_EL1.
        unsafe {
            Self::restore(saved);
        }
    }
}

// ── per-pointer tagging surface ─────────────────────────────────────
//
// IRG / STG / LDG / GMI don't have stable Rust intrinsics, so the
// inline asm gates the encoding behind `.arch_extension memtag`. Tag
// bits live in bits 59:56 of the virtual address (ARM DDI0487 D6.2).

/// MTE level reported by `ID_AA64PFR1_EL1.MTE` ≥ 1, i.e. tagging
/// instructions are usable. Level 2 additionally permits checked
/// loads/stores; the per-pointer surface below only needs level 1.
#[inline]
pub fn supported() -> bool {
    // SAFETY: MRS ID_AA64PFR1_EL1 is always legal at EL1.
    let feats = unsafe { crate::aarch64::Features::probe() };
    feats.mte >= 1
}

/// IRG — Insert Random Tag (ARM DDI0487 C6.2.IRG).
///
/// Returns `ptr` with bits 59:56 replaced by a random tag generated
/// per `GCR_EL1`. The address bits 55:0 are unchanged.
///
/// # Safety
/// CPU must report `supported()`. The returned tagged pointer aliases
/// `ptr`; storing the tag via `stg` is the caller's responsibility
/// before any tag-checked access.
// IRG is register-to-register only; the pointer operand is never
// dereferenced, so `nomem` is accurate despite the pointer input.
#[allow(clippy::pointers_in_nomem_asm_block)]
#[inline]
pub unsafe fn irg(ptr: *mut u8) -> *mut u8 {
    let out: *mut u8;
    // SAFETY: IRG is a pure register-to-register tag generator; no
    // memory traffic. The `memtag` arch extension is opt-in at the
    // assembler level so the kernel build doesn't have to pass
    // `-C target-feature=+mte` globally.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            ".arch_extension memtag",
            "irg {out}, {inp}",
            inp = in(reg) ptr,
            out = lateout(reg) out,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    out
}

/// STG — Store Allocation Tag (ARM DDI0487 C6.2.STG).
///
/// Writes the logical tag carried in bits 59:56 of `ptr` to the
/// 16-byte allocation-tag granule containing `ptr`.
///
/// # Safety
/// `ptr` must point into writable memory backed by tag storage
/// (kernel mappings on QEMU `-machine virt,mte=on` qualify). The
/// Bit position of the MTE allocation tag within a pointer.
pub const TAG_SHIFT: u32 = 56;

/// Mask of the tag field, bits 59:56.
pub const TAG_MASK: u64 = 0xF << TAG_SHIFT;

/// Replace `ptr`'s allocation tag with `tag` (low 4 bits).
///
/// **Replace, not OR.** A TTBR1 address has bits 63:48 set, so its tag field
/// already reads `0b1111`; OR-ing a tag into it is a no-op and leaves every
/// kernel pointer carrying tag 15. That is not a hypothetical — it is what
/// `bpf_arena` did before this existed, which made `stg` write 15 to every
/// granule while `pick_arena_tag`'s choice was silently discarded, and left
/// the arena's tag equal to the tag every untagged kernel pointer already
/// carries.
///
/// Safe for kernel pointers: with `TCR_EL1.TBI1` set (see `boot.S`), bits
/// 63:56 are excluded from translation and TTBR selection is decided by
/// bit 55, which this leaves untouched.
#[inline]
#[must_use]
pub const fn with_tag(ptr: u64, tag: u8) -> u64 {
    (ptr & !TAG_MASK) | (((tag as u64) & 0xF) << TAG_SHIFT)
}

/// The allocation tag `ptr` carries, in `0..=15`.
#[inline]
#[must_use]
pub const fn tag_of(ptr: u64) -> u8 {
    ((ptr >> TAG_SHIFT) & 0xF) as u8
}

/// The tag an untagged kernel pointer carries. Bits 63:48 of a TTBR1 address
/// are all ones, so its tag field reads 15 — the kernel-half equivalent of
/// user space's untagged 0, and therefore a value no arena may be assigned.
pub const UNTAGGED_KERNEL_TAG: u8 = 0xF;

/// CPU must report `supported()`.
#[inline]
pub unsafe fn stg(ptr: *mut u8) {
    // SAFETY: STG writes the granule's allocation-tag. The granule is
    // 16-byte aligned; STG itself ignores the low 4 bits of the
    // operand. Caller proves the granule is part of a tag-storage
    // mapping.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            ".arch_extension memtag",
            "stg {p}, [{p}]",
            p = in(reg) ptr,
            options(nostack, preserves_flags),
        );
    }
}

/// LDG — Load Allocation Tag (ARM DDI0487 C6.2.LDG).
///
/// Returns `ptr` with bits 59:56 replaced by the allocation tag
/// currently stored for the granule containing `ptr`. Bits 55:0
/// are preserved.
///
/// # Safety
/// `ptr` must reference a tag-storage-backed mapping; CPU must
/// report `supported()`.
// LDG reads allocation-tag storage, not the pointee; the load is
// invisible to the Rust memory model, so `nomem` is intentional.
#[allow(clippy::pointers_in_nomem_asm_block)]
#[inline]
pub unsafe fn ldg(ptr: *mut u8) -> *mut u8 {
    let out: *mut u8;
    // SAFETY: LDG reads tag storage for the granule; no payload access.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "mov {out}, {inp}",
            "ldg {out}, [{out}]",
            inp = in(reg) ptr,
            out = lateout(reg) out,
            options(nomem, nostack, preserves_flags),
        );
    }
    out
}

/// GMI — Tag Mask Insert (ARM DDI0487 C6.2.GMI).
///
/// Returns `excl | (1 << logical_tag(ptr))`, i.e. folds `ptr`'s
/// logical tag into an exclusion mask suitable for feeding back into
/// `GCR_EL1.Exclude` so subsequent `irg` calls don't pick the same
/// tag. Useful when an allocator wants neighbours to carry
/// non-overlapping tags without seeding `GCR_EL1` ahead of time.
///
/// # Safety
/// CPU must report `supported()`.
// GMI folds the pointer's logical tag into a mask via a pure ALU op;
// the pointer operand is never dereferenced, so `nomem` is accurate.
#[allow(clippy::pointers_in_nomem_asm_block)]
#[inline]
pub unsafe fn gmi(tag_excl_mask: u64, ptr: *mut u8) -> u64 {
    let out: u64;
    // SAFETY: GMI is a pure ALU op on the tag field; no memory traffic.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "gmi {out}, {p}, {m}",
            p = in(reg) ptr,
            m = in(reg) tag_excl_mask,
            out = lateout(reg) out,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    out
}

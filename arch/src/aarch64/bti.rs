//! aarch64 BTI (Branch Target Identification).
//!
//! Spec: `arch/specification/cpu-security.md` §2.
//!
//! BTI requires every indirect branch to land on a `bti` /
//! `bti j` / `bti c` / `bti jc` instruction (or known-safe
//! op like `paciasp`). Per-page enforcement is via the
//! translation-table descriptor's `GP` bit (attribute bits[50]
//! of stage-1 EL1 mappings).
//!
//! Detection lives here; the page-flag plumbing (setting the
//! GP bit on executable user mappings) is a `memory/` concern.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64pfr1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// `true` iff `ID_AA64PFR1_EL1.BT >= 1` (BTI implemented).
pub fn caps() -> bool {
    id_aa64pfr1() & 0xF != 0
}

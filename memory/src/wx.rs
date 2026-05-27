//! W^X — Write XOR Execute enforcement.
//!
//! No virtual-memory mapping may simultaneously carry the W (write)
//! and X (exec) permission bits. The kernel refuses such mappings at
//! the `mmap` entry and refuses such transitions at the `mprotect`
//! entry.
//!
//! The classical exception is JIT codegen: a JIT engine writes
//! machine code into a writable page, then flips the page to
//! read+execute and jumps to it. NARF supports that — but only
//! through an explicit RW → RX transition gated by a CAP_JIT
//! capability the task must already hold. There is no path through
//! `mprotect` that adds X to an existing W mapping for a task
//! without the cap.
//!
//! Compare:
//!
//!   * Linux historically allowed `PROT_WRITE | PROT_EXEC` and only
//!     started encouraging W^X via per-process flags (`PROC_MEM_FORCE_*`
//!     in 6.x). Even today, most distros enable W^X enforcement only
//!     via SELinux/AppArmor rules — i.e. policy, not mechanism.
//!   * grsecurity's PaX has had hard W^X via `MPROTECT` flag since
//!     2003, with the same JIT-by-design exception. NARF takes the
//!     same shape but expresses the JIT exception as a *capability*
//!     not a per-process bit, so the privilege is named and revocable
//!     rather than implicit.
//!
//! References:
//!   * grsecurity / PaX documentation, `MPROTECT` feature.
//!   * Linux `Documentation/admin-guide/kernel-parameters.txt`:
//!     `vsyscall=none`, `noexec=on`, `nx_huge_pages=force`.
//!   * OpenBSD `MAP_STACK` / W^X rollout history.

#![allow(dead_code)]

use crate::address_space::RegionPerms;

/// Outcome of a `mmap` permission check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WxCheck {
    /// Mapping is acceptable; pass it on to the AS layer.
    Allow,
    /// W|X requested simultaneously — refuse with EINVAL.
    DenyWX,
}

/// Outcome of a `mprotect` permission *transition* check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WxTransition {
    /// Transition is safe (one of: drops X, drops W, or stays at the
    /// same W^X invariant).
    Allow,
    /// Transition adds W to an existing X mapping. Always refused —
    /// not even CAP_JIT can do this (JIT writes new code into a
    /// freshly-allocated RW region, then flips to RX; an existing X
    /// region staying X across data writes is a different shape that
    /// implies self-modifying code with no relocation, which we don't
    /// support).
    DenyXtoWX,
    /// Transition adds X to a currently-W mapping. Permitted *only*
    /// if the caller holds `CAP_JIT`. The cap check is the caller's
    /// responsibility — this enum is just the protocol.
    NeedsCapJit,
}

/// Check a proposed `mmap` permission set. Returns [`WxCheck::Allow`]
/// for any permission set that does not contain BOTH W and X; returns
/// [`WxCheck::DenyWX`] for the W|X case.
#[inline]
pub fn check_mmap_perms(perms: RegionPerms) -> WxCheck {
    let w = perms.contains(RegionPerms::WRITE);
    let x = perms.contains(RegionPerms::EXEC);
    if w && x {
        WxCheck::DenyWX
    } else {
        WxCheck::Allow
    }
}

/// Inspect an `old → new` permission change and report what kind of
/// transition it is. The cap check (if [`WxTransition::NeedsCapJit`])
/// lives in the syscall layer, not here.
#[inline]
pub fn classify_mprotect(old: RegionPerms, new: RegionPerms) -> WxTransition {
    let old_w = old.contains(RegionPerms::WRITE);
    let old_x = old.contains(RegionPerms::EXEC);
    let new_w = new.contains(RegionPerms::WRITE);
    let new_x = new.contains(RegionPerms::EXEC);

    // Refuse W|X end state.
    if new_w && new_x {
        // Two sub-cases: was X (adding W) or was W (adding X). The
        // grsecurity model rejects the first absolutely; the second
        // is the JIT path that needs the cap. Adding both bits at
        // once (from RO) is the same as the JIT path — if you can
        // write OR execute, you can certainly write then execute.
        if old_x {
            return WxTransition::DenyXtoWX;
        }
        return WxTransition::NeedsCapJit;
    }

    // Otherwise W^X holds in the destination state.
    //
    // RW -> RX (W is dropped at the same time X is gained) is the
    // canonical JIT codegen flip and requires CAP_JIT.
    if !new_w && new_x && old_w && !old_x {
        return WxTransition::NeedsCapJit;
    }

    WxTransition::Allow
}

/// `true` iff the permission set is RW (read + write, no exec) — the
/// state a JIT engine populates before flipping to RX.
#[inline]
pub fn is_jit_buffer(perms: RegionPerms) -> bool {
    perms.contains(RegionPerms::WRITE)
        && perms.contains(RegionPerms::READ)
        && !perms.contains(RegionPerms::EXEC)
}

/// `true` iff the permission set is RX (read + exec, no write) — the
/// state a JIT engine flips a buffer into post-codegen.
#[inline]
pub fn is_jit_code(perms: RegionPerms) -> bool {
    perms.contains(RegionPerms::READ)
        && perms.contains(RegionPerms::EXEC)
        && !perms.contains(RegionPerms::WRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wx_at_mmap() {
        let wx = RegionPerms::WRITE | RegionPerms::EXEC | RegionPerms::READ;
        assert_eq!(check_mmap_perms(wx), WxCheck::DenyWX);
    }

    #[test]
    fn allows_rx() {
        let rx = RegionPerms::READ | RegionPerms::EXEC;
        assert_eq!(check_mmap_perms(rx), WxCheck::Allow);
    }

    #[test]
    fn allows_rw() {
        let rw = RegionPerms::READ | RegionPerms::WRITE;
        assert_eq!(check_mmap_perms(rw), WxCheck::Allow);
    }

    #[test]
    fn mprotect_rw_to_rx_needs_cap() {
        let rw = RegionPerms::READ | RegionPerms::WRITE;
        let rx = RegionPerms::READ | RegionPerms::EXEC;
        assert_eq!(classify_mprotect(rw, rx), WxTransition::NeedsCapJit);
    }

    #[test]
    fn mprotect_rx_to_rw_is_allowed() {
        let rx = RegionPerms::READ | RegionPerms::EXEC;
        let rw = RegionPerms::READ | RegionPerms::WRITE;
        assert_eq!(classify_mprotect(rx, rw), WxTransition::Allow);
    }

    #[test]
    fn mprotect_rx_to_rwx_is_x_then_w_denied() {
        let rx = RegionPerms::READ | RegionPerms::EXEC;
        let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
        assert_eq!(classify_mprotect(rx, rwx), WxTransition::DenyXtoWX);
    }
}

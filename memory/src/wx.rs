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

//! ## Status
//!
//! Until the BPF work this module was **dead code**: its only non-test
//! consumer was a doc comment at `address_space.rs`, and the live path —
//! `AddressSpace::mprotect_range` — hard-rejected `WRITE | EXEC` without ever
//! calling [`classify_mprotect`]. [`jit_mprotect`] below is the missing
//! consumer, and `CapKind::Jit` (0x0053) is the capability the doc comment
//! above has been promising since it was written.

extern crate alloc as alloc_crate;

use alloc_crate::collections::BTreeMap;

use narf_capabilities::{CapError, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::address_space::{AddressSpace, AddressSpaceError, RegionPerms};
use crate::bpf_text::Jit;
use crate::VirtAddr;

/// The granting form of the JIT capability. The marker type lives in
/// `bpf_text` alongside the kernel-side text allocator it also gates.
pub type JitCap = narf_capabilities::Cap<Jit, Grant>;

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
    /// Transition adds X to a currently-W mapping, ending at RX. Permitted
    /// *only* if the caller holds `CAP_JIT`. This is the canonical JIT codegen
    /// flip. The cap check is the caller's responsibility — this enum is just
    /// the protocol.
    NeedsCapJit,
    /// The destination state is simultaneously writable and executable.
    /// Refused unconditionally: **no capability grants RWX.**
    ///
    /// This used to be [`Self::NeedsCapJit`] when the source mapping was not
    /// already executable, which had the effect of making `CAP_JIT` a licence
    /// to create a genuinely RWX user mapping — something NARF had previously
    /// made impossible — while leaving the RW → RX flip the capability was
    /// designed for ungated. That is backwards: grsecurity/PaX never permits
    /// W|X, and the flip is the whole point of the exception.
    DenyWX,
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

    // Refuse a W|X end state, unconditionally and whatever the caller holds.
    //
    // `DenyXtoWX` is kept as a distinct answer when the mapping was already
    // executable, because that case names a different mistake (self-modifying
    // code with no relocation) and is worth reporting separately. Both are
    // refusals.
    if new_w && new_x {
        if old_x {
            return WxTransition::DenyXtoWX;
        }
        return WxTransition::DenyWX;
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

// ── The JIT grant table ────────────────────────────────────────────────
//
// There is no per-task capability table for userspace today — `sys_bootstrap`
// hands out ad-hoc integer ids keyed by task id in a `BTreeMap` behind an
// `IrqSafeSpinLock`. This is modelled on exactly that shape rather than
// inventing a second mechanism, and it is revoked on task exit through the
// existing exit-observer fan-out.
//
// `Cap::bootstrap()` allocates an object-table slot per call, so it is called
// **once per grant**, never per `mprotect` — see `feedback_cap_bootstrap_hot_path`.

static JIT_GRANTS: IrqSafeSpinLock<Option<BTreeMap<u64, JitCap>>> = IrqSafeSpinLock::new(None);

/// Initialise the JIT grant registry. Boot calls this alongside the other
/// per-task state tables.
pub fn jit_grants_init() {
    *JIT_GRANTS.lock() = Some(BTreeMap::new());
}

/// Grant `task` the JIT capability, minting a fresh object-table entry.
///
/// Re-granting returns the existing capability rather than minting a second
/// one — the object table is not free, and two live caps for the same
/// authority would make revocation ambiguous.
pub fn grant_jit(task: u64) -> JitCap {
    let mut g = JIT_GRANTS.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    if let Some(c) = map.get(&task) {
        return *c;
    }
    let cap = JitCap::bootstrap();
    map.insert(task, cap);
    cap
}

/// This task's JIT capability, if it holds one.
pub fn jit_cap(task: u64) -> Option<JitCap> {
    JIT_GRANTS.lock().as_ref()?.get(&task).copied()
}

/// Revoke `task`'s JIT capability.
///
/// Wired to the thread-scoped exit-observer fan-out, so a task that exits
/// while holding the grant cannot leave a live authority behind. Revocation
/// bumps the object's epoch, so any capability copy that escaped fails its
/// next `check_live` — invariant #5.
pub fn revoke_jit(task: u64) {
    let taken = JIT_GRANTS.lock().as_mut().and_then(|m| m.remove(&task));
    if let Some(cap) = taken {
        cap.revoke();
    }
}

/// Live grants. Diagnostic only.
pub fn jit_grant_count() -> usize {
    JIT_GRANTS.lock().as_ref().map(|m| m.len()).unwrap_or(0)
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_jit_grants_for_test() {
    *JIT_GRANTS.lock() = Some(BTreeMap::new());
}

/// Why a capability-gated `mprotect` was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WxError {
    /// The destination state would be simultaneously writable and executable.
    DenyWX,
    /// The request does not cover a single mapped region, so there is no
    /// `old` permission set to classify the transition against.
    Unmapped,
    /// The transition adds `W` to a currently-`X` mapping. Refused
    /// unconditionally — not even `Cap<Jit, Grant>` permits it. A JIT writes
    /// new code into a fresh RW region and then flips it; an existing X region
    /// staying X across data writes is self-modifying code with no relocation,
    /// which NARF does not support.
    DenyXtoWX,
    /// The capability was revoked between grant and use.
    CapRevoked,
    /// The address-space layer refused the change for an unrelated reason
    /// (alignment, hugepage split, …).
    AddressSpace(AddressSpaceError),
}

impl From<CapError> for WxError {
    fn from(_: CapError) -> Self {
        WxError::CapRevoked
    }
}

/// Capability-gated `mprotect`.
///
/// This is the **only** path by which a `W | X` mapping can come into
/// existence in a user address space. It:
///
/// 1. proves the capability is *currently* valid (holding a `Cap` proves prior
///    grant; only a live check proves current validity — invariant #5),
/// 2. reads the region's existing permissions and classifies the transition
///    through [`classify_mprotect`],
/// 3. refuses [`WxTransition::DenyXtoWX`] regardless of the capability, and
/// 4. applies the change through the W^X-unchecked inner entry.
///
/// A transition that [`classify_mprotect`] reports as [`WxTransition::Allow`]
/// needs no capability at all and is handled identically — callers may route
/// everything here without a second code path.
///
/// Gated on `linux-compat` because the splitting `mprotect_range` it builds on
/// is; the NARF-native `change_perms_range` is whole-region only and has no
/// W^X classification to gate.
#[cfg(feature = "linux-compat")]
pub fn jit_mprotect(
    cap: &JitCap,
    space: &AddressSpace,
    base: VirtAddr,
    len: u64,
    new_perms: RegionPerms,
) -> Result<(), WxError> {
    cap.check_live()?;
    let old = space
        .perms_covering(base, len)
        .ok_or(WxError::Unmapped)?
        .prot_only();
    match classify_mprotect(old, new_perms.prot_only()) {
        WxTransition::DenyXtoWX => Err(WxError::DenyXtoWX),
        // No capability grants RWX.
        WxTransition::DenyWX => Err(WxError::DenyWX),
        // Both `Allow` and `NeedsCapJit` proceed — the capability was already
        // proven live above, and `Allow` never needed it.
        WxTransition::Allow | WxTransition::NeedsCapJit => space
            .mprotect_range_wx_checked(base, len, new_perms)
            .map_err(WxError::AddressSpace),
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The grant table behaves like a capability table and not like a bit: a
/// second grant reuses the object-table entry, and revocation invalidates
/// every copy that escaped.
fn smoke_wx_jit_grant_lifecycle() -> TestResult {
    __reset_jit_grants_for_test();
    const TASK: u64 = 0xBFE1;

    if jit_cap(TASK).is_some() {
        return TestResult::Fail("an ungranted task already holds the JIT cap");
    }
    let first = grant_jit(TASK);
    let second = grant_jit(TASK);
    if first.slot().index != second.slot().index {
        // `Cap::bootstrap()` allocates an object-table slot per call — minting
        // a second one per grant would leak slots and make revocation
        // ambiguous about which authority it killed.
        return TestResult::Fail("re-granting minted a second object-table entry");
    }
    // A copy that escaped the table.
    let escaped = jit_cap(TASK).expect("granted");
    if escaped.check_live().is_err() {
        return TestResult::Fail("a fresh grant is not live");
    }

    revoke_jit(TASK);
    if jit_cap(TASK).is_some() {
        return TestResult::Fail("revoke left the grant in the table");
    }
    if escaped.check_live().is_ok() {
        return TestResult::Fail("a capability copy survived revocation");
    }
    __reset_jit_grants_for_test();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_wx_jit_grant_lifecycle);

/// The classification the cap gate is built on. Positive and negative arms:
/// RW→RX and RW→RWX need the cap, RX→RWX is refused outright, and everything
/// that preserves W^X needs nothing.
fn smoke_wx_classify_covers_every_arm() -> TestResult {
    let r = RegionPerms::READ;
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    let rx = RegionPerms::READ | RegionPerms::EXEC;
    let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;

    let cases: &[(RegionPerms, RegionPerms, WxTransition)] = &[
        // The JIT codegen flip — the one transition CAP_JIT exists for.
        (rw, rx, WxTransition::NeedsCapJit),
        // Asking for W|X: refused, whatever the caller holds. These two used
        // to be `NeedsCapJit`, which made the capability a licence to create a
        // genuinely RWX mapping — something NARF had previously made
        // impossible — while the flip above went ungated. A task that can
        // write a page and then make it executable already has RWX's power, so
        // gating the flip is what buys something and permitting W|X is what
        // gives it away.
        (rw, rwx, WxTransition::DenyWX),
        (r, rwx, WxTransition::DenyWX),
        // Adding W to an existing X mapping names a different mistake
        // (self-modifying code with no relocation) and keeps its own answer.
        (rx, rwx, WxTransition::DenyXtoWX),
        // W^X-preserving transitions need no authority at all.
        (rx, rw, WxTransition::Allow),
        (rx, r, WxTransition::Allow),
        (rw, r, WxTransition::Allow),
        // R -> RX is deliberately still ungated: it adds no write path, and
        // gating it would break a dynamic linker making a mapping executable.
        (r, rx, WxTransition::Allow),
    ];
    for &(old, new, want) in cases {
        if classify_mprotect(old, new) != want {
            return TestResult::Fail("classify_mprotect disagreed with the expected arm");
        }
    }
    if check_mmap_perms(rwx) != WxCheck::DenyWX {
        return TestResult::Fail("mmap accepted a W|X mapping");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_wx_classify_covers_every_arm);

/// The cap-gated entry refuses X→WX even with a live capability, and refuses
/// everything once the capability is revoked.
#[cfg(feature = "linux-compat")]
fn smoke_wx_jit_mprotect_refuses_x_to_wx() -> TestResult {
    let space = AddressSpace::empty();
    let base = VirtAddr::new(0x4000_0000);
    if space
        .map_region(crate::address_space::Region {
            base,
            len: 0x2000,
            perms: RegionPerms::READ | RegionPerms::EXEC,
            // Unbacked (demand-paged) slots: this test only exercises the
            // permission classifier, which never touches the backing.
            phys: alloc_crate::vec![crate::PhysAddr::new(0); 2],
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    let cap = JitCap::bootstrap();
    let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    match jit_mprotect(&cap, &space, base, 0x2000, rwx) {
        Err(WxError::DenyXtoWX) => {}
        _ => return TestResult::Fail("a live JIT cap was allowed to add W to an X mapping"),
    }
    // And an unmapped range has no `old` to classify against.
    match jit_mprotect(&cap, &space, VirtAddr::new(0x9000_0000), 0x1000, rwx) {
        Err(WxError::Unmapped) => {}
        _ => return TestResult::Fail("jit_mprotect accepted an unmapped range"),
    }
    cap.revoke();
    match jit_mprotect(&cap, &space, base, 0x2000, rwx) {
        Err(WxError::CapRevoked) => TestResult::Pass,
        _ => TestResult::Fail("a revoked JIT cap was still honoured"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("memory", smoke_wx_jit_mprotect_refuses_x_to_wx);

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

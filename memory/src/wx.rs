//! W^X — Write XOR Execute policy.
//!
//! A mapping that is simultaneously writable and executable is a
//! JIT engine's working memory: V8 makes its whole code range
//! `PROT_READ | PROT_WRITE | PROT_EXEC` (guarded by a protection key where
//! the CPU has them), and SpiderMonkey writes code into an RW page and then
//! flips it to RX. NARF gates both shapes behind one named, revocable
//! capability, `CAP_JIT`:
//!
//!   * the RW → RX flip, and
//!   * any transition whose end state is W|X,
//!
//! need a live `Cap<Jit, Grant>`. They are the same power — a task that can
//! write a page and then make it executable can do everything a task holding
//! an RWX page can — so gating one and refusing the other bought nothing,
//! while refusing W|X outright broke every V8 embedder (Chromium, Electron,
//! Node): `CodeRange::InitReservation` CHECKs that `pkey_mprotect(RWX)`
//! succeeds and treats anything but ENOMEM as fatal.
//!
//! Linux grants both unconditionally unless the process opted into
//! memory-deny-write-execute (`PR_SET_MDWE`), which the syscall layer
//! enforces above this policy. NARF's difference is that the privilege is a
//! capability the task holds by default and that can be revoked or denied,
//! rather than ambient.
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
    /// Reserved: a transition no capability can authorise. The current
    /// policy produces none ([`classify_mprotect`] never returns it); the
    /// variant stays so [`jit_mprotect`]'s refusal path keeps a name.
    DenyXtoWX,
    /// Transition needs `CAP_JIT`: the RW → RX codegen flip, or any change
    /// whose end state is W|X. The cap check is the caller's responsibility —
    /// this enum is just the protocol.
    NeedsCapJit,
    /// Reserved, as [`Self::DenyXtoWX`]: never produced by the current policy.
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

    // A W|X end state is JIT memory: it needs the JIT capability, whatever
    // the source state (PROT_NONE reservation, RW, or an existing RX range
    // V8 makes writable again). See the module comment for why this is the
    // same authority as the RW -> RX flip below.
    if new_w && new_x {
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

/// Fold [`classify_mprotect`] over every region an `mprotect` request spans.
///
/// `mprotect_range` splits across every intersecting region, so classification
/// has to consider every one of them. The fold takes the **strictest** verdict:
/// a refusal anywhere refuses the whole request, and a `NeedsCapJit` anywhere
/// demands the capability. Partial application is not an option — the request
/// is one syscall and either happens or does not.
///
/// An empty iterator yields [`WxTransition::Allow`], deliberately: nothing is
/// mapped in the range, and reporting *that* is the address-space layer's job.
/// Returning a refusal here would replace a precise `Unmapped` with a generic
/// permission error.
#[must_use]
pub fn classify_mprotect_range<I: Iterator<Item = RegionPerms>>(
    olds: I,
    new: RegionPerms,
) -> WxTransition {
    let mut worst = WxTransition::Allow;
    for old in olds {
        let t = classify_mprotect(old.prot_only(), new);
        // Strictness order: the two refusals outrank NeedsCapJit, which
        // outranks Allow. `DenyXtoWX` is reported in preference to `DenyWX`
        // because it names the more specific mistake.
        worst = match (worst, t) {
            (WxTransition::DenyXtoWX, _) | (_, WxTransition::DenyXtoWX) => WxTransition::DenyXtoWX,
            (WxTransition::DenyWX, _) | (_, WxTransition::DenyWX) => WxTransition::DenyWX,
            (WxTransition::NeedsCapJit, _) | (_, WxTransition::NeedsCapJit) => {
                WxTransition::NeedsCapJit
            }
            (WxTransition::Allow, WxTransition::Allow) => WxTransition::Allow,
        };
    }
    worst
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

/// A task's standing with respect to the JIT authority.
///
/// Three states, not two, because "no entry" and "explicitly denied" must be
/// distinguishable. Collapsing them into a bare "is it in the map" test is what
/// makes revocation either meaningless (the next `mprotect` re-grants) or
/// permanent in the wrong way (a recycled task id inherits a denial).
#[derive(Copy, Clone, Debug)]
enum JitState {
    /// Holds the authority.
    Granted(JitCap),
    /// Denied by policy. The default grant policy will not re-grant; only an
    /// explicit [`grant_jit`] restores it.
    Denied,
}

static JIT_GRANTS: IrqSafeSpinLock<Option<BTreeMap<u64, JitState>>> = IrqSafeSpinLock::new(None);

/// Initialise the JIT grant registry. Boot calls this alongside the other
/// per-task state tables.
///
/// Idempotent, and deliberately so: `init_per_task_state` is called from many
/// test paths as well as from boot, and replacing the map wholesale dropped
/// live grants **without revoking them** — leaving every escaped capability
/// copy still passing `check_live`, which is exactly what invariant #5 forbids.
pub fn jit_grants_init() {
    let mut g = JIT_GRANTS.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

/// Grant `task` the JIT capability, minting a fresh object-table entry.
///
/// Re-granting returns the existing capability rather than minting a second
/// one — the object table is not free, and two live caps for the same
/// authority would make revocation ambiguous. An explicit grant overrides a
/// prior [`deny_jit`].
pub fn grant_jit(task: u64) -> JitCap {
    let mut g = JIT_GRANTS.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    if let Some(JitState::Granted(c)) = map.get(&task) {
        return *c;
    }
    let cap = JitCap::bootstrap();
    map.insert(task, JitState::Granted(cap));
    cap
}

/// Deny `task` the JIT authority by policy, revoking any capability it holds.
///
/// Distinct from [`revoke_jit`], which is the *exit sweep*: this one leaves a
/// standing denial so the default grant policy will not hand the authority
/// straight back on the next `mprotect`. Without that distinction, revocation
/// on a live task would last exactly until its next syscall.
pub fn deny_jit(task: u64) {
    let mut g = JIT_GRANTS.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    let prior = map.insert(task, JitState::Denied);
    drop(g);
    if let Some(JitState::Granted(cap)) = prior {
        cap.revoke();
    }
}

/// This task's JIT capability, if it holds one.
///
/// Reports possession only — it never grants. Use
/// [`jit_cap_default_policy`] on the `mprotect` path, or a task that was
/// never explicitly granted can perform no RW→RX flip at all.
pub fn jit_cap(task: u64) -> Option<JitCap> {
    match JIT_GRANTS.lock().as_ref()?.get(&task) {
        Some(JitState::Granted(c)) => Some(*c),
        Some(JitState::Denied) | None => None,
    }
}

/// The capability `mprotect` should use, applying the **default grant policy**.
///
/// NARF's policy today is *permissive by default, revocable on demand*: a task
/// that has not been explicitly revoked gets the grant the first time it needs
/// one. This is a deliberate choice and the alternative was a regression, so it
/// is worth being precise about why.
///
/// Before `CapKind::Jit` existed, `AddressSpace::mprotect_range` refused `W|X`
/// end states and permitted RW→RX for everyone. Gating the flip on a capability
/// that **nothing granted** did not tighten that policy — it denied the flip
/// unconditionally, breaking every JIT userland that relies on it (V8, the JVM,
/// LuaJIT, libffi trampolines). A gate whose authority is unobtainable is not a
/// gate; it is an outage.
///
/// So what the capability buys today is not admission control — it is a *named,
/// revocable* authority with a real revocation path ([`revoke_jit`], swept on
/// task exit) and one enforcement point ([`jit_mprotect`]). Tightening the
/// policy is then a change at this one function — refuse to auto-grant, and
/// have whoever decides policy call [`grant_jit`] — rather than a re-plumbing of
/// the enforcement path. `W|X` remains refused for everyone regardless, which is
/// the property that was actually load-bearing.
pub fn jit_cap_default_policy(task: u64) -> Option<JitCap> {
    {
        let g = JIT_GRANTS.lock();
        match g.as_ref().and_then(|m| m.get(&task)) {
            Some(JitState::Granted(c)) => return Some(*c),
            // A standing policy denial. Not re-granted.
            Some(JitState::Denied) => return None,
            None => {}
        }
    }
    Some(grant_jit(task))
}

/// Revoke `task`'s JIT capability and forget it entirely.
///
/// Wired to the thread-scoped exit-observer fan-out, so a task that exits
/// while holding the grant cannot leave a live authority behind. Revocation
/// bumps the object's epoch, so any capability copy that escaped fails its
/// next `check_live` — invariant #5.
///
/// Removes the entry rather than marking it [`JitState::Denied`], which matters
/// because task ids are recycled: leaving a denial behind would make a *future*
/// unrelated task inherit this one's revocation.
pub fn revoke_jit(task: u64) {
    let taken = JIT_GRANTS.lock().as_mut().and_then(|m| m.remove(&task));
    if let Some(JitState::Granted(cap)) = taken {
        cap.revoke();
    }
}

/// Live grants. Diagnostic only.
pub fn jit_grant_count() -> usize {
    JIT_GRANTS
        .lock()
        .as_ref()
        .map(|m| {
            m.values()
                .filter(|s| matches!(s, JitState::Granted(_)))
                .count()
        })
        .unwrap_or(0)
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
pub fn jit_mprotect(
    cap: &JitCap,
    space: &AddressSpace,
    base: VirtAddr,
    len: u64,
    new_perms: RegionPerms,
) -> Result<(), WxError> {
    cap.check_live()?;
    // Classify over EVERY region the request intersects, as `mprotect(2)`
    // walks every VMA in `[start, end)`. Requiring one region to cover the
    // whole request refused a JIT range an earlier `mprotect` had split
    // (SpiderMonkey's pattern) with -ENOMEM. A hole between the regions is
    // still refused: `mprotect_range_wx_checked` checks full coverage.
    let olds = space.perms_intersecting(base, len);
    if olds.is_empty() {
        return Err(WxError::Unmapped);
    }
    match classify_mprotect_range(olds.into_iter(), new_perms.prot_only()) {
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

/// The classification the cap gate is built on: the RW→RX flip and every
/// W|X end state need the cap, and everything that preserves W^X needs
/// nothing.
fn smoke_wx_classify_covers_every_arm() -> TestResult {
    let r = RegionPerms::READ;
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    let rx = RegionPerms::READ | RegionPerms::EXEC;
    let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;

    let cases: &[(RegionPerms, RegionPerms, WxTransition)] = &[
        // The JIT codegen flip — the one transition CAP_JIT exists for.
        (rw, rx, WxTransition::NeedsCapJit),
        // A W|X end state is JIT memory, whatever the source: V8 makes a
        // PROT_NONE code range RWX in one pkey_mprotect, and re-opens RX
        // ranges for writing. Same authority as the flip above.
        (rw, rwx, WxTransition::NeedsCapJit),
        (r, rwx, WxTransition::NeedsCapJit),
        (RegionPerms(0), rwx, WxTransition::NeedsCapJit),
        (rx, rwx, WxTransition::NeedsCapJit),
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

/// The cap-gated entry makes an executable mapping RWX with a live
/// capability, and refuses everything once the capability is revoked.
fn smoke_wx_jit_mprotect_rwx_needs_live_cap() -> TestResult {
    let space = AddressSpace::empty();
    let base = VirtAddr::new(0x4000_0000);
    if space
        .map_region(crate::address_space::Region {
            base,
            len: 0x2000,
            perms: RegionPerms::READ | RegionPerms::EXEC,
            // Unbacked (demand-paged) slots: this test only exercises the
            // permission classifier, which never touches the backing.
            phys: alloc_crate::vec![crate::PhysAddr::new(0); 2].into(),
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    let cap = JitCap::bootstrap();
    let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    if jit_mprotect(&cap, &space, base, 0x1000, rwx).is_err() {
        return TestResult::Fail("a live JIT cap could not make an RX mapping RWX");
    }
    if space.perms_covering(base, 0x1000).map(|p| p.prot_only()) != Some(rwx) {
        return TestResult::Fail("RX->RWX under a live JIT cap did not apply");
    }
    // And an unmapped range has no `old` to classify against.
    match jit_mprotect(&cap, &space, VirtAddr::new(0x9000_0000), 0x1000, rwx) {
        Err(WxError::Unmapped) => {}
        _ => return TestResult::Fail("jit_mprotect accepted an unmapped range"),
    }
    cap.revoke();
    let second = VirtAddr::new(base.as_u64() + 0x1000);
    match jit_mprotect(&cap, &space, second, 0x1000, rwx) {
        Err(WxError::CapRevoked) => {}
        _ => return TestResult::Fail("a revoked JIT cap was still honoured"),
    }
    if space.perms_covering(second, 0x1000).map(|p| p.prot_only())
        != Some(RegionPerms::READ | RegionPerms::EXEC)
    {
        return TestResult::Fail("a refused RWX request changed the mapping");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_wx_jit_mprotect_rwx_needs_live_cap);

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
    fn mprotect_to_rwx_needs_cap() {
        let rx = RegionPerms::READ | RegionPerms::EXEC;
        let rw = RegionPerms::READ | RegionPerms::WRITE;
        let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
        assert_eq!(classify_mprotect(rx, rwx), WxTransition::NeedsCapJit);
        assert_eq!(classify_mprotect(rw, rwx), WxTransition::NeedsCapJit);
        assert_eq!(classify_mprotect(RegionPerms(0), rwx), WxTransition::NeedsCapJit);
    }
}

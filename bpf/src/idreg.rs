//! The kernel-wide id registries — what `BPF_*_GET_NEXT_ID` walks and what
//! `BPF_*_GET_FD_BY_ID` resolves.
//!
//! [`crate::prog::BpfProg`] and [`crate::map::BpfMap`] already carried an `id`
//! before anything could look one up; this is the other half — the id → object
//! direction, which is what makes an id an *address* rather than a label.
//!
//! ## Weak, not strong
//!
//! Entries hold [`Weak`], never [`Arc`]. A strong entry would mean an id keeps
//! its object alive forever, so every program a loader ever loaded would stay
//! resident for the boot — and `bpftool prog list` would show a graveyard. A
//! weak entry means the object's lifetime is still exactly its fd's plus
//! whatever else references it, and a lookup of a dead id fails (`ENOENT`)
//! instead of resurrecting anything.
//!
//! ## Why the table is also pruned on drop
//!
//! `Weak` alone stops a use-after-free but not a leak: the entry itself, and
//! the `Arc` allocation's control block that the `Weak` pins, would outlive the
//! object. So `Drop for BpfProg` / `Drop for BpfMap` call [`IdRegistry::remove`],
//! and the weak-ness above is what makes the *window* between "strong count hit
//! zero" and "`Drop` ran" safe rather than merely narrow.
//!
//! Both halves are load-bearing and both are tested: `idreg_lifetime_*` below
//! pins the lookup half, `idreg_teardown_*` the pruning half.
//!
//! ## Ids are never reused
//!
//! Assignment is a `fetch_add` on a boot-lifetime counter in each of
//! `prog.rs` / `map.rs`; nothing here ever hands an id back. A reused id is how
//! a loader that cached one silently starts addressing a different object, so
//! the counter is monotone even though the table is sparse.
//!
//! ## Not reachable from a running program
//!
//! `bpf/specification/spec.md` §4.6 forbids allocating on the program-run path.
//! Every mutation here happens at load/create (insert) or teardown (remove);
//! the interpreter, the JIT entry, and every kfunc resolve maps through
//! `BpfProg::map_by_fd`, which reads a slice the program owns and never touches
//! this lock. The lock is `IrqSafeSpinLock` regardless, because `remove` runs
//! from `Drop` and a `Drop` can land anywhere.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// An id → object table for one object class.
///
/// Kept sorted by id so `GET_NEXT_ID` is a `partition_point` rather than a
/// scan, and so `get` is a binary search. Ids arrive very nearly in order —
/// they come off a `fetch_add` — but *not* exactly: two CPUs can take ids 5 and
/// 6 and insert 6 first. Hence a sorted insert rather than a push, because a
/// table that is only usually sorted is one whose binary search is only usually
/// right.
#[derive(Debug)]
pub struct IdRegistry<T> {
    entries: IrqSafeSpinLock<Vec<(u32, Weak<T>)>>,
}

impl<T> IdRegistry<T> {
    /// An empty registry. `const` so the two statics below need no lazy init.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Record `obj` under `id`.
    ///
    /// Called once per object, immediately after the `Arc` is built and before
    /// it is handed to anyone. A duplicate id would mean the assigning counter
    /// wrapped or was reused; the entry is replaced rather than duplicated so
    /// the table stays a function of id, but that case is a bug elsewhere.
    pub fn insert(&self, id: u32, obj: &Arc<T>) {
        let w = Arc::downgrade(obj);
        let mut g = self.entries.lock();
        match g.binary_search_by(|(i, _)| i.cmp(&id)) {
            Ok(pos) => g[pos].1 = w,
            Err(pos) => g.insert(pos, w_at(id, w)),
        }
    }

    /// Drop the entry for `id`.
    ///
    /// Called from the object's `Drop`. Idempotent: an id that is not present
    /// is not an error, which matters because a failed create may or may not
    /// have got as far as inserting.
    pub fn remove(&self, id: u32) {
        let mut g = self.entries.lock();
        if let Ok(pos) = g.binary_search_by(|(i, _)| i.cmp(&id)) {
            g.remove(pos);
        }
    }

    /// The object with this id, if it is still alive.
    ///
    /// The `Weak` is cloned under the lock and upgraded *outside* it, and that
    /// ordering is not stylistic. Upgrading under the lock would materialise an
    /// `Arc<T>` whose drop — if the last other reference went away meanwhile —
    /// runs `Drop for T`, which calls [`Self::remove`], which takes this same
    /// non-reentrant lock. Self-deadlock. Nothing in this module may ever hold
    /// an `Arc<T>` across the guard.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<Arc<T>> {
        let w = {
            let g = self.entries.lock();
            let pos = g.binary_search_by(|(i, _)| i.cmp(&id)).ok()?;
            g[pos].1.clone()
        };
        w.upgrade()
    }

    /// The smallest live id strictly greater than `after`.
    ///
    /// Linux's `BPF_*_GET_NEXT_ID` semantics: the caller passes the id it last
    /// saw (0 to start) and gets the next one, or `None` at the end of the
    /// table. `after = u32::MAX` therefore has no successor and is not a
    /// special case, just an empty range.
    ///
    /// Liveness is tested with `strong_count`, not `upgrade`, for the
    /// self-deadlock reason in [`Self::get`] — this one runs entirely under the
    /// guard, so it must not be able to construct an `Arc<T>` at all.
    #[must_use]
    pub fn next_id(&self, after: u32) -> Option<u32> {
        let g = self.entries.lock();
        let start = g.partition_point(|(i, _)| *i <= after);
        g[start..]
            .iter()
            .find(|(_, w)| w.strong_count() > 0)
            .map(|(i, _)| *i)
    }

    /// How many entries the table holds, live or merely not-yet-pruned.
    ///
    /// Exists for the teardown smoke: "the entry went away when the object did"
    /// is the half of this module that rots silently, and it cannot be observed
    /// through `get`, which answers `None` for a stale entry too.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the table is empty. Paired with [`Self::len`] because clippy
    /// asks for it; a boot that has loaded anything never sees `true`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for IdRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the tuple `insert` stores. A named helper only because the closure
/// form confused type inference inside `Vec::insert`.
fn w_at<T>(id: u32, w: Weak<T>) -> (u32, Weak<T>) {
    (id, w)
}

static PROGS: IdRegistry<crate::prog::BpfProg> = IdRegistry::new();
static MAPS: IdRegistry<crate::map::BpfMap> = IdRegistry::new();
static LINKS: IdRegistry<crate::link::BpfLink> = IdRegistry::new();

/// The program id table.
#[must_use]
pub fn progs() -> &'static IdRegistry<crate::prog::BpfProg> {
    &PROGS
}

/// The map id table.
#[must_use]
pub fn maps() -> &'static IdRegistry<crate::map::BpfMap> {
    &MAPS
}

/// The link id table — what `BPF_LINK_GET_NEXT_ID` walks and
/// `BPF_LINK_GET_FD_BY_ID` resolves.
///
/// A link is the one object class here whose teardown has an *external* effect:
/// `Drop for BpfLink` detaches the hook. So the pruning half of this module is
/// not merely an anti-leak measure for links — an entry that outlived its link
/// would hand `GET_FD_BY_ID` a handle to an attach that no longer exists. The
/// `Weak` makes that impossible and `BpfLink`'s drop keeps the table tidy;
/// `smoke_bpf_link_id_*` in `link.rs` pins both halves against the real object.
#[must_use]
pub fn links() -> &'static IdRegistry<crate::link::BpfLink> {
    &LINKS
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A stand-in object. The registry is generic, and testing it through
    /// `BpfProg` would mean every assertion about *the table* also depended on
    /// the verifier accepting a program — the "testing a lower layer through a
    /// stricter upper layer" trap. The `bpf(2)`-level smokes in
    /// `abi_bpf_tests.rs` cover the composed path.
    #[derive(Debug)]
    struct Obj(u32);

    fn reg() -> IdRegistry<Obj> {
        IdRegistry::new()
    }

    /// Bodies return `Result` so they can use `?` and read as a list of
    /// assertions; `wrap` turns that into the runner's [`TestResult`].
    type R = Result<(), &'static str>;

    fn wrap(r: R) -> TestResult {
        match r {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }

    fn body_get_and_next() -> R {
        let r = reg();
        let a = Arc::new(Obj(1));
        let c = Arc::new(Obj(3));
        // Inserted out of order on purpose: the table must sort, because
        // `next_id` is a `partition_point` over it.
        r.insert(3, &c);
        r.insert(1, &a);
        if r.get(1).map(|o| o.0) != Some(1) {
            return Err("get(1) did not return the object inserted at id 1");
        }
        if r.get(3).map(|o| o.0) != Some(3) {
            return Err("get(3) did not return the object inserted at id 3");
        }
        if r.next_id(0) != Some(1) {
            return Err("next_id(0) should be the first id, 1");
        }
        if r.next_id(1) != Some(3) {
            return Err("next_id(1) should skip 1 and give 3");
        }
        if r.next_id(3).is_some() {
            return Err("next_id past the last id should be None");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_get_and_next_pos() -> TestResult {
        wrap(body_get_and_next())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_get_and_next_pos);

    fn body_unknown_id() -> R {
        let r = reg();
        let a = Arc::new(Obj(1));
        r.insert(1, &a);
        if r.get(2).is_some() {
            return Err("get on an id that was never inserted returned an object");
        }
        if r.get(0).is_some() {
            return Err("get(0) — never a valid id — returned an object");
        }
        if r.next_id(u32::MAX).is_some() {
            return Err("next_id(u32::MAX) has no successor and must be None");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_unknown_id_neg() -> TestResult {
        wrap(body_unknown_id())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_unknown_id_neg);

    /// The half that makes `GET_FD_BY_ID` on a freed object `ENOENT` rather
    /// than a dangling handle.
    fn body_lifetime_weak() -> R {
        let r = reg();
        let a = Arc::new(Obj(7));
        r.insert(1, &a);
        // A second strong reference: dropping the first must NOT invalidate the
        // id, or `GET_FD_BY_ID` would fail for an object that is very much
        // alive behind another fd.
        let keeper = Arc::clone(&a);
        drop(a);
        if r.get(1).map(|o| o.0) != Some(7) {
            return Err("id lookup failed while another strong reference was live");
        }
        drop(keeper);
        // `Obj` has no `Drop` calling `remove`, so the entry is still present —
        // and the lookup must still fail. That is precisely the window this
        // registry is `Weak` to cover.
        if r.get(1).is_some() {
            return Err("id lookup resurrected an object whose last reference was dropped");
        }
        if r.next_id(0).is_some() {
            return Err("next_id walked over a stale entry instead of skipping it");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_lifetime_weak_neg() -> TestResult {
        wrap(body_lifetime_weak())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_lifetime_weak_neg);

    /// The half that makes the table not leak.
    fn body_teardown_prunes() -> R {
        let r = reg();
        let a = Arc::new(Obj(1));
        r.insert(1, &a);
        if r.len() != 1 {
            return Err("insert did not add an entry");
        }
        r.remove(1);
        if r.len() != 0 {
            return Err("remove did not drop the entry — the table leaks one slot per object");
        }
        // Idempotent: a create that failed after assigning an id, or a double
        // teardown, must not panic or disturb a neighbour.
        r.remove(1);
        r.insert(1, &a);
        r.remove(2);
        if r.len() != 1 {
            return Err("remove of an absent id disturbed the table");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_teardown_prunes_pos() -> TestResult {
        wrap(body_teardown_prunes())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_teardown_prunes_pos);

    /// The real objects, wired through their `Drop`. Separate from the generic
    /// smoke above because the wiring — `BpfMap::create` inserting and
    /// `Drop for BpfMap` removing — is what the syscall path actually depends
    /// on, and it lives in another module where it can be deleted without any
    /// of the tests above going red.
    fn body_map_drop_unregisters() -> R {
        use crate::map::{BpfMap, BpfMapCap, MapAttr, MapKind};
        use narf_capabilities::{Cap, Grant};

        // One bootstrap for this smoke; `Cap::bootstrap()` allocates an
        // object-table slot per call.
        let cap: Cap<BpfMapCap, Grant> = Cap::bootstrap();
        let m = BpfMap::create(
            &cap,
            MapAttr {
                kind: MapKind::Array,
                key_size: 4,
                value_size: 8,
                max_entries: 2,
            },
            alloc::string::String::from("idreg"),
        )
        .map_err(|_| "BpfMap::create failed")?;
        let id = m.id;
        let before = maps().len();
        if maps().get(id).is_none() {
            return Err("a created map is not reachable by its id");
        }
        if next_id_reaches(id) != Some(true) {
            return Err("a created map is not reachable by walking GET_NEXT_ID");
        }
        drop(m);
        if maps().get(id).is_some() {
            return Err("a dropped map is still reachable by its id");
        }
        if maps().len() != before - 1 {
            return Err("dropping a map did not prune its id entry — the table leaks");
        }
        if next_id_reaches(id) != Some(false) {
            return Err("GET_NEXT_ID still walks over a dropped map's id");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_map_drop_unregisters_pos() -> TestResult {
        wrap(body_map_drop_unregisters())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_map_drop_unregisters_pos);

    /// Whether an id-walk from 0 reaches `want`. `None` never happens; the
    /// `Option` is only so the assertion above reads as one comparison.
    fn next_id_reaches(want: u32) -> Option<bool> {
        let mut cur = 0u32;
        while let Some(n) = maps().next_id(cur) {
            if n == want {
                return Some(true);
            }
            cur = n;
        }
        Some(false)
    }

    /// Ids are not reused. Two maps created back to back get different ids, and
    /// the id of a map that has been freed is not handed to the next one — the
    /// property that stops a loader's cached id from silently addressing
    /// someone else's object.
    fn body_ids_not_reused() -> R {
        use crate::map::{BpfMap, BpfMapCap, MapAttr, MapKind};
        use narf_capabilities::{Cap, Grant};

        let cap: Cap<BpfMapCap, Grant> = Cap::bootstrap();
        let attr = MapAttr {
            kind: MapKind::Array,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        };
        let mk = || BpfMap::create(&cap, attr, alloc::string::String::new());

        let first = mk().map_err(|_| "BpfMap::create failed")?;
        let first_id = first.id;
        drop(first);
        let second = mk().map_err(|_| "BpfMap::create failed")?;
        if second.id == first_id {
            return Err("a freed map's id was handed to the next map — ids must never be reused");
        }
        let third = mk().map_err(|_| "BpfMap::create failed")?;
        if third.id == second.id {
            return Err("two live maps share an id");
        }
        if third.id <= second.id {
            return Err("map ids are not monotonically increasing");
        }
        Ok(())
    }
    fn smoke_bpf_idreg_ids_not_reused_pos() -> TestResult {
        wrap(body_ids_not_reused())
    }
    kernel_test_in!("bpf", smoke_bpf_idreg_ids_not_reused_pos);
}

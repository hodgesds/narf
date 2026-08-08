//! BPF links — an *owning* handle for an attach.
//!
//! `attach::attach_probe` and `attach_xdp::attach` install a program and then
//! forget about it: the hook's own table holds the `Arc<BpfProg>`, and undoing
//! the attach means knowing the target again and calling the matching detach.
//! That is fine for kernel code, which knows both. It is not enough for
//! `bpf(2)`, where the modern API (`BPF_LINK_CREATE`, which is what libbpf and
//! systemd reach for) hands userspace a **file descriptor whose close undoes
//! the attach**. This module is that handle.
//!
//! ## The two properties a link owes its holder
//!
//! 1. **Dropping the link detaches.** [`BpfLink::drop`] calls
//!    [`BpfLink::detach`], so the last `close(2)` on the fd tears the hook
//!    down. Nothing else is required of the fd layer: dropping the `FdEntry`
//!    drops the `Arc<dyn FileOps>`, which drops the [`LinkFile`], which drops
//!    the `Arc<BpfLink>`. A `dup`ed fd keeps the link alive, which is the same
//!    thing it does on Linux.
//! 2. **The program outlives the attach.** The link holds its own
//!    `Arc<BpfProg>` for exactly as long as it is attached, so closing the
//!    *program* fd while a link is live cannot free a running program.
//!
//! ## Ids
//!
//! Every link also gets a boot-unique `u32` id and an entry in
//! [`crate::idreg::links`], which is what `BPF_LINK_GET_NEXT_ID` walks and
//! `BPF_LINK_GET_FD_BY_ID` resolves. The registry holds a `Weak`, so the id
//! never keeps a link — and therefore never keeps an *attach* — alive; the
//! entry is pruned in [`BpfLink::drop`], which is the same place the detach
//! happens. A link fetched by id holds its own `Arc`, so it too must be closed
//! before the attach comes down, exactly as a `dup`ed fd would.
//!
//! ## Why there is an owner table
//!
//! Every NARF hook this module can reach is single-slot and its detach is
//! keyed only by the target — `HandlerTable::unregister(probe_id)` and
//! `remove_xdp(iface)` remove *whatever is there*, not "the thing this link
//! installed". Without a record of who installed what, a `BPF_PROG_DETACH` on
//! a link-held target would silently unhook the link's program, and the link's
//! own later drop would then unhook whatever had replaced it. The owner table
//! below records one claim per target so both of those are `EBUSY` at the
//! syscall boundary instead.
//!
//! The table governs claims made *through `bpf(2)`* only. Kernel code calling
//! `attach_probe` directly (the in-tree tracing users, and the smokes in
//! `tests.rs`) does not claim, and is not protected from a syscall-driven
//! detach of the same probe id — recording that here rather than pretending
//! otherwise, because the alternative is a comment this code does not enforce.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::bypass::classifier::ClassifyError;
use narf_tracing::dispatch::{ProbeHandlerInstall, RegisterError};

use crate::attach::AttachError;
use crate::prog::{BpfAttach, BpfProg};

/// What a link (or a bare `BPF_PROG_ATTACH`) is attached to.
///
/// One variant per attach surface NARF actually has. Linux's
/// `enum bpf_attach_type` is much wider; the mapping from it to this — and the
/// `ENOTSUP` for everything with no variant here — lives at the syscall
/// boundary, because it is ABI translation rather than runtime state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkTarget {
    /// A dynamic probe site, by `narf_tracing::dispatch` probe id.
    Probe(u32),
    /// An interface's XDP hook, by interface name.
    Xdp(String),
}

/// Why a link operation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// A capability presented for the attach was revoked.
    AuthorityRevoked,
    /// The program was verified for a context this hook does not provide.
    ///
    /// Spec §4.5 makes this a type error at attach. Both hooks this module
    /// reaches are `Atomic`, so a `Sleepable` program is refused here rather
    /// than declining at run time — which for XDP meant the interface looked
    /// filtered and was not.
    ContextMismatch,
    /// Something is already attached to this target through `bpf(2)`.
    Busy,
    /// The probe dispatcher's handler table is full.
    TableFull,
    /// Nothing is attached (detaching a target that was never claimed, or a
    /// link that has already been detached).
    NotAttached,
    /// `BPF_F_REPLACE` named a program that is not the one the link holds.
    ProgMismatch,
    /// This target has no atomic program-replace operation. See
    /// [`BpfLink::update`].
    NoAtomicReplace,
    /// The hook refused for a reason with no more specific variant.
    Refused,
}

/// The capabilities a link needs for the whole of its life.
///
/// `&'static` deliberately: a link's *drop* must be able to detach, and a drop
/// cannot be handed anything. `Cap::bootstrap()` allocates an object-table slot
/// per call, so these are minted once by the caller and cached — never per
/// attach.
#[derive(Copy, Clone, Debug)]
pub struct LinkCaps {
    /// Gates attach/detach on every surface.
    pub attach: &'static Cap<BpfAttach, Grant>,
    /// Gates handler (un)registration in `narf_tracing::dispatch`. A distinct
    /// authority from `attach`: registering a probe handler is a separate grant
    /// from arming the site.
    pub probe_install: &'static Cap<ProbeHandlerInstall, Grant>,
}

/// Who holds the single claim on a target.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Owner {
    /// A [`BpfLink`], by id. Detaching it is the link's job (or its drop's).
    Link(u32),
    /// A bare `BPF_PROG_ATTACH`, undone only by `BPF_PROG_DETACH`.
    Prog,
}

/// Boot-lifetime, monotone, and never handed back — the same discipline
/// `prog.rs` and `map.rs` use, and for the same reason: a loader that cached a
/// link id must never find it addressing a different attach. 1, because 0 is
/// "no link" everywhere in the `bpf(2)` ABI. `u32` because that is the width
/// `bpf_attr.link_id` and `bpf_link_info.id` have.
static NEXT_LINK_ID: AtomicU32 = AtomicU32::new(1);
/// The claim table. The `bool` is "a detach is in flight for this entry".
///
/// A detach cannot be a single `retain`, because the claim is the *only*
/// serialisation for an XDP target: `install_xdp` replaces whatever is on the
/// interface rather than refusing (`net/src/bypass/classifier.rs`), so a create
/// that slips in between "claim released" and "hook torn down" installs a
/// program that the in-flight `do_detach` then removes — leaving the new link
/// reporting attached, holding the claim, with nothing actually hooked, and
/// `XDP_ANY` false so every frame is passed. Fail-open, from a legal sequence of
/// two `bpf(2)` calls.
///
/// So a detach *marks* its entry instead of removing it. The entry keeps
/// refusing [`claim`] for the whole teardown and is removed only afterwards.
static OWNERS: IrqSafeSpinLock<Vec<(LinkTarget, Owner, bool, u32)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Take the claim on `target` for `owner`, recording the id of the program it
/// attaches so `BPF_PROG_QUERY` can name it. `false` if it is already claimed —
/// including by an entry whose detach is still in flight.
fn claim(target: &LinkTarget, owner: Owner, prog_id: u32) -> bool {
    let mut g = OWNERS.lock();
    if g.iter().any(|(t, _, _, _)| t == target) {
        return false;
    }
    g.push((target.clone(), owner, false, prog_id));
    true
}

/// Begin dropping `owner`'s claim: the entry stops answering to `owner` but
/// stays in the table, so `claim` keeps refusing `target`. `false` if `owner`
/// did not hold a claim that was not already detaching — which is also what
/// serialises two concurrent detaches of the same target.
///
/// Every caller must pair this with [`finish_unclaim`] once the hook is down.
fn begin_unclaim(target: &LinkTarget, owner: Owner) -> bool {
    let mut g = OWNERS.lock();
    for (t, o, detaching, _) in g.iter_mut() {
        if t == target && *o == owner && !*detaching {
            *detaching = true;
            return true;
        }
    }
    false
}

/// Remove the entry [`begin_unclaim`] marked, releasing `target`.
fn finish_unclaim(target: &LinkTarget) {
    let mut g = OWNERS.lock();
    g.retain(|(t, _, detaching, _)| !(t == target && *detaching));
}

/// Release `owner`'s claim outright.
///
/// Only for the unwind path where `do_attach` failed: nothing was ever
/// installed, so there is no tear-down for the target to stay reserved across
/// and the two-phase dance would be noise. Anything that *did* attach must use
/// [`begin_unclaim`] / [`finish_unclaim`].
fn release_claim(target: &LinkTarget, owner: Owner) {
    let mut g = OWNERS.lock();
    g.retain(|(t, o, _, _)| !(t == target && *o == owner));
}

/// The id of the program currently attached to `target`, or `None` if nothing is
/// (or a detach is in flight). This is what `BPF_PROG_QUERY` reports.
#[must_use]
pub fn attached_prog_id(target: &LinkTarget) -> Option<u32> {
    OWNERS
        .lock()
        .iter()
        .find(|(t, _, detaching, _)| t == target && !*detaching)
        .map(|(_, _, _, id)| *id)
}

/// Update the recorded program id after a link swaps its program in place, so
/// `BPF_PROG_QUERY` keeps naming the *current* one.
fn set_attached_prog_id(target: &LinkTarget, prog_id: u32) {
    for entry in OWNERS.lock().iter_mut() {
        if entry.0 == *target && !entry.2 {
            entry.3 = prog_id;
        }
    }
}

/// Whether anything reached through `bpf(2)` is attached to `target`.
#[must_use]
pub fn is_claimed(target: &LinkTarget) -> bool {
    OWNERS.lock().iter().any(|(t, _, _, _)| t == target)
}

impl From<AttachError> for LinkError {
    fn from(e: AttachError) -> Self {
        match e {
            AttachError::AuthorityRevoked => LinkError::AuthorityRevoked,
            AttachError::ContextMismatch => LinkError::ContextMismatch,
            AttachError::Register(RegisterError::AuthorityRevoked) => LinkError::AuthorityRevoked,
            AttachError::Register(RegisterError::DuplicateProbeId) => LinkError::Busy,
            AttachError::Register(RegisterError::TableFull) => LinkError::TableFull,
        }
    }
}

impl From<ClassifyError> for LinkError {
    fn from(e: ClassifyError) -> Self {
        match e {
            ClassifyError::CapRevoked => LinkError::AuthorityRevoked,
            ClassifyError::WrongContext => LinkError::ContextMismatch,
            ClassifyError::AlreadyAttached => LinkError::Busy,
            // `WrongCapKind` cannot arise from this module — every call site
            // passes a `Cap<BpfAttach, _>`, and the kind is part of that type.
            // It still needs an arm, and lumping it with the rest is right:
            // it would be a NARF bug, not something a caller can provoke.
            ClassifyError::WrongCapKind
            | ClassifyError::Duplicate
            | ClassifyError::UmemAccessDenied
            | ClassifyError::NoFillBuffer => LinkError::Refused,
        }
    }
}

/// Install `prog` on `target` without a link.
///
/// This is `BPF_PROG_ATTACH`: the hook's own table holds the program, and only
/// `BPF_PROG_DETACH` takes it back out.
///
/// # Errors
///
/// [`LinkError::Busy`] if the target is already claimed; otherwise whatever the
/// hook refused with.
pub fn prog_attach(
    caps: LinkCaps,
    target: &LinkTarget,
    prog: Arc<BpfProg>,
) -> Result<(), LinkError> {
    caps.attach
        .check_live()
        .map_err(|_| LinkError::AuthorityRevoked)?;
    if !claim(target, Owner::Prog, prog.id) {
        return Err(LinkError::Busy);
    }
    if let Err(e) = do_attach(&caps, target, prog) {
        release_claim(target, Owner::Prog);
        return Err(e);
    }
    Ok(())
}

/// Undo a [`prog_attach`].
///
/// # Errors
///
/// [`LinkError::NotAttached`] if nothing was attached this way — including the
/// case where a *link* owns the target, which is [`LinkError::Busy`] instead so
/// that a caller can tell "nothing there" from "not yours to remove".
pub fn prog_detach(caps: LinkCaps, target: &LinkTarget) -> Result<(), LinkError> {
    caps.attach
        .check_live()
        .map_err(|_| LinkError::AuthorityRevoked)?;
    // Marked rather than dropped, for the reason in [`OWNERS`]. This is also
    // what serialises two concurrent `BPF_PROG_DETACH`es of the same target:
    // only one can mark the entry, and the loser reports `Busy` (the target is
    // occupied by a tear-down) rather than racing into `do_detach` and removing
    // whatever had been attached in between.
    if !begin_unclaim(target, Owner::Prog) {
        return Err(if is_claimed(target) {
            LinkError::Busy
        } else {
            LinkError::NotAttached
        });
    }
    let r = do_detach(&caps, target);
    finish_unclaim(target);
    r
}

fn do_attach(caps: &LinkCaps, target: &LinkTarget, prog: Arc<BpfProg>) -> Result<(), LinkError> {
    match target {
        LinkTarget::Probe(id) => {
            crate::attach::attach_probe(caps.attach, caps.probe_install, *id, prog)
                .map_err(LinkError::from)
        }
        LinkTarget::Xdp(iface) => {
            crate::attach_xdp::attach(caps.attach, iface.clone(), prog).map_err(LinkError::from)
        }
    }
}

fn do_detach(caps: &LinkCaps, target: &LinkTarget) -> Result<(), LinkError> {
    match target {
        LinkTarget::Probe(id) => {
            crate::attach::detach_probe(caps.probe_install, *id).map_err(LinkError::from)
        }
        LinkTarget::Xdp(iface) => crate::attach_xdp::detach(caps.attach, iface)
            .map(|_| ())
            .map_err(LinkError::from),
    }
}

/// An owning handle on one attach.
#[derive(Debug)]
pub struct BpfLink {
    id: u32,
    target: LinkTarget,
    caps: LinkCaps,
    /// The attached program, and the "still attached" flag in one: `take()`ing
    /// it under the lock is the single point that decides which caller performs
    /// the detach, so a concurrent `BPF_LINK_DETACH` and `close(2)` cannot both
    /// tear the hook down.
    prog: IrqSafeSpinLock<Option<Arc<BpfProg>>>,
}

impl BpfLink {
    /// Attach `prog` to `target` and return the owning handle.
    ///
    /// # Errors
    ///
    /// [`LinkError::Busy`] if the target is already claimed through `bpf(2)`;
    /// [`LinkError::ContextMismatch`] for a program verified for the wrong
    /// execution context; otherwise whatever the hook refused with.
    pub fn create(
        caps: LinkCaps,
        target: LinkTarget,
        prog: Arc<BpfProg>,
    ) -> Result<Arc<Self>, LinkError> {
        // Checked here as well as inside the attach adapters: the claim below
        // must not be taken (and then have to be unwound) on behalf of an
        // authority that is already dead.
        caps.attach
            .check_live()
            .map_err(|_| LinkError::AuthorityRevoked)?;
        let id = NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed);
        if !claim(&target, Owner::Link(id), prog.id) {
            return Err(LinkError::Busy);
        }
        if let Err(e) = do_attach(&caps, &target, Arc::clone(&prog)) {
            release_claim(&target, Owner::Link(id));
            return Err(e);
        }
        let link = Arc::new(Self {
            id,
            target,
            caps,
            prog: IrqSafeSpinLock::new(Some(prog)),
        });
        // Registered only once the attach has actually happened, and only from
        // the `Arc` that will be handed out — the registry holds a `Weak`, so
        // an entry made before there is an `Arc` to downgrade could not exist,
        // and one made before the attach succeeded would be reachable by
        // `BPF_LINK_GET_FD_BY_ID` while naming nothing.
        crate::idreg::links().insert(id, &link);
        Ok(link)
    }

    /// This link's id. Unique for the life of the kernel.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// What it is attached to.
    #[must_use]
    pub fn target(&self) -> &LinkTarget {
        &self.target
    }

    /// The attached program, or `None` once detached.
    #[must_use]
    pub fn prog(&self) -> Option<Arc<BpfProg>> {
        self.prog.lock().clone()
    }

    /// Whether the link still holds its attach.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.prog.lock().is_some()
    }

    /// Undo the attach. Idempotent in the sense that the second call reports
    /// [`LinkError::NotAttached`] rather than tearing down someone else's
    /// program.
    ///
    /// # Errors
    ///
    /// [`LinkError::NotAttached`] if already detached; [`LinkError::AuthorityRevoked`]
    /// if the capability needed to undo the attach has since been revoked — in
    /// which case the hook **stays installed**. That is a leak of one attach,
    /// not a use-after-free: the hook's table still owns its own `Arc<BpfProg>`.
    pub fn detach(&self) -> Result<(), LinkError> {
        // Take first, then tear down. The `take()` is what serialises two
        // concurrent detaches; doing the tear-down first would let both of them
        // reach `unregister`, and the second would remove whatever had been
        // attached in between.
        let taken = self.prog.lock().take();
        let Some(prog) = taken else {
            return Err(LinkError::NotAttached);
        };
        // The claim is *marked*, not dropped, so the target stays unclaimable
        // for the whole tear-down — see [`OWNERS`] for the fail-open XDP race
        // that releasing it here opened. Released after `do_detach` regardless
        // of the result: on `AuthorityRevoked` the hook stays installed, but
        // `install_xdp` replaces rather than refuses, so a later attach both
        // reclaims the target and drops the stranded program. Holding the claim
        // instead would strand it permanently, since `self.prog` is already
        // taken and a second `detach` now reports `NotAttached`.
        let held = begin_unclaim(&self.target, Owner::Link(self.id));
        let r = do_detach(&self.caps, &self.target);
        if held {
            finish_unclaim(&self.target);
        }
        // Explicit, and after the lock is released: dropping the last `Arc` to
        // a program frees its image, and doing that under an IRQ-masked
        // spinlock puts the allocator on the wrong side of the lock.
        drop(prog);
        r
    }

    /// Replace the attached program.
    ///
    /// `expected` implements `BPF_F_REPLACE`: the update only applies if the
    /// link currently holds that exact program.
    ///
    /// # Errors
    ///
    /// [`LinkError::NoAtomicReplace`] for a probe link. `narf_tracing`'s
    /// `HandlerTable` has `register` and `unregister` and no replace, so a swap
    /// would have to unregister and re-register — and every probe that fired in
    /// the window between them would silently miss the program. Linux's
    /// `bpf_link_update` is atomic, and a non-atomic imitation of it is the
    /// kind of "works in the test, drops events in production" divergence this
    /// subsystem exists to avoid. The XDP path *does* have an atomic replace
    /// (`install_xdp` swaps the slot under one lock) and is supported.
    pub fn update(
        &self,
        new_prog: Arc<BpfProg>,
        expected: Option<&Arc<BpfProg>>,
    ) -> Result<(), LinkError> {
        let LinkTarget::Xdp(iface) = &self.target else {
            // LINUX-GAP: `BPF_LINK_UPDATE` on a tracing link. See above.
            return Err(LinkError::NoAtomicReplace);
        };
        let mut slot = self.prog.lock();
        let Some(cur) = slot.as_ref() else {
            return Err(LinkError::NotAttached);
        };
        if let Some(exp) = expected {
            if !Arc::ptr_eq(cur, exp) {
                return Err(LinkError::ProgMismatch);
            }
        }
        crate::attach_xdp::attach(self.caps.attach, iface.clone(), Arc::clone(&new_prog))?;
        // Keep `BPF_PROG_QUERY` naming the program now on the hook.
        set_attached_prog_id(&self.target, new_prog.id);
        let old = slot.replace(new_prog);
        drop(slot);
        // As in `detach`: the old program's last reference may die here.
        drop(old);
        Ok(())
    }
}

impl Drop for BpfLink {
    fn drop(&mut self) {
        // The property the fd layer relies on: the last `close(2)` drops the
        // last `Arc<BpfLink>`, and *this* is what makes that a detach. There is
        // no `release` hook on `FileOps` to do it anywhere else.
        let _ = self.detach();
        // The other half of `idreg`'s contract. The `Weak` already makes a
        // stale id a failed lookup rather than a dangling handle; this stops
        // the entry — and the `Arc` control block it pins — outliving the link.
        // Safe to call from here precisely because `IdRegistry::remove` never
        // materialises an `Arc<BpfLink>` under its lock: doing so would re-enter
        // this `Drop`.
        crate::idreg::links().remove(self.id);
    }
}

/// A link behind a file descriptor.
///
/// Anon-fd pattern, as `ProgFile` and `MapFile` use. Read and write are
/// unsupported: a link fd is a handle, not a stream, and Linux's link fds
/// answer `read(2)` the same way.
#[derive(Debug)]
pub struct LinkFile {
    link: Arc<BpfLink>,
}

impl LinkFile {
    /// Wrap a link for installation in an fd table.
    #[must_use]
    pub fn new(link: Arc<BpfLink>) -> Self {
        Self { link }
    }

    /// The link behind this fd.
    #[must_use]
    pub fn link(&self) -> Arc<BpfLink> {
        Arc::clone(&self.link)
    }
}

impl narf_filesystem::FileOps for LinkFile {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    /// The hook every fd-to-link recovery goes through.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────
//
// Here rather than in `crate::tests` because every one of them needs the real
// probe dispatcher or the real network classifier — the two global tables a
// link's drop reaches into — and because the property under test (dropping the
// handle undoes the attach) is this module's alone.

#[cfg(feature = "kernel-test")]
mod smokes {
    use super::*;

    use narf_bpf_isa::encode::encode;
    use narf_bpf_isa::{Decoded, Insn, Reg, Source};
    use narf_bpf_verifier::kfunc::Context;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_net::bypass::classifier::{classify, Verdict};
    use narf_tracing::dispatch::{self, ProbeArgs};

    use crate::prog::{BpfProgLoad, LoadRequest};

    /// Minted once and cached — `Cap::bootstrap()` allocates an object-table
    /// slot per call, so per-test minting would leak one per smoke run.
    fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
        static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
            IrqSafeSpinLock::new(None);
        let mut g = SLOT.lock();
        if g.is_none() {
            let c: &'static _ =
                alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    Cap::<BpfProgLoad, Grant>::bootstrap(),
                ));
            *g = Some(c);
        }
        g.expect("just installed")
    }

    /// As [`load_cap`]: one pair for the whole smoke run.
    fn caps() -> LinkCaps {
        static SLOT: IrqSafeSpinLock<Option<LinkCaps>> = IrqSafeSpinLock::new(None);
        let mut g = SLOT.lock();
        if g.is_none() {
            let attach: &'static _ =
                alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    Cap::<BpfAttach, Grant>::bootstrap(),
                ));
            let probe_install: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(
                Cap::<ProbeHandlerInstall, Grant>::bootstrap(),
            ));
            *g = Some(LinkCaps {
                attach,
                probe_install,
            });
        }
        g.expect("just installed")
    }

    /// `r0 = v; exit`, encoded through the real assembler.
    fn ret_prog(name: &str, v: i32, context: Context) -> Option<Arc<BpfProg>> {
        let mut insns: Vec<Insn> = Vec::new();
        for d in [
            Decoded::Mov {
                wide: true,
                dst: Reg::new(0).expect("r0"),
                src: Source::Imm(v),
                sign_extend: None,
            },
            Decoded::Exit,
        ] {
            insns.extend_from_slice(encode(d).slots());
        }
        BpfProg::load(
            load_cap(),
            LoadRequest {
                name: String::from(name),
                insns,
                context,
                maps: Vec::new(),
            },
        )
        .ok()
    }

    /// `classify()`'s verdict, as a pair of predicates — `Verdict` carries a
    /// payload on `Consumed` and so is not `PartialEq`.
    fn dropped(v: Verdict) -> bool {
        matches!(v, Verdict::Dropped)
    }
    fn passed_through(v: Verdict) -> bool {
        matches!(v, Verdict::PassThrough)
    }

    // ── tracing links ───────────────────────────────────────────────

    /// The property the fd layer depends on: dropping the link detaches.
    fn smoke_bpf_link_drop_detaches_the_probe() -> TestResult {
        let Some(prog) = ret_prog("linkprobe", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), Arc::clone(&prog)) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed on a fresh probe id"),
        };

        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("the linked program did not run when the probe fired");
        }

        // The whole point. No explicit detach — just release the handle.
        drop(link);

        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("the probe still ran the program after the link was dropped");
        }
        // …and the claim came back, or the target would be `EBUSY` forever.
        if is_claimed(&LinkTarget::Probe(probe_id)) {
            return TestResult::Fail("dropping the link left its claim behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_drop_detaches_the_probe);

    /// A link keeps its program alive after every other reference is gone.
    ///
    /// This is what makes `close(prog_fd)` safe while a link is live: the fd's
    /// `Arc` is not the last one.
    fn smoke_bpf_link_holds_the_program_alive() -> TestResult {
        let Some(prog) = ret_prog("linkalive", 7, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), prog) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        // The caller's reference was moved into `create`, so the link and the
        // dispatcher's handler are the only holders now — and the program must
        // still be runnable through both.
        dispatch::fire(probe_id, ProbeArgs::none());
        let Some(held) = link.prog() else {
            return TestResult::Fail("an attached link reported no program");
        };
        if held.runs() != 1 || held.accumulated() != 7 {
            return TestResult::Fail("the program the link holds is not the one that ran");
        }
        drop(link);
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_holds_the_program_alive);

    /// Two links cannot share one target, and the refusal does not disturb the
    /// first.
    ///
    /// For a *probe* target the duplicate is caught twice over — the owner
    /// table refuses the claim, and `HandlerTable::register` would refuse the
    /// duplicate probe id anyway. `smoke_bpf_link_second_link_on_an_xdp_target_is_busy`
    /// is the one that pins the owner table itself, because `install_xdp` has
    /// no such backstop.
    fn smoke_bpf_link_second_link_on_a_target_is_busy() -> TestResult {
        let (Some(a), Some(b)) = (
            ret_prog("linkbusy_a", 1, Context::Atomic),
            ret_prog("linkbusy_b", 2, Context::Atomic),
        ) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), Arc::clone(&a)) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        match BpfLink::create(caps(), LinkTarget::Probe(probe_id), b) {
            Err(LinkError::Busy) => {}
            Err(_) => return TestResult::Fail("the second link failed for the wrong reason"),
            Ok(second) => {
                drop(second);
                drop(link);
                return TestResult::Fail("two links attached to one probe id");
            }
        }
        // The first link must still be the one that runs.
        dispatch::fire(probe_id, ProbeArgs::none());
        if a.runs() != 1 {
            return TestResult::Fail("the refused second link disturbed the first");
        }
        drop(link);
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_second_link_on_a_target_is_busy);

    /// Spec §4.5: a probe site is `Atomic`, so a `Sleepable` program is a type
    /// error at attach — not a run-time surprise.
    fn smoke_bpf_link_rejects_a_sleepable_program() -> TestResult {
        let Some(prog) = ret_prog("linksleep", 1, Context::Sleepable) else {
            return TestResult::Fail("load rejected a trivial sleepable program");
        };
        let probe_id = dispatch::reserve_probe_id();
        match BpfLink::create(caps(), LinkTarget::Probe(probe_id), prog) {
            Err(LinkError::ContextMismatch) => {}
            Err(_) => return TestResult::Fail("the attach failed for the wrong reason"),
            Ok(l) => {
                drop(l);
                return TestResult::Fail("a sleepable program linked to an atomic hook");
            }
        }
        // A refused create must not leave the target claimed.
        if is_claimed(&LinkTarget::Probe(probe_id)) {
            return TestResult::Fail("a refused link left its claim behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_rejects_a_sleepable_program);

    /// Holding a `Cap` proves prior grant; only `check_live()` proves current
    /// validity.
    fn smoke_bpf_link_revoked_cap_cannot_attach() -> TestResult {
        let Some(prog) = ret_prog("linkrevoked", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        // A cap of this smoke's own, so revoking it cannot disturb the cached
        // pair every other test uses.
        let attach: &'static _ =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<BpfAttach, Grant>::bootstrap()));
        let dead = LinkCaps {
            attach,
            probe_install: caps().probe_install,
        };
        attach.revoke();
        let probe_id = dispatch::reserve_probe_id();
        match BpfLink::create(dead, LinkTarget::Probe(probe_id), prog) {
            Err(LinkError::AuthorityRevoked) => {}
            Err(_) => return TestResult::Fail("the attach failed for the wrong reason"),
            Ok(l) => {
                drop(l);
                return TestResult::Fail("a revoked capability attached a program");
            }
        }
        if is_claimed(&LinkTarget::Probe(probe_id)) {
            return TestResult::Fail("a revoked-cap attach left a claim behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_revoked_cap_cannot_attach);

    /// `BPF_LINK_DETACH` is explicit; a second one reports "nothing attached"
    /// rather than removing whatever arrived in the meantime.
    fn smoke_bpf_link_detach_is_not_repeatable() -> TestResult {
        let Some(prog) = ret_prog("linkdetach", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), prog) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        if link.detach().is_err() {
            return TestResult::Fail("the first detach failed");
        }
        if link.is_attached() {
            return TestResult::Fail("a detached link still reports itself attached");
        }
        // Re-attach something else to the same id. A second detach on the dead
        // link must leave it alone — that is the bug the take-then-tear-down
        // ordering in `detach` exists to prevent.
        let Some(other) = ret_prog("linkdetach2", 2, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let second = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), Arc::clone(&other))
        {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("re-linking the freed probe id failed"),
        };
        if link.detach() != Err(LinkError::NotAttached) {
            return TestResult::Fail("detaching a dead link did not report NotAttached");
        }
        dispatch::fire(probe_id, ProbeArgs::none());
        if other.runs() != 1 {
            return TestResult::Fail("a dead link's detach removed the live link's program");
        }
        drop(second);
        drop(link);
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_detach_is_not_repeatable);

    /// `BPF_LINK_UPDATE` on a tracing link is `NoAtomicReplace`, and says so
    /// rather than performing a lossy unregister/register pair.
    fn smoke_bpf_link_update_on_a_probe_is_refused() -> TestResult {
        let (Some(a), Some(b)) = (
            ret_prog("linkupd_a", 1, Context::Atomic),
            ret_prog("linkupd_b", 2, Context::Atomic),
        ) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), Arc::clone(&a)) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        let r = link.update(b, None);
        // The refusal must be inert: the original program is still the attached
        // one, which is the difference between "refused" and "half-applied".
        dispatch::fire(probe_id, ProbeArgs::none());
        drop(link);
        if r != Err(LinkError::NoAtomicReplace) {
            return TestResult::Fail("updating a probe link did not report NoAtomicReplace");
        }
        if a.runs() != 1 {
            return TestResult::Fail("a refused update disturbed the attached program");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_update_on_a_probe_is_refused);

    // ── XDP links ───────────────────────────────────────────────────

    /// `XDP_DROP` while linked, pass-through once the link is gone.
    ///
    /// Driven through the real `classify()` entry point, so it exercises the
    /// same path a NIC's RX takes.
    fn smoke_bpf_link_drop_detaches_xdp() -> TestResult {
        const IFACE: &str = "bpf-link-xdp0";
        // 1 is Linux's `XDP_DROP`, which `BpfXdp::run` matches on.
        let Some(prog) = ret_prog("linkxdp", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let link = match BpfLink::create(
            caps(),
            LinkTarget::Xdp(String::from(IFACE)),
            Arc::clone(&prog),
        ) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed for an XDP target"),
        };
        let frame = [0u8; 64];
        if !dropped(classify(IFACE, &frame)) {
            return TestResult::Fail("the linked XDP program did not drop the frame");
        }
        drop(link);
        if !passed_through(classify(IFACE, &frame)) {
            return TestResult::Fail("frames were still dropped after the link was dropped");
        }
        if prog.runs() != 1 {
            return TestResult::Fail("the program ran for a frame it was no longer attached for");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_drop_detaches_xdp);

    /// Two links cannot share an interface either — and here the owner table is
    /// the *only* thing enforcing it.
    ///
    /// `install_xdp` replaces the interface's slot silently (that is what
    /// `remove_xdp`-then-`install` would have to do, and it does it under one
    /// lock). So without a claim the second link would take the interface, and
    /// then whichever link dropped first would remove the *other* one's
    /// program. The tail of this test is what catches that: after dropping the
    /// second (refused) attempt's handle, the first link's program must still be
    /// the one deciding.
    fn smoke_bpf_link_second_link_on_an_xdp_target_is_busy() -> TestResult {
        const IFACE: &str = "bpf-link-xdp3";
        let (Some(dropper), Some(passer)) = (
            ret_prog("linkxdpbusy_d", 1, Context::Atomic),
            ret_prog("linkxdpbusy_p", 2, Context::Atomic),
        ) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let link = match BpfLink::create(
            caps(),
            LinkTarget::Xdp(String::from(IFACE)),
            Arc::clone(&dropper),
        ) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed for an XDP target"),
        };
        let second = BpfLink::create(caps(), LinkTarget::Xdp(String::from(IFACE)), passer);
        let second_taken = second.is_ok();
        // Drop the interloper's handle before asserting, so that if it *did*
        // attach, its drop has had the chance to strip the interface — which is
        // the damage this test exists to detect.
        drop(second);
        let still_dropping = dropped(classify(IFACE, &[0u8; 64]));
        drop(link);
        if second_taken {
            return TestResult::Fail("a second link took an interface a link already held");
        }
        if !still_dropping {
            return TestResult::Fail("the first link's program is no longer on the interface");
        }
        if !passed_through(classify(IFACE, &[0u8; 64])) {
            return TestResult::Fail("dropping the surviving link left a program behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_second_link_on_an_xdp_target_is_busy);

    /// The XDP hook is `Atomic` too, and this is the check whose absence was
    /// worst.
    ///
    /// `BpfXdp::run` calls `run_atomic`, which returns `None` for a program
    /// verified for `Sleepable` — and `None` means "pass the frame", because
    /// dropping traffic when a filter cannot run would turn a resource limit
    /// into a network outage. So without the check the attach *succeeded* and
    /// the interface then failed open on every frame: filtered-looking and not
    /// filtered. The second half of this test is the part that matters — it
    /// checks no program was installed, not merely that an error came back.
    fn smoke_bpf_link_xdp_rejects_a_sleepable_program() -> TestResult {
        const IFACE: &str = "bpf-link-xdp2";
        let Some(prog) = ret_prog("linkxdpsleep", 1, Context::Sleepable) else {
            return TestResult::Fail("load rejected a trivial sleepable program");
        };
        match BpfLink::create(caps(), LinkTarget::Xdp(String::from(IFACE)), prog) {
            Err(LinkError::ContextMismatch) => {}
            Err(_) => return TestResult::Fail("the XDP attach failed for the wrong reason"),
            Ok(l) => {
                drop(l);
                return TestResult::Fail("a sleepable program attached to the XDP hook");
            }
        }
        if is_claimed(&LinkTarget::Xdp(String::from(IFACE))) {
            return TestResult::Fail("a refused XDP link left its claim behind");
        }
        // Nothing may be installed on the interface. A `run_atomic` that
        // declines yields `XdpAction::Pass`, which is indistinguishable from
        // "no program" by verdict alone — so this checks the classifier slot
        // through the one thing that *does* differ: a program that would have
        // dropped, attached afterwards, must be the one that runs.
        let Some(dropper) = ret_prog("linkxdpdrop", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let link = match BpfLink::create(
            caps(),
            LinkTarget::Xdp(String::from(IFACE)),
            Arc::clone(&dropper),
        ) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("the interface was left unusable by the refusal"),
        };
        let ok = dropped(classify(IFACE, &[0u8; 64]));
        drop(link);
        if !ok {
            return TestResult::Fail("the refused sleepable program was still on the interface");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_xdp_rejects_a_sleepable_program);

    /// An XDP link *does* have an atomic replace, and `BPF_F_REPLACE` guards it.
    fn smoke_bpf_link_update_swaps_the_xdp_program() -> TestResult {
        const IFACE: &str = "bpf-link-xdp1";
        let (Some(dropper), Some(passer)) = (
            ret_prog("linkxdp_d", 1, Context::Atomic),
            ret_prog("linkxdp_p", 2, Context::Atomic),
        ) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let link = match BpfLink::create(
            caps(),
            LinkTarget::Xdp(String::from(IFACE)),
            Arc::clone(&dropper),
        ) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed for an XDP target"),
        };
        let frame = [0u8; 64];
        if !dropped(classify(IFACE, &frame)) {
            return TestResult::Fail("the first program did not drop");
        }
        // `BPF_F_REPLACE` naming the wrong program must not apply.
        if link.update(Arc::clone(&passer), Some(&passer)) != Err(LinkError::ProgMismatch) {
            drop(link);
            return TestResult::Fail("BPF_F_REPLACE accepted the wrong expected program");
        }
        if !dropped(classify(IFACE, &frame)) {
            drop(link);
            return TestResult::Fail("a refused update changed the attached program");
        }
        if link.update(Arc::clone(&passer), Some(&dropper)).is_err() {
            drop(link);
            return TestResult::Fail("a correctly-guarded update was refused");
        }
        if !passed_through(classify(IFACE, &frame)) {
            drop(link);
            return TestResult::Fail("the updated program is not the one running");
        }
        drop(link);
        if !passed_through(classify(IFACE, &frame)) {
            return TestResult::Fail("dropping an updated link left a program behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_update_swaps_the_xdp_program);

    // ── link ids ────────────────────────────────────────────────────

    /// Whether an id-walk from 0 reaches `want`.
    ///
    /// Bounded: an id table that never ends is an infinite loop in every
    /// enumerating tool, and this walk is the same shape one performs.
    fn link_walk_reaches(want: u32) -> Option<bool> {
        let mut cur = 0u32;
        for _ in 0..100_000 {
            let n = crate::idreg::links().next_id(cur)?;
            if n == want {
                return Some(true);
            }
            if n <= cur {
                return None;
            }
            cur = n;
        }
        None
    }

    /// A live link is reachable by id and by walk; a dropped one is neither,
    /// and its table entry is gone rather than merely dead.
    ///
    /// The pruning half is the one that rots silently: a `Weak` entry left
    /// behind still answers `get` with `None`, so nothing *visible* breaks
    /// until the table has one stale slot per link this boot ever made. `len()`
    /// is the only way to see it.
    fn smoke_bpf_link_id_registered_and_pruned() -> TestResult {
        let Some(prog) = ret_prog("linkidreg", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), prog) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed on a fresh probe id"),
        };
        let id = link.id();
        if id == 0 {
            return TestResult::Fail("a link was assigned id 0, which means 'no link'");
        }
        let before = crate::idreg::links().len();
        match crate::idreg::links().get(id) {
            Some(found) if Arc::ptr_eq(&found, &link) => {}
            Some(_) => return TestResult::Fail("the link id resolved to a different link"),
            None => return TestResult::Fail("a created link is not reachable by its id"),
        }
        if link_walk_reaches(id) != Some(true) {
            return TestResult::Fail("a created link is not reachable by walking GET_NEXT_ID");
        }

        drop(link);

        if crate::idreg::links().get(id).is_some() {
            return TestResult::Fail("a dropped link is still reachable by its id");
        }
        if crate::idreg::links().len() != before - 1 {
            return TestResult::Fail(
                "dropping a link did not prune its id entry — the table leaks",
            );
        }
        if link_walk_reaches(id) == Some(true) {
            return TestResult::Fail("GET_NEXT_ID still walks over a dropped link's id");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_id_registered_and_pruned);

    /// A link fetched out of the registry keeps the attach alive — and, when it
    /// is the last holder, still detaches.
    ///
    /// This is the property `BPF_LINK_GET_FD_BY_ID` sells: the second handle is
    /// independent of the first. If it were not, closing the creating fd would
    /// tear the hook down under a caller that had just reopened it.
    fn smoke_bpf_link_id_holder_detaches_on_last_drop() -> TestResult {
        let Some(prog) = ret_prog("linkidhold", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let link = match BpfLink::create(caps(), LinkTarget::Probe(probe_id), Arc::clone(&prog)) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        let id = link.id();
        let Some(by_id) = crate::idreg::links().get(id) else {
            return TestResult::Fail("a live link did not resolve by id");
        };

        // Release the original. The attach must survive, because `by_id` is a
        // reference of its own.
        drop(link);
        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("the attach came down when a second reference was still held");
        }
        if crate::idreg::links().get(id).is_none() {
            return TestResult::Fail("the id stopped resolving while a reference was still held");
        }

        // Now the last one. `BpfLink::drop` is what makes this a detach, and
        // an id-obtained handle must run it just like the creating fd would.
        drop(by_id);
        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("dropping the id-obtained link did not detach the probe");
        }
        if is_claimed(&LinkTarget::Probe(probe_id)) {
            return TestResult::Fail("the id-obtained link's drop left the claim behind");
        }
        if crate::idreg::links().get(id).is_some() {
            return TestResult::Fail("the id still resolved after the last reference went away");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_id_holder_detaches_on_last_drop);

    /// Ids are monotone and never reused — the property that stops a cached id
    /// from silently addressing someone else's attach.
    fn smoke_bpf_link_ids_are_not_reused() -> TestResult {
        let mk = |name: &str| -> Option<Arc<BpfLink>> {
            let prog = ret_prog(name, 1, Context::Atomic)?;
            BpfLink::create(
                caps(),
                LinkTarget::Probe(dispatch::reserve_probe_id()),
                prog,
            )
            .ok()
        };
        let Some(first) = mk("linkidre1") else {
            return TestResult::Fail("BpfLink::create failed");
        };
        let dead = first.id();
        drop(first);
        let Some(second) = mk("linkidre2") else {
            return TestResult::Fail("BpfLink::create failed");
        };
        let Some(third) = mk("linkidre3") else {
            return TestResult::Fail("BpfLink::create failed");
        };
        let (a, b) = (second.id(), third.id());
        drop(second);
        drop(third);
        if a == dead {
            return TestResult::Fail("a freed link's id was handed to the next link");
        }
        if b == a {
            return TestResult::Fail("two live links share an id");
        }
        if a <= dead || b <= a {
            return TestResult::Fail("link ids are not monotonically increasing");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_link_ids_are_not_reused);

    // ── BPF_PROG_ATTACH (no link) ───────────────────────────────────

    /// The legacy pair: attach, fire, detach, fire again.
    fn smoke_bpf_prog_attach_detach_round_trip() -> TestResult {
        let Some(prog) = ret_prog("progattach", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let target = LinkTarget::Probe(probe_id);
        if prog_attach(caps(), &target, Arc::clone(&prog)).is_err() {
            return TestResult::Fail("prog_attach failed on a fresh probe id");
        }
        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("the attached program did not run");
        }
        if prog_detach(caps(), &target).is_err() {
            return TestResult::Fail("prog_detach failed");
        }
        dispatch::fire(probe_id, ProbeArgs::none());
        if prog.runs() != 1 {
            return TestResult::Fail("the program still ran after detach");
        }
        // Detaching again is `NotAttached`, not a silent success.
        if prog_detach(caps(), &target) != Err(LinkError::NotAttached) {
            return TestResult::Fail("detaching nothing did not report NotAttached");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_prog_attach_detach_round_trip);

    /// A link's target is not `BPF_PROG_DETACH`-able. Without the owner table
    /// this call would unhook the link's program and the link's own drop would
    /// then unhook whatever replaced it.
    fn smoke_bpf_prog_detach_cannot_take_a_link_target() -> TestResult {
        let Some(prog) = ret_prog("progdetach", 1, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial atomic program");
        };
        let probe_id = dispatch::reserve_probe_id();
        let target = LinkTarget::Probe(probe_id);
        let link = match BpfLink::create(caps(), target.clone(), Arc::clone(&prog)) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("BpfLink::create failed"),
        };
        let r = prog_detach(caps(), &target);
        dispatch::fire(probe_id, ProbeArgs::none());
        drop(link);
        if r != Err(LinkError::Busy) {
            return TestResult::Fail("BPF_PROG_DETACH on a link target did not report Busy");
        }
        if prog.runs() != 1 {
            return TestResult::Fail("the refused detach unhooked the link's program");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_prog_detach_cannot_take_a_link_target);

    /// A target stays unclaimable for the *whole* of a detach, not just up to
    /// the moment the claim is released.
    ///
    /// Releasing first is fail-open on XDP: `install_xdp` replaces rather than
    /// refuses, so a `LINK_CREATE` landing inside the window installs a program
    /// that the in-flight `do_detach` then removes with `remove_xdp(iface)` —
    /// which removes whatever is on the interface, not what the detaching link
    /// installed. The new link reports attached, holds the claim (so every
    /// later attach is `EBUSY` until its fd closes), and nothing is hooked:
    /// `XDP_ANY` goes false and a drop-based filter passes every frame.
    ///
    /// The window is one preemption wide and cannot be driven deterministically
    /// from a test, so this asserts the property that closes it — the claim
    /// outlives the tear-down — against the table directly.
    fn smoke_bpf_link_detach_keeps_the_target_claimed_until_the_hook_is_down() -> TestResult {
        let target = LinkTarget::Xdp(String::from("narf-detach-race-probe"));
        let owner = Owner::Link(u32::MAX);
        let racer = Owner::Link(u32::MAX - 1);

        if !claim(&target, owner, 1) {
            return TestResult::Fail("the test target was already claimed");
        }
        if !begin_unclaim(&target, owner) {
            release_claim(&target, owner);
            return TestResult::Fail("begin_unclaim refused a claim its owner held");
        }
        // Mid-tear-down. This is the racing `BPF_LINK_CREATE`.
        if claim(&target, racer, 2) {
            release_claim(&target, racer);
            finish_unclaim(&target);
            return TestResult::Fail(
                "a create claimed the target while a detach was still tearing the hook down",
            );
        }
        if !is_claimed(&target) {
            finish_unclaim(&target);
            return TestResult::Fail("a target being detached did not report as claimed");
        }
        // A second concurrent detach must lose rather than race into do_detach.
        if begin_unclaim(&target, owner) {
            finish_unclaim(&target);
            return TestResult::Fail("two concurrent detaches both took the same claim");
        }

        finish_unclaim(&target);
        if is_claimed(&target) {
            return TestResult::Fail("the claim outlived the detach that completed");
        }
        if !claim(&target, racer, 2) {
            return TestResult::Fail("the target was not reattachable after the detach finished");
        }
        release_claim(&target, racer);
        TestResult::Pass
    }
    kernel_test_in!(
        "bpf",
        smoke_bpf_link_detach_keeps_the_target_claimed_until_the_hook_is_down
    );
}

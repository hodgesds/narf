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
use core::sync::atomic::{AtomicU64, Ordering};

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
    Link(u64),
    /// A bare `BPF_PROG_ATTACH`, undone only by `BPF_PROG_DETACH`.
    Prog,
}

static NEXT_LINK_ID: AtomicU64 = AtomicU64::new(1);
static OWNERS: IrqSafeSpinLock<Vec<(LinkTarget, Owner)>> = IrqSafeSpinLock::new(Vec::new());

/// Take the claim on `target` for `owner`. `false` if it is already claimed.
fn claim(target: &LinkTarget, owner: Owner) -> bool {
    let mut g = OWNERS.lock();
    if g.iter().any(|(t, _)| t == target) {
        return false;
    }
    g.push((target.clone(), owner));
    true
}

/// Drop `owner`'s claim on `target`. `false` if it did not hold one.
fn unclaim(target: &LinkTarget, owner: Owner) -> bool {
    let mut g = OWNERS.lock();
    let before = g.len();
    g.retain(|(t, o)| !(t == target && *o == owner));
    g.len() != before
}

/// Whether anything reached through `bpf(2)` is attached to `target`.
#[must_use]
pub fn is_claimed(target: &LinkTarget) -> bool {
    OWNERS.lock().iter().any(|(t, _)| t == target)
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
    if !claim(target, Owner::Prog) {
        return Err(LinkError::Busy);
    }
    if let Err(e) = do_attach(&caps, target, prog) {
        unclaim(target, Owner::Prog);
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
    if !unclaim(target, Owner::Prog) {
        return Err(if is_claimed(target) {
            LinkError::Busy
        } else {
            LinkError::NotAttached
        });
    }
    do_detach(&caps, target)
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
    id: u64,
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
        if !claim(&target, Owner::Link(id)) {
            return Err(LinkError::Busy);
        }
        if let Err(e) = do_attach(&caps, &target, Arc::clone(&prog)) {
            unclaim(&target, Owner::Link(id));
            return Err(e);
        }
        Ok(Arc::new(Self {
            id,
            target,
            caps,
            prog: IrqSafeSpinLock::new(Some(prog)),
        }))
    }

    /// This link's id. Unique for the life of the kernel.
    #[must_use]
    pub fn id(&self) -> u64 {
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
        unclaim(&self.target, Owner::Link(self.id));
        let r = do_detach(&self.caps, &self.target);
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
}

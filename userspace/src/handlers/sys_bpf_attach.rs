//! `bpf(2)` — the attach commands.
//!
//! `BPF_PROG_ATTACH` / `BPF_PROG_DETACH` (the legacy pair) and
//! `BPF_LINK_CREATE` / `BPF_LINK_UPDATE` / `BPF_LINK_DETACH` (the modern one,
//! and the one libbpf and systemd reach for). Split out of `sys_bpf.rs` because
//! this is where Linux's `enum bpf_attach_type` gets translated into NARF's
//! attach surfaces, and that translation is most of the code.
//!
//! ## What NARF has to attach to
//!
//! Two hooks, both `Atomic`:
//!
//! * **`BPF_TRACE_FENTRY`** → a `narf_tracing::dispatch` probe site. NARF's
//!   dynamic probes are the fentry-shaped hook — `sys_bpf.rs` already maps
//!   `BPF_PROG_TYPE_TRACING` onto them — and they run with IRQs masked.
//! * **`BPF_XDP`** → the interface's XDP slot, ahead of
//!   `narf_net::bypass::classifier`'s bypass table.
//!
//! Every other `bpf_attach_type` Linux defines is `ENOTSUP`, and a value
//! outside the enum entirely is `EINVAL`. That distinction is the contract: a
//! probing loader has to be able to tell "this kernel does not do that" from
//! "you passed nonsense", and collapsing both into `EINVAL` makes feature
//! detection guesswork.
//!
//! ## Naming the target: two deliberate ABI divergences
//!
//! **Tracing takes a probe id, not a name.** Linux names an fentry target by
//! BTF id (`link_create.target_btf_id`) or, for raw tracepoints, by a
//! `tp_name` string. NARF has neither: `probe!` records a provider/name pair
//! into `.note.narf.probes` as *metadata*, while `dispatch::reserve_probe_id()`
//! hands out ids lazily and independently, and nothing joins the two. Accepting
//! a name would therefore mean inventing a lookup that nothing populates — a
//! name that silently resolved to the wrong site, or to none, is worse than a
//! documented divergence. So `target_fd` carries the `u32` probe id.
//! // LINUX-GAP: no name- or BTF-based tracing target resolution.
//!
//! **XDP takes an ifindex, resolved the way NARF's rtnetlink assigns them.**
//! `net/src/bypass/classifier.rs` keys its XDP slot by interface *name*, and
//! the only ifindex numbering NARF publishes to userspace is the one
//! `netlink_route`'s `RTM_GETLINK` dump uses: 1 is a synthetic loopback, and
//! registered NICs follow at 2, 3, … in registration order.
//! [`iface_for_ifindex`] reproduces that from the same public source
//! `netlink_route` derives it from (`narf_net::iface::snapshot_all`), and
//! `smoke_bpf_syscall_link_close_detaches_xdp` pins the numbering by
//! registering an interface, computing its index from `snapshot_all`, and
//! checking that frames *on that name* are the ones the program sees.
//! // LINUX-GAP: Linux attaches XDP through rtnetlink `IFLA_XDP`, not through
//! `bpf(2)`. NARF's rtnetlink has no `IFLA_XDP`, so accepting `BPF_XDP` here
//! gives a loader one working path instead of none.

#[allow(unused_imports)]
use super::*;

use alloc::string::String;
use alloc::sync::Arc;

use narf_bpf::link::{self, BpfLink, LinkCaps, LinkError, LinkFile, LinkTarget};
use narf_bpf::prog::{BpfAttach, BpfProg, ProgFile};
use narf_capabilities::{Cap, Grant};
use narf_tracing::dispatch::ProbeHandlerInstall;

// Errno values these commands return. Spelled out here rather than widening
// `handlers/mod.rs`'s set, as `sys_bpf.rs` does for its own.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ENODEV: i64 = 19;
const EINVAL: i64 = 22;
const EBUSY: i64 = 16;
const EMFILE: i64 = 24;
const ENOSPC: i64 = 28;
/// Linux's `ENOTSUPP` is an internal 524; the userspace-visible spelling is
/// `EOPNOTSUPP`, which on Linux equals `ENOTSUP` (95).
const ENOTSUP: i64 = 95;

/// `union bpf_attr`, zero-extended. Same rule and same bound as `sys_bpf.rs`:
/// Linux accepts any size and zero-extends
/// (`kernel/bpf/syscall.c::bpf_check_uarg_tail_zero`) so that an older binary
/// works on a newer kernel and vice versa.
const ATTR_BUF: usize = 256;

// `enum bpf_attach_type`, from include/uapi/linux/bpf.h. Only the two NARF has
// a surface for are named; the rest are handled by range.
const BPF_TRACE_FENTRY: u32 = 24;
const BPF_XDP: u32 = 37;
/// `__MAX_BPF_ATTACH_TYPE` as of Linux 6.18. Anything at or above it is not a
/// value Linux defines, so it is `EINVAL` rather than `ENOTSUP`.
const MAX_BPF_ATTACH_TYPE: u32 = 59;

// `struct { … }` (PROG_ATTACH / PROG_DETACH) field offsets.
const PA_TARGET: usize = 0;
const PA_ATTACH_BPF_FD: usize = 4;
const PA_ATTACH_TYPE: usize = 8;
const PA_ATTACH_FLAGS: usize = 12;

// `struct { … } link_create` field offsets.
const LC_PROG_FD: usize = 0;
const LC_TARGET: usize = 4;
const LC_ATTACH_TYPE: usize = 8;
const LC_FLAGS: usize = 12;

// `struct { … } link_update` field offsets.
const LU_LINK_FD: usize = 0;
const LU_NEW_PROG_FD: usize = 4;
const LU_FLAGS: usize = 8;
const LU_OLD_PROG_FD: usize = 12;

// `struct { … } link_detach` field offsets.
const LD_LINK_FD: usize = 0;

/// `BPF_F_REPLACE` — `link_update.old_prog_fd` names the program the caller
/// believes is attached, and the update applies only if it is.
const BPF_F_REPLACE: u32 = 1 << 2;

/// The capabilities every attach on this path presents.
///
/// Minted once and cached. `Cap::bootstrap()` allocates an object-table slot
/// per call, so minting per attach would leak one per `BPF_LINK_CREATE` — and
/// links are created in loops by real loaders.
///
/// As with `sys_bpf.rs`'s `load_cap`, these are **plumbing, not the
/// authorisation check**: a capability the syscall mints for itself proves
/// nothing, and `check_live()` on it only proves nothing has revoked it since.
/// The gate is the per-task credential check in `sys_bpf`, which runs before
/// this module is reached. The liveness checks below still matter — a revoked
/// grant must stop working even though this handler minted it — but they are
/// the *second* line, not the first.
fn link_caps() -> LinkCaps {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<LinkCaps>> = IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let attach: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfAttach,
            Grant,
        >::bootstrap(
        )));
        let probe_install: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            ProbeHandlerInstall,
            Grant,
        >::bootstrap(
        )));
        *g = Some(LinkCaps {
            attach,
            probe_install,
        });
    }
    g.expect("just installed")
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Copy `size` bytes of `union bpf_attr` into a zeroed buffer of our own.
///
/// A local copy of `sys_bpf.rs`'s reader rather than a shared one: the rule it
/// implements (accept any size, zero-extend the tail) is Linux's ABI contract
/// for every `bpf(2)` command, so each command block owning its reader costs a
/// few lines and keeps the attach commands from being coupled to the map
/// commands' buffer.
fn read_attr(attr_uptr: u64, size: usize) -> Result<[u8; ATTR_BUF], i64> {
    if attr_uptr == 0 || size == 0 || size > ATTR_BUF {
        return Err(-EINVAL);
    }
    let mut buf = [0u8; ATTR_BUF];
    // SAFETY: caller-supplied pointer, range-validated inside `copy_from_user`,
    // which also opens and closes the SMAP window and converts a fault into
    // `Err(EFAULT)` rather than a kernel panic.
    unsafe { copy_from_user(&mut buf[..size], attr_uptr) }.map_err(|e| -(e as i64))?;
    Ok(buf)
}

/// Recover a loaded program from a file descriptor.
///
/// The same resolution `BPF_PROG_TEST_RUN` uses: fd table → `Arc<dyn FileOps>`
/// → `as_any().downcast_ref::<ProgFile>()`. `EBADF` for an fd that names
/// nothing, `EINVAL` for one that names something that is not a program —
/// which is the confusion the downcast exists to catch.
fn prog_from_fd(fd: u32) -> Result<Arc<BpfProg>, i64> {
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return Err(-EBADF),
    };
    ops.as_any()
        .and_then(|a| a.downcast_ref::<ProgFile>())
        .map(ProgFile::prog)
        .ok_or(-EINVAL)
}

/// Recover a link from a file descriptor.
fn link_from_fd(fd: u32) -> Result<Arc<BpfLink>, i64> {
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return Err(-EBADF),
    };
    ops.as_any()
        .and_then(|a| a.downcast_ref::<LinkFile>())
        .map(LinkFile::link)
        .ok_or(-EINVAL)
}

/// The interface name NARF's rtnetlink dump reports for `ifindex`.
///
/// Reproduces `net/src/netlink_route.rs::enumerate_in`'s numbering from the
/// same public source it uses (`iface::snapshot_all`, which is already
/// namespace-0-filtered): index 1 is the synthetic loopback the dump always
/// prepends, and registered NICs follow at 2, 3, … in registration order.
/// `smoke_bpf_syscall_link_close_detaches_xdp` pins it: it registers an
/// interface, derives the index from `snapshot_all` the way this function
/// consumes it, and then checks that traffic *on that interface's name* is what
/// the attached program sees. This is exactly the kind of cross-crate
/// convention that stays correct-looking after the other side changes, so the
/// pin is an end-to-end one rather than a restatement of the arithmetic.
///
/// `None` for an ifindex that names no *classifier-reachable* interface —
/// including ifindex 1. The loopback is synthetic: `bypass::classifier::classify`
/// is only reached from the L2 RX path of a registered NIC
/// (`tcp_stack.rs`), so a program attached to `lo` would never run. Refusing
/// is the point — an XDP filter that installs cleanly and never fires is the
/// failure mode this whole surface is built to avoid.
fn iface_for_ifindex(ifindex: u32) -> Option<String> {
    if ifindex < 2 {
        return None;
    }
    narf_net::iface::snapshot_all()
        .get((ifindex - 2) as usize)
        .map(|nic| nic.name.clone())
}

/// The inverse of [`iface_for_ifindex`], for `bpf_link_info.xdp.ifindex`.
///
/// Kept beside its inverse deliberately: the numbering convention is a
/// cross-crate one (`netlink_route`'s dump order), and two independent
/// derivations of it in two files is how one of them silently stops agreeing.
/// `None` for a name no longer registered — an interface can be removed while a
/// link on it is still held, and reporting a stale index would be worse than
/// reporting none.
pub(crate) fn ifindex_for_iface(name: &str) -> Option<u32> {
    narf_net::iface::snapshot_all()
        .iter()
        .position(|nic| nic.name == name)
        .and_then(|pos| u32::try_from(pos + 2).ok())
}

/// Translate `(attach_type, target)` into the hook it names.
///
/// `Err` carries the errno directly, because the two failure modes are
/// deliberately different errnos and folding them would lose the distinction
/// this module's header argues for.
fn resolve_target(attach_type: u32, target: u32) -> Result<LinkTarget, i64> {
    match attach_type {
        BPF_TRACE_FENTRY => {
            // `dispatch::reserve_probe_id` starts at 1 and reserves 0 as
            // "unassigned", so 0 never names a site.
            if target == 0 {
                return Err(-EINVAL);
            }
            Ok(LinkTarget::Probe(target))
        }
        BPF_XDP => iface_for_ifindex(target)
            .map(LinkTarget::Xdp)
            .ok_or(-ENODEV),
        // LINUX-GAP: cgroup hooks, sockmap/sk_msg, LSM, flow dissector,
        // struct_ops-as-a-link, netfilter, tcx, perf events, kprobe/uprobe
        // multi, and the rest. NARF has no surface for any of them —
        // `struct_ops` installs through `narf_bpf::structops::install`, which is
        // a kernel-side trait slot rather than an fd-shaped link. `ENOTSUP`
        // says "this kernel does not do that"; the `EINVAL` below says "that is
        // not a thing".
        t if t < MAX_BPF_ATTACH_TYPE => Err(-ENOTSUP),
        _ => Err(-EINVAL),
    }
}

/// Map a link-layer failure onto the errno Linux uses for it.
fn errno(e: LinkError) -> i64 {
    match e {
        LinkError::AuthorityRevoked => -EPERM,
        // Spec §4.5: attaching a program verified for the other execution
        // context is a *type* error, and Linux answers a program-type/attach-type
        // mismatch with `EINVAL`.
        LinkError::ContextMismatch => -EINVAL,
        LinkError::Busy => -EBUSY,
        LinkError::TableFull => -ENOSPC,
        LinkError::NotAttached => -ENOENT,
        LinkError::ProgMismatch => -EINVAL,
        LinkError::NoAtomicReplace => -ENOTSUP,
        LinkError::Refused => -EINVAL,
    }
}

// ── BPF_PROG_ATTACH / BPF_PROG_DETACH ───────────────────────────────

pub(crate) fn bpf_prog_attach(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < PA_ATTACH_FLAGS + 4 {
        return -EINVAL;
    }
    // LINUX-GAP: `BPF_F_ALLOW_OVERRIDE` / `BPF_F_ALLOW_MULTI` / `BPF_F_REPLACE`
    // all describe how *several* programs share one attach point, which is a
    // cgroup-hierarchy concept. Both NARF hooks hold exactly one program, so
    // accepting these flags would be a lie about the resulting behaviour —
    // `EINVAL`, which is what Linux returns when a hook does not support them.
    if u32_at(&attr, PA_ATTACH_FLAGS) != 0 {
        return -EINVAL;
    }
    let target = match resolve_target(u32_at(&attr, PA_ATTACH_TYPE), u32_at(&attr, PA_TARGET)) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let prog = match prog_from_fd(u32_at(&attr, PA_ATTACH_BPF_FD)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match link::prog_attach(link_caps(), &target, prog) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

pub(crate) fn bpf_prog_detach(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < PA_ATTACH_TYPE + 4 {
        return -EINVAL;
    }
    let target = match resolve_target(u32_at(&attr, PA_ATTACH_TYPE), u32_at(&attr, PA_TARGET)) {
        Ok(t) => t,
        Err(e) => return e,
    };
    // LINUX-GAP: `attach_bpf_fd` is not read. Linux only consults it to pick
    // *which* of several `BPF_F_ALLOW_MULTI` programs to remove, and NARF's
    // hooks hold one. Validating it would imply a per-program detach that does
    // not exist.
    match link::prog_detach(link_caps(), &target) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

// ── BPF_LINK_CREATE / UPDATE / DETACH ───────────────────────────────

pub(crate) fn bpf_link_create(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < LC_FLAGS + 4 {
        return -EINVAL;
    }
    // No `BPF_LINK_CREATE` flag NARF understands. Every one Linux defines
    // selects behaviour of an attach type NARF does not have (perf-event
    // cookies, kprobe-multi return probes, tcx ordering), so silently ignoring
    // one would change what the caller thinks it installed.
    if u32_at(&attr, LC_FLAGS) != 0 {
        return -EINVAL;
    }
    let target = match resolve_target(u32_at(&attr, LC_ATTACH_TYPE), u32_at(&attr, LC_TARGET)) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let prog = match prog_from_fd(u32_at(&attr, LC_PROG_FD)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let bpf_link = match BpfLink::create(link_caps(), target, prog) {
        Ok(l) => l,
        Err(e) => return errno(e),
    };

    let ops: Arc<dyn narf_filesystem::FileOps> = Arc::new(LinkFile::new(bpf_link));
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // As for program and map fds: Linux's `bpf_link_new_fd` passes
            // `O_CLOEXEC`, because a leaked link fd is a leaked capability —
            // and here it is also a leaked *attach*, since the link detaches
            // only when its last fd closes.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        // `with_table` yields `None` when the calling task has no fd table at
        // all, so the closure never ran and `ops` is dropped here — which runs
        // `LinkFile`'s drop and therefore the link's, undoing the attach rather
        // than orphaning it with no handle left to undo it. `EMFILE` is the
        // errno `sys_bpf.rs` already uses for the same shape.
        None => -EMFILE,
    }
}

pub(crate) fn bpf_link_update(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < LU_OLD_PROG_FD + 4 {
        return -EINVAL;
    }
    let flags = u32_at(&attr, LU_FLAGS);
    if flags & !BPF_F_REPLACE != 0 {
        return -EINVAL;
    }
    let bpf_link = match link_from_fd(u32_at(&attr, LU_LINK_FD)) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let new_prog = match prog_from_fd(u32_at(&attr, LU_NEW_PROG_FD)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let old_prog = if flags & BPF_F_REPLACE != 0 {
        match prog_from_fd(u32_at(&attr, LU_OLD_PROG_FD)) {
            Ok(p) => Some(p),
            Err(e) => return e,
        }
    } else {
        None
    };
    match bpf_link.update(new_prog, old_prog.as_ref()) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

pub(crate) fn bpf_link_detach(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < LD_LINK_FD + 4 {
        return -EINVAL;
    }
    let bpf_link = match link_from_fd(u32_at(&attr, LD_LINK_FD)) {
        Ok(l) => l,
        Err(e) => return e,
    };
    // Detaching does not close the fd — the link object stays, answering
    // `BPF_LINK_UPDATE` with `ENOENT` and a second detach with the same. That
    // is Linux's shape too: `bpf_link_detach` leaves the fd valid and the link
    // "dead".
    match bpf_link.detach() {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

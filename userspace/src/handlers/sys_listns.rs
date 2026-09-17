#[allow(unused_imports)]
use super::*;

// `listns(2)` — enumerate the namespaces that exist, which before Linux
// 6.17's namespace tree was not answerable at all: a namespace could only be
// reached through something already using it.

/// `NS_ID_REQ_SIZE_VER0` — `sizeof(struct ns_id_req)`:
/// `{ __u32 size, spare; __u64 ns_id; __u32 ns_type, spare2; __u64 user_ns_id; }`.
const NS_ID_REQ_SIZE_VER0: u64 = 32;

/// `LISTNS_CURRENT_USER` — "the caller's own user namespace".
const LISTNS_CURRENT_USER: u64 = u64::MAX;

/// `mm`-style cap on how many ids one call may be asked for.
const LISTNS_MAXCOUNT: u64 = 1_000_000;

/// `kernel/nstree.c::SYSCALL_DEFINE4(listns)` — x86_64/arm64 470.
///
/// ```text
/// if (flags)                     return -EINVAL;
/// if (nr_ns_ids > maxcount)      return -EOVERFLOW;
/// if (!access_ok(ns_ids, ...))   return -EFAULT;
/// ret = copy_ns_id_req(req, &kreq);
/// if (kreq.user_ns_id) return do_listns_userns(&klns);
/// return do_listns(&klns);
/// ```
///
/// `req.ns_id` is a CURSOR — the last id already seen — so a caller with
/// more namespaces than buffer resumes rather than restarting. That is what
/// makes the call safe against a tree changing underneath it, and it is why
/// the tree is ordered by id rather than hashed.
#[cfg(feature = "container")]
pub(crate) fn sys_listns(ctx: &mut dyn TrapContext) {
    use crate::namespaces::{ns_type, NsTreeEntry};

    let a = *ctx.args();
    let (req, out_ptr, nr, flags) = (a.arg0, a.arg1, a.arg2, a.arg3);

    if flags != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // "If the mount namespace really has more than 1 million..." — the same
    // cap `listmount` carries, and for the same reason.
    if nr > LISTNS_MAXCOUNT {
        ctx.set_return(SyscallReturn::ok((-75i64) as u64)); // -EOVERFLOW
        return;
    }
    // `access_ok` on the whole array BEFORE the request is read, so an
    // unwritable buffer is -EFAULT rather than a partial enumeration.
    if nr != 0 && validate_user_range(out_ptr, (nr as usize).saturating_mul(8)).is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }

    // `copy_ns_id_req`. Same extensible-struct shape as `mnt_id_req`, and
    // the same ORDER — E2BIG is decided before EINVAL, so an oversized
    // `size` reports E2BIG even though it is also not a known version.
    let mut size_buf = [0u8; 4];
    // SAFETY: `req` is the user `struct ns_id_req`; copy_from_user
    // range-validates it and brackets the read.
    if unsafe { copy_from_user(&mut size_buf, req) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    let usize_bytes = u64::from(u32::from_ne_bytes(size_buf));
    if usize_bytes > 4096 {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // -E2BIG
        return;
    }
    if usize_bytes < NS_ID_REQ_SIZE_VER0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let mut buf = [0u8; NS_ID_REQ_SIZE_VER0 as usize];
    let known = core::cmp::min(usize_bytes, NS_ID_REQ_SIZE_VER0) as usize;
    // SAFETY: `known` <= the struct size and lies inside the caller's.
    if unsafe { copy_from_user(&mut buf[..known], req) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    // Every byte past the struct this kernel knows must be zero, or -E2BIG.
    if usize_bytes > NS_ID_REQ_SIZE_VER0 {
        let rest = (usize_bytes - NS_ID_REQ_SIZE_VER0) as usize;
        // SAFETY: the tail lies inside the caller-declared struct.
        let tail = match unsafe { copy_from_user_vec(req + NS_ID_REQ_SIZE_VER0, rest) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
                return;
            }
        };
        if tail.iter().any(|&b| b != 0) {
            ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // -E2BIG
            return;
        }
    }
    let spare = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
    let cursor = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let req_ns_type = u32::from_ne_bytes(buf[16..20].try_into().unwrap());
    let user_ns_id = u64::from_ne_bytes(buf[24..32].try_into().unwrap());

    // `if (kreq->spare != 0) return -EINVAL;` — a reserved field a caller
    // set is a caller expecting something this kernel does not do.
    if spare != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // `if (kreq->ns_type & ~NS_ALL) return -EOPNOTSUPP;` — deliberately NOT
    // -EINVAL and not an empty result: "no such namespace type" and "no
    // namespaces of that type" are different answers, and a caller probing
    // for a flavour this kernel does not know needs to tell them apart.
    if req_ns_type & !ns_type::ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
        return;
    }

    let task = current_task_id();
    let owner_filter = match user_ns_id {
        0 => None,
        // `do_listns_userns`: `if (kls->user_ns_id == LISTNS_CURRENT_USER)
        // ns = to_ns_common(current_user_ns());` — always resolves.
        LISTNS_CURRENT_USER => Some(crate::namespaces::current_user_ns(task).id()),
        other => {
            // `else if (kls->user_ns_id) ns = lookup_ns_id(kls->user_ns_id,
            // CLONE_NEWUSER); if (!ns) return -EINVAL;`
            //
            // An owner id that names NOTHING, or names a namespace of some
            // other flavour, is -EINVAL — not an empty result. The two are
            // very different answers to a caller: "the user namespace you
            // asked about is gone" versus "it still exists and owns
            // nothing", and a supervisor polling a sandbox it created needs
            // to tell them apart. Filtering on the id without resolving it
            // first would have reported the second for both.
            match crate::namespaces::ns_tree_lookup(other) {
                Some(e) if e.ns_type == ns_type::USER => Some(other),
                _ => {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
                    return;
                }
            }
        }
    };

    let candidates = crate::namespaces::ns_tree_entries_from(cursor, req_ns_type, owner_filter);

    // `if (kls->last_ns_id) { first = lookup_ns_id_at(last + 1, ...); if
    // (!first) return -ENOENT; }` — a cursor with nothing after it is
    // -ENOENT, NOT an empty success. That is how a paging caller learns it
    // has reached the end; returning 0 would be indistinguishable from "no
    // namespaces are visible to you right now" and a loop would spin.
    if cursor != 0 && candidates.is_empty() {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }

    // `may_list_ns`: a namespace the caller is IN is always listable;
    // anything else needs `may_see_all_namespaces()`, which is the initial
    // pid namespace plus CAP_SYS_ADMIN in the initial user namespace.
    let privileged = may_see_all_namespaces(task);
    let own = current_namespace_ids(task);
    let visible = |e: &NsTreeEntry| privileged || own.contains(&e.id);

    let mut ids: alloc::vec::Vec<u64> = candidates
        .iter()
        .filter(|e| visible(e))
        .map(|e| e.id)
        .collect();
    ids.truncate(nr as usize);

    let mut bytes = alloc::vec::Vec::with_capacity(ids.len() * 8);
    for id in &ids {
        bytes.extend_from_slice(&id.to_ne_bytes());
    }
    if !bytes.is_empty() {
        // SAFETY: the range was validated above and `bytes` is exactly
        // `ids.len() * 8` long.
        if unsafe { copy_to_user(out_ptr, &bytes) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(ids.len() as u64));
}

/// `kernel/nscommon.c::may_see_all_namespaces`.
///
/// ```text
/// return (task_active_pid_ns(current) == &init_pid_ns) &&
///        ns_capable_noaudit(init_pid_ns.user_ns, CAP_SYS_ADMIN);
/// ```
///
/// Both halves matter: CAP_SYS_ADMIN inside a pid namespace is authority
/// over that namespace, not over the system, so a container root must not be
/// able to enumerate its host's namespaces.
#[cfg(feature = "container")]
fn may_see_all_namespaces(task: u64) -> bool {
    let in_initial_pid_ns = crate::pid_ns::ns_of(task).is_none();
    in_initial_pid_ns && capable(CAP_SYS_ADMIN)
}

/// The ids of every namespace the caller is currently in.
///
/// `is_current_namespace(ns)` in Linux, which is why an unprivileged caller
/// can still see its OWN namespaces — it is already in them, so listing them
/// discloses nothing it could not read from `/proc/self/ns/`.
#[cfg(feature = "container")]
fn current_namespace_ids(task: u64) -> alloc::vec::Vec<u64> {
    let mut v = alloc::vec::Vec::new();
    if let Some(ns) = crate::namespaces::uts_ns_of(task) {
        v.push(ns.id());
    }
    if let Some(ns) = crate::namespaces::net_ns_of(task) {
        v.push(ns.id());
    }
    if let Some(ns) = crate::namespaces::ipc_ns_of(task) {
        v.push(ns.id());
    }
    if let Some(ns) = crate::namespaces::user_ns_of(task) {
        v.push(ns.id());
    }
    if let Some(ns) = crate::pid_ns::ns_of(task) {
        v.push(ns.id());
    }
    if let Some(ns) = current_mount_namespace() {
        v.push(ns.id());
    }
    v
}

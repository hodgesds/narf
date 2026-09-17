//! `fs/nsfs.c` — the ioctls an ns-fd answers, and the file handle it
//! encodes to.
//!
//! An ns-fd is what `/proc/<pid>/ns/<flavour>`, the pidfd namespace ioctls
//! and `setns(2)` all pass around. Until now it was opaque: a caller could
//! hold one and join it, but could not ask what it WAS. These ioctls are
//! how `nsenter`, `lsns` and systemd's `pidref_namespace_open_by_type`
//! interrogate one.
//!
//! This lives at the syscall layer rather than behind `FileOps::ioctl`
//! because four of the commands mint a new fd, and the fd table belongs to
//! this layer — the same reason `TIOCGPTPEER` is handled in `sys_ioctl`.

#[allow(unused_imports)]
use super::*;

use crate::namespaces::{HeldNs, NsFlavour};

/// `NSIO` — the ioctl type byte the whole family shares.
const NSIO: u32 = 0xb7;

/// `MNT_NS_INFO_SIZE_VER0` — `sizeof(struct mnt_ns_info)`:
/// `{ __u32 size; __u32 nr_mounts; __u64 mnt_ns_id; }`. Verified against
/// the header with `offsetof`, not counted by hand.
const MNT_NS_INFO_SIZE_VER0: u32 = 16;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;
const EOPNOTSUPP: i64 = -95;
const ESTALE: i64 = -116;

fn ioc_type(cmd: u32) -> u32 {
    (cmd >> 8) & 0xff
}
fn ioc_nr(cmd: u32) -> u32 {
    cmd & 0xff
}
fn ioc_dir(cmd: u32) -> u32 {
    cmd >> 30
}
/// `_IOC_SIZEBITS` is 14 on both targets.
fn ioc_size(cmd: u32) -> u32 {
    (cmd >> 16) & 0x3fff
}

/// `_IOR(NSIO, nr, T)` for a `T` of `size` bytes.
fn ior(nr: u32, size: u32) -> u32 {
    (2 << 30) | (size << 16) | (NSIO << 8) | nr
}
/// `_IO(NSIO, nr)`.
fn io(nr: u32) -> u32 {
    (NSIO << 8) | nr
}

/// `extensible_ioctl_valid` (`include/linux/fs.h:3634`) — same direction,
/// type and number, and a size of at least the first published struct. A
/// LARGER size is accepted deliberately: that is how the struct grows.
fn extensible_valid(cmd: u32, nr: u32, min_size: u32) -> bool {
    let base = ior(nr, min_size);
    ioc_dir(cmd) == ioc_dir(base) && ioc_type(cmd) == ioc_type(base) && ioc_size(cmd) >= min_size
}

/// `nsfs_ioctl_valid`. The fixed-shape commands must match EXACTLY, so a
/// caller that got the direction or argument size wrong is told the command
/// is unknown rather than being served against a mis-sized buffer.
fn nsfs_ioctl_valid(cmd: u32) -> bool {
    let nr = ioc_nr(cmd);
    match nr {
        1..=4 => cmd == io(nr),
        5 | 13 => cmd == ior(nr, 8),
        6..=9 => cmd == ior(nr, 4),
        10..=12 => extensible_valid(cmd, nr, MNT_NS_INFO_SIZE_VER0),
        _ => false,
    }
}

/// `may_use_nsfs_ioctl` — traversal is gated, everything else is not, and
/// the gate is checked BEFORE the namespace is even fetched from the inode.
/// Refusal is `-EPERM`, not `-ENOTTY`: the command exists, this caller may
/// not use it.
fn may_use(task: u64, cmd: u32) -> bool {
    match ioc_nr(cmd) {
        11 | 12 => may_see_all_namespaces(task),
        _ => true,
    }
}

/// Is `cmd` addressed to nsfs at all? Anything else falls through to the
/// generic ioctl path untouched.
pub(crate) fn is_nsfs_ioctl(cmd: u32) -> bool {
    ioc_type(cmd) == NSIO
}

/// `ns_ioctl` (`fs/nsfs.c`). Returns the syscall result — a new fd, a
/// value, 0, or a negative errno.
pub(crate) fn nsfs_ioctl(task: u64, held: &HeldNs, cmd: u32, arg: usize) -> i64 {
    // `if (!nsfs_ioctl_valid(ioctl)) return -ENOIOCTLCMD;` — which the VFS
    // turns into -ENOTTY before userspace sees it, the same answer the
    // unknown-extensible arm gives directly.
    if !nsfs_ioctl_valid(cmd) {
        return ENOTTY;
    }
    if !may_use(task, cmd) {
        return EPERM;
    }
    match ioc_nr(cmd) {
        1 => get_userns(task, held),
        2 => get_parent(task, held),
        // `case NS_GET_NSTYPE: return ns->ns_type;` — the VALUE is the
        // return, not something written through `arg`.
        3 => i64::from(held.flavour().ns_type()),
        4 => get_owner_uid(task, held, arg),
        // `case NS_GET_MNTNS_ID: if (ns->ns_type != CLONE_NEWNS) return
        // -EINVAL; fallthrough;` — the mount-specific spelling of the same
        // question, which is why it type-checks first and then shares a body.
        5 | 13 => {
            if ioc_nr(cmd) == 5 && held.flavour() != NsFlavour::Mnt {
                return EINVAL;
            }
            write_u64(arg, held.id())
        }
        6..=9 => pidns_translate(task, held, ioc_nr(cmd), arg),
        10 => mnt_get_info(held, cmd, arg),
        11 | 12 => mnt_get_adjoined(task, held, cmd, arg, ioc_nr(cmd) == 12),
        _ => ENOTTY,
    }
}

fn write_u64(arg: usize, v: u64) -> i64 {
    // SAFETY: the UAPI argument is a single `__u64`; copy_to_user
    // range-validates the eight bytes.
    match unsafe { copy_to_user(arg as u64, &v.to_ne_bytes()) } {
        Ok(_) => 0,
        Err(_) => EFAULT,
    }
}

/// Publish `held` as a fresh ns-fd.
///
/// Linux mints these `O_CLOEXEC` (`open_related_ns` allocates with
/// `get_unused_fd_flags(O_CLOEXEC)`), so an ns-fd is never inherited across
/// an exec the caller did not arrange — which matters here because the fd
/// is a capability on a namespace.
fn publish(task: u64, held: HeldNs) -> i64 {
    let ops: Arc<dyn narf_filesystem::FileOps> = crate::namespaces::NsFd::new(held);
    match fd::install(
        task,
        fd::FdEntry {
            ops,
            offset: 0,
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        },
    ) {
        Some(f) => i64::from(f),
        None => EMFILE,
    }
}

/// `ns_get_owner` (`kernel/user_namespace.c:1377`).
///
/// ```text
/// owner = p = ns->ops->owner(ns);
/// for (;;) {
///         if (!p) return ERR_PTR(-EPERM);
///         if (p == my_user_ns) break;
///         p = p->parent;
/// }
/// ```
///
/// The walk IS the permission check: the owning user namespace is handed
/// over only when the caller's own namespace lies on the chain above it —
/// i.e. the owner is the caller's, or a descendant of the caller's. Running
/// off the top without meeting it means the owner sits outside the caller's
/// authority, and -EPERM is the answer. Without the walk, an ns-fd inside a
/// container would hand out a route to the host's user namespace.
fn owner_in_callers_reach(task: u64, held: &HeldNs) -> Result<Arc<crate::namespaces::UserNamespace>, i64> {
    let Some(owner) = crate::namespaces::owner_user_ns_of(held) else {
        return Err(EPERM);
    };
    let mine = crate::namespaces::current_user_ns(task).id();
    let mut cursor = Some(owner.clone());
    while let Some(ns) = cursor {
        if ns.id() == mine {
            return Ok(owner);
        }
        cursor = ns.parent().cloned();
    }
    Err(EPERM)
}

fn get_userns(task: u64, held: &HeldNs) -> i64 {
    match owner_in_callers_reach(task, held) {
        Ok(ns) => publish(task, HeldNs::User(ns)),
        Err(e) => e,
    }
}

/// `case NS_GET_PARENT: if (!ns->ops->get_parent) return -EINVAL;`
///
/// Only two flavours have a parent. `userns_operations.get_parent` is
/// literally `ns_get_owner` — a user namespace's parent IS its owner — and
/// `pidns_operations.get_parent` is `pidns_get_parent`. Every other flavour
/// is -EINVAL: not -EOPNOTSUPP, and not a null answer.
fn get_parent(task: u64, held: &HeldNs) -> i64 {
    match held {
        HeldNs::User(_) => get_userns(task, held),
        HeldNs::Pid(n) => {
            // `pidns_get_parent`: walk up from the parent looking for the
            // caller's ACTIVE pid namespace, -EPERM if it is never met. The
            // same shape as `ns_get_owner`, measured in the pid hierarchy —
            // a task must not be handed a namespace it sits below.
            let active =
                crate::pid_ns::ns_of(task).map_or(crate::namespaces::init_ns_id::PID, |ns| ns.id());
            let Some(parent) = n.parent() else {
                return EPERM;
            };
            let mut cursor = Some(parent.clone());
            while let Some(ns) = cursor {
                if ns.id() == active {
                    return publish(task, HeldNs::Pid(parent));
                }
                cursor = ns.parent();
            }
            EPERM
        }
        _ => EINVAL,
    }
}

/// `case NS_GET_OWNER_UID`. -EINVAL for anything but a user namespace.
///
/// The uid goes through `from_kuid_munged(current_user_ns(), ..)`, so a
/// caller in a namespace that does not map the owner sees the overflow id
/// rather than a host uid it has no business learning.
fn get_owner_uid(task: u64, held: &HeldNs, arg: usize) -> i64 {
    let HeldNs::User(ns) = held else {
        return EINVAL;
    };
    let seen = crate::namespaces::current_user_ns(task)
        .translate_uid_from_host(ns.owner_uid())
        .unwrap_or(crate::namespaces::OVERFLOW_ID);
    // SAFETY: the UAPI argument is a single `uid_t`; copy_to_user
    // range-validates the four bytes.
    match unsafe { copy_to_user(arg as u64, &seen.to_ne_bytes()) } {
        Ok(_) => 0,
        Err(_) => EFAULT,
    }
}

/// `NS_GET_{PID,TGID}_{FROM,IN}_PIDNS`.
///
/// -EINVAL unless the fd names a pid namespace; -ESRCH when no such task.
/// `FROM` translates a pid in the TARGET namespace into the caller's; `IN`
/// translates one of the caller's into the target's. NARF does not model
/// thread groups separately from tasks, so TGID answers the same value as
/// PID — the same identification `clone_pid_levels` already makes.
fn pidns_translate(task: u64, held: &HeldNs, nr: u32, arg: usize) -> i64 {
    let HeldNs::Pid(target) = held else {
        return EINVAL;
    };
    let want = arg as u64;
    let answer = if matches!(nr, 6 | 7) {
        // `find_task_by_pid_ns(arg, pid_ns)` then `task_pid_vnr(tsk)`:
        // target-inner -> outer -> caller-inner.
        target
            .inner_to_outer(want)
            .and_then(|outer| crate::pid_ns::ns_visible_inner(task, outer))
    } else {
        // `find_task_by_vpid(arg)` then `task_pid_nr_ns(tsk, pid_ns)`:
        // caller-inner -> outer -> target-inner.
        crate::pid_ns::resolve_inner_pid(task, want).and_then(|outer| target.outer_to_inner(outer))
    };
    match answer {
        // `if (!ret) ret = -ESRCH;` — pid 0 names no task, so a translation
        // that lands there is reported absent rather than returned.
        None | Some(0) => ESRCH,
        Some(v) => v as i64,
    }
}

/// `copy_ns_info_to_user`. `size` is what THIS kernel filled in, so a
/// caller compiled against a later struct can tell how much of its buffer
/// is meaningful rather than reading zeroes as data.
fn write_mnt_ns_info(arg: usize, ns: &narf_filesystem::MountNamespace) -> i64 {
    let mut buf = [0u8; MNT_NS_INFO_SIZE_VER0 as usize];
    buf[0..4].copy_from_slice(&MNT_NS_INFO_SIZE_VER0.to_ne_bytes());
    buf[4..8].copy_from_slice(&(ns.list().len() as u32).to_ne_bytes());
    buf[8..16].copy_from_slice(&ns.id().to_ne_bytes());
    // SAFETY: copy_to_user range-validates the 16-byte destination. Only
    // the bytes this kernel knows are written; `size` is what tells a larger
    // caller struct that the rest is untouched.
    match unsafe { copy_to_user(arg as u64, &buf) } {
        Ok(_) => 0,
        Err(_) => EFAULT,
    }
}

fn mnt_get_info(held: &HeldNs, cmd: u32, arg: usize) -> i64 {
    let HeldNs::Mnt(ns) = held else {
        return EINVAL;
    };
    // `if (!uinfo) return -EINVAL;` — INFO alone rejects a null buffer,
    // because reporting into it is the command's entire job.
    if arg == 0 {
        return EINVAL;
    }
    if ioc_size(cmd) < MNT_NS_INFO_SIZE_VER0 {
        return EINVAL;
    }
    write_mnt_ns_info(arg, ns)
}

/// `NS_MNT_GET_NEXT` / `NS_MNT_GET_PREV` — step to the adjacent mount
/// namespace and return an fd on it.
///
/// `get_sequential_mnt_ns` (`fs/namespace.c:2103`) LOOPS rather than
/// returning the immediate neighbour:
///
/// ```text
/// for (;;) {
///         ns = ns_tree_adjoined_rcu(mntns, previous);
///         if (IS_ERR(ns)) return ERR_CAST(ns);
///         if (!ns_capable_noaudit(mntns->user_ns, CAP_SYS_ADMIN)) continue;
///         if (!ns_ref_get(mntns)) continue;
///         return mntns;
/// }
/// ```
///
/// A namespace the caller has no authority over is SKIPPED, not refused, so
/// an enumerating caller walks what it may see and ends at -ENOENT instead
/// of stopping dead at the first namespace it may not. That is on top of the
/// `may_see_all_namespaces` gate this command already passed: the gate is
/// about the system, the per-namespace check is about each namespace.
fn mnt_get_adjoined(task: u64, held: &HeldNs, cmd: u32, arg: usize, previous: bool) -> i64 {
    let HeldNs::Mnt(ns) = held else {
        return EINVAL;
    };
    if ioc_size(cmd) < MNT_NS_INFO_SIZE_VER0 {
        return EINVAL;
    }
    let mut from = ns.id();
    loop {
        let Some(entry) =
            crate::namespaces::ns_tree_adjoined(from, crate::namespaces::ns_type::MNT, previous)
        else {
            return ENOENT;
        };
        from = entry.id;
        // The fd must OWN the namespace, so recover the `Arc` from the tree
        // rather than borrowing through the entry's weak handle.
        let Some(live) = crate::namespaces::ns_tree_lookup_object(entry.id) else {
            continue;
        };
        let Some(HeldNs::Mnt(next)) =
            crate::namespaces::held_from_ns_object(&live.object, live.ns_type)
        else {
            continue;
        };
        // `ns_capable_noaudit(mntns->user_ns, CAP_SYS_ADMIN)`.
        let owner = crate::namespaces::owner_user_ns_of(&HeldNs::Mnt(next.clone()));
        let permitted = match owner {
            Some(u) => task_ns_capable(task, &u, CAP_SYS_ADMIN),
            None => task_capable(task, CAP_SYS_ADMIN),
        };
        if !permitted {
            continue;
        }
        // The info write comes before the fd is published: Linux publishes
        // first, but a faulting buffer must not leave a descriptor behind
        // that the caller never learns the number of.
        if arg != 0 {
            let r = write_mnt_ns_info(arg, &next);
            if r != 0 {
                return r;
            }
        }
        return publish(task, HeldNs::Mnt(next));
    }
}

// ── File handles ────────────────────────────────────────────────────

/// `FILEID_NSFS` (`include/linux/exportfs.h:129`) — the handle type an
/// nsfs handle carries, so `open_by_handle_at` can tell it apart from every
/// other kind of handle NARF encodes.
pub(crate) const FILEID_NSFS: i32 = 0xf1;

/// `NSFS_FILE_HANDLE_SIZE_VER0` — `sizeof(struct nsfs_file_handle)`:
/// `{ __u64 ns_id; __u32 ns_type; __u32 ns_inum; }`.
pub(crate) const NSFS_FILE_HANDLE_SIZE: usize = 16;

/// `nsfs_encode_fh` (`fs/nsfs.c`) — all three fields.
///
/// The id alone would locate the namespace; the type and inode are there so
/// a DECODER can cross-check what it found against what the encoder saw.
pub(crate) fn encode_handle(held: &HeldNs) -> [u8; NSFS_FILE_HANDLE_SIZE] {
    let mut b = [0u8; NSFS_FILE_HANDLE_SIZE];
    b[0..8].copy_from_slice(&held.id().to_ne_bytes());
    b[8..12].copy_from_slice(&held.flavour().ns_type().to_ne_bytes());
    b[12..16].copy_from_slice(&crate::namespaces::ns_inum(held.id()).to_ne_bytes());
    b
}

/// `nsfs_fh_to_dentry` (`fs/nsfs.c:518`) — resolve a handle back to a
/// namespace, or to an errno.
///
/// Namespace ids are never reused within a boot but are minted afresh on
/// every boot, so a handle persisted across one names a DIFFERENT namespace.
/// The type and inode cross-checks are what catch that instead of silently
/// handing back the wrong object.
pub(crate) fn decode_handle(task: u64, fid: &[u8]) -> Result<HeldNs, i64> {
    // `if (fh_len < NSFS_FID_SIZE_U32_VER0) return NULL;`
    if fid.len() < NSFS_FILE_HANDLE_SIZE {
        return Err(ESTALE);
    }
    // `if ((fh_len > NSFS_FID_SIZE_U32_LATEST) && memchr_inv(...))` — bytes
    // past the struct this kernel knows must be zero, or the handle was
    // written by something that knows more than we do.
    if fid[NSFS_FILE_HANDLE_SIZE..].iter().any(|&b| b != 0) {
        return Err(ESTALE);
    }
    let ns_id = u64::from_ne_bytes(fid[0..8].try_into().unwrap());
    let ns_type = u32::from_ne_bytes(fid[8..12].try_into().unwrap());
    let ns_inum = u32::from_ne_bytes(fid[12..16].try_into().unwrap());
    // `if (!fid->ns_id) return NULL;` — id 0 names nothing, ever.
    if ns_id == 0 {
        return Err(ESTALE);
    }
    // `if (!fid->ns_inum != !fid->ns_type) return NULL;` — both set, or
    // neither. One without the other is a half-written handle.
    if (ns_inum == 0) != (ns_type == 0) {
        return Err(ESTALE);
    }
    let Some(live) = crate::namespaces::ns_tree_lookup_object(ns_id) else {
        return Err(ESTALE);
    };
    if ns_inum != 0 && ns_inum != crate::namespaces::ns_inum(ns_id) {
        return Err(ESTALE);
    }
    if ns_type != 0 && ns_type != live.ns_type {
        return Err(ESTALE);
    }
    let Some(held) = crate::namespaces::held_from_ns_object(&live.object, live.ns_type) else {
        // `default: return ERR_PTR(-EOPNOTSUPP);` — a flavour this kernel
        // does not model.
        return Err(EOPNOTSUPP);
    };
    // `if (owning_ns && !may_see_all_namespaces()) return ERR_PTR(-EPERM);`
    // — a caller that is NOT in the namespace needs system-wide visibility
    // to open it by handle. Without this a handle would be a way around
    // every check `/proc/<pid>/ns/` enforces.
    if !crate::namespaces::task_is_in_namespace(task, &held) && !may_see_all_namespaces(task) {
        return Err(EPERM);
    }
    Ok(held)
}

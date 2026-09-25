#[allow(unused_imports)]
use super::*;

// `statmount(2)` / `listmount(2)` — the mount-table query pair Linux 6.8
// added so a program can ask about one mount, or enumerate a subtree,
// without parsing `/proc/self/mountinfo`.

/// `MNT_UNIQUE_ID_OFFSET` (`fs/namespace.c`): `1ULL << 31`.
///
/// Linux keeps two id spaces per mount — the small, REUSED id that
/// `/proc/<pid>/mountinfo` prints, and a never-reused 64-bit one that starts
/// above this offset. `copy_mnt_id_req` rejects any `mnt_id <= OFFSET`
/// precisely so a caller cannot pass a mountinfo id by mistake and silently
/// address a different mount than it meant.
///
/// NARF has one id space, the mountinfo one, so the unique id is that id
/// plus the offset. Both are reported: `mnt_id` carries the offset form and
/// `mnt_id_old` the raw one, which is what `/proc` shows.
const MNT_UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// `LSMT_ROOT` — "list from the namespace root" (`listmount` only).
const LSMT_ROOT: u64 = u64::MAX;
const LISTMOUNT_REVERSE: u64 = 1;
const STATMOUNT_BY_FD: u64 = 1;

// `@mask` bits (`include/uapi/linux/mount.h`). Only the ones NARF can fill
// are named; the rest are deliberately absent, because the contract is that
// the RETURNED mask says what was actually written.
const STATMOUNT_SB_BASIC: u64 = 0x0000_0001;
const STATMOUNT_MNT_BASIC: u64 = 0x0000_0002;
const STATMOUNT_MNT_ROOT: u64 = 0x0000_0008;
const STATMOUNT_MNT_POINT: u64 = 0x0000_0010;
const STATMOUNT_FS_TYPE: u64 = 0x0000_0020;
const STATMOUNT_MNT_NS_ID: u64 = 0x0000_0040;
const STATMOUNT_MNT_OPTS: u64 = 0x0000_0080;
const STATMOUNT_SB_SOURCE: u64 = 0x0000_0200;
const STATMOUNT_SUPPORTED_MASK: u64 = 0x0000_1000;

/// The mask NARF can actually answer, reported through
/// `STATMOUNT_SUPPORTED_MASK`.
///
/// This is the honest half of the design and the reason no field has to be
/// faked: Linux's own contract is that `sm.mask` reports what was WRITTEN,
/// not what was asked for, because filesystems vary in what they can supply.
/// A caller that asks for `STATMOUNT_PROPAGATE_FROM` here gets a successful
/// statmount with that bit CLEAR, which is the same answer it would get from
/// a Linux mount that has no propagation — and it can learn the whole set up
/// front by asking for `STATMOUNT_SUPPORTED_MASK`.
const STATMOUNT_SUPPORTED: u64 = STATMOUNT_SB_BASIC
    | STATMOUNT_MNT_BASIC
    | STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_NS_ID
    | STATMOUNT_MNT_OPTS
    | STATMOUNT_SB_SOURCE
    | STATMOUNT_SUPPORTED_MASK;

/// The `[str]` bits: requesting any of these needs room past the fixed
/// struct, which is what makes `bufsize == sizeof(statmount)` -EOVERFLOW.
///
/// This is Linux's `STATMOUNT_STRING_REQ`, including the string fields NARF
/// cannot fill (FS_SUBTYPE, OPT_ARRAY, OPT_SEC_ARRAY, MNT_UIDMAP,
/// MNT_GIDMAP): `prepare_kstatmount` tests the REQUESTED mask, so asking for
/// only FS_SUBTYPE with a 512-byte buffer is -EOVERFLOW even though nothing
/// would be written (probed on 6.18).
const STATMOUNT_STRING_REQ: u64 = STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_OPTS
    | 0x0000_0100 // STATMOUNT_FS_SUBTYPE
    | STATMOUNT_SB_SOURCE
    | 0x0000_0400 // STATMOUNT_OPT_ARRAY
    | 0x0000_0800 // STATMOUNT_OPT_SEC_ARRAY
    | 0x0000_2000 // STATMOUNT_MNT_UIDMAP
    | 0x0000_4000; // STATMOUNT_MNT_GIDMAP

/// `struct statmount` (`include/uapi/linux/mount.h`), field for field.
///
/// Written as a `repr(C)` struct rather than as byte offsets into a buffer
/// BECAUSE the offsets are not countable by hand: `sb_flags` follows a
/// `__u64` after two `__u32`s, and `mnt_id_old`/`mnt_parent_id_old` sit
/// between two `__u64`s, so three of the fields land after padding that
/// counting fields does not show. Every offset I derived by hand was wrong,
/// and a wrong offset here is not a compile error — it is a caller reading a
/// mount id out of the middle of `mnt_attr`. The compiler computes them
/// correctly and for free; the assertion below pins the total against the
/// kernel's 512.
#[repr(C)]
#[derive(Clone, Copy)]
struct Statmount {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    mnt_ns_id: u64,
    fs_subtype: u32,
    sb_source: u32,
    opt_num: u32,
    opt_array: u32,
    opt_sec_num: u32,
    opt_sec_array: u32,
    supported_mask: u64,
    mnt_uidmap_num: u32,
    mnt_uidmap: u32,
    mnt_gidmap_num: u32,
    mnt_gidmap: u32,
    spare2: [u64; 43],
}

/// The ABI is the layout. `sizeof(struct statmount)` is 512 on every arch
/// Linux supports it on, and a caller's buffer is that size — writing fewer
/// bytes would leave the tail of its struct holding whatever was on its
/// stack.
const STATMOUNT_SIZE: usize = 512;
const _: () = assert!(core::mem::size_of::<Statmount>() == STATMOUNT_SIZE);

impl Statmount {
    /// All-zero, which is also what an unrequested field must read as: the
    /// contract is that `mask` says what was written, so every other field
    /// has to be left cleared rather than carrying stale bytes.
    ///
    /// Hand-written rather than derived because `[u64; 43]` is past the
    /// array length `Default` is implemented for.
    const fn zeroed() -> Self {
        // SAFETY: every field is a plain integer or an array of them, for
        // which all-zero is a valid value.
        unsafe { core::mem::zeroed() }
    }
}

/// `struct mnt_id_req` (`include/uapi/linux/mount.h`), read with
/// `copy_struct_from_user`'s extensible-struct rules.
///
/// ```text
/// struct mnt_id_req { __u32 size; __u32 mnt_ns_fd/mnt_fd;
///                     __u64 mnt_id; __u64 param; __u64 mnt_ns_id; };
/// #define MNT_ID_REQ_SIZE_VER0 24
/// #define MNT_ID_REQ_SIZE_VER1 32
/// ```
///
/// `copy_mnt_id_req` reads `size` out of the struct itself before anything
/// else, so a caller declares its own version:
///
/// ```text
/// if (unlikely(usize > PAGE_SIZE))            return -E2BIG;
/// if (unlikely(usize < MNT_ID_REQ_SIZE_VER0)) return -EINVAL;
/// ```
///
/// Note the ORDER — E2BIG is decided before EINVAL, so a wildly oversized
/// `size` reports E2BIG even though it is also not a version this kernel
/// knows. Returns `(mnt_fd, mnt_id, param, mnt_ns_id)`.
fn mnt_id_req_from_user(req: u64, by_fd: bool) -> Result<(u32, u64, u64, u64), i64> {
    const VER0: u64 = 24;
    const VER1: usize = 32;
    const PAGE: u64 = 4096;
    let mut size_buf = [0u8; 4];
    // SAFETY: `copy_from_user` range-validates `req` and brackets the read.
    if unsafe { copy_from_user(&mut size_buf, req) }.is_err() {
        return Err(EFAULT);
    }
    let usize_bytes = u64::from(u32::from_ne_bytes(size_buf));
    if usize_bytes > PAGE {
        return Err(E2BIG);
    }
    if usize_bytes < VER0 {
        return Err(EINVAL);
    }
    let known = core::cmp::min(usize_bytes as usize, VER1);
    let mut buf = [0u8; VER1];
    // SAFETY: `known` <= VER1 and lies inside the caller-declared struct.
    if unsafe { copy_from_user(&mut buf[..known], req) }.is_err() {
        return Err(EFAULT);
    }
    // `copy_struct_from_user`: every byte past the struct this kernel knows
    // must be zero, or -E2BIG. A caller who set a field this kernel would
    // ignore is told so rather than having it dropped.
    if usize_bytes as usize > VER1 {
        let rest = usize_bytes as usize - VER1;
        // SAFETY: the tail lies inside the caller-declared struct.
        let tail = match unsafe { copy_from_user_vec(req + VER1 as u64, rest) } {
            Ok(v) => v,
            Err(_) => return Err(EFAULT),
        };
        if tail.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
    }
    let mnt_fd = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
    let mnt_id = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let param = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
    let mnt_ns_id = u64::from_ne_bytes(buf[24..32].try_into().unwrap());
    if by_fd {
        if mnt_id != 0 || mnt_ns_id != 0 {
            return Err(EINVAL);
        }
    } else {
        if mnt_fd != 0 && mnt_ns_id != 0 {
            return Err(EINVAL);
        }
        // "The first valid unique mount id is MNT_UNIQUE_ID_OFFSET + 1."
        // LSMT_ROOT is u64::MAX and so passes this on its own.
        if mnt_id <= MNT_UNIQUE_ID_OFFSET {
            return Err(EINVAL);
        }
    }
    Ok((mnt_fd, mnt_id, param, mnt_ns_id))
}

/// Every mount visible to the caller, as
/// `(unique_id, unique_parent_id, old_id, path, fstype, mnt_opts, sb_opts)`.
fn visible_mounts() -> alloc::vec::Vec<(u64, u64, u64, alloc::string::String, alloc::string::String, alloc::string::String, alloc::string::String)> {
    let rows = mount_namespace_of(current_task_id())
        .map(|ns| ns.list_mountinfo())
        .unwrap_or_else(|| narf_filesystem::registry().list_mountinfo());
    rows.into_iter()
        .map(|(id, parent, path, fstype, mnt_opts, sb_opts)| {
            // `struct statmount`: "mnt_parent_id — Unique ID of parent (for
            // root == mnt_id)". Linux's root mount has `mnt_parent` pointing
            // at itself, so `do_statmount` reports its own id.
            //
            // NARF's mountinfo rows use 0 for "no ancestor found", and 0 +
            // OFFSET is exactly MNT_UNIQUE_ID_OFFSET — which
            // `copy_mnt_id_req` REJECTS as "at or below the first valid
            // unique id". Passing it straight through would hand a caller a
            // parent id that statmount then refuses to accept.
            let parent = if parent == 0 { id } else { parent };
            (
                id + MNT_UNIQUE_ID_OFFSET,
                parent + MNT_UNIQUE_ID_OFFSET,
                id,
                path,
                fstype,
                mnt_opts,
                sb_opts,
            )
        })
        .collect()
}

/// Is `path` at or below `base`? The reachability test `do_listmount` runs
/// with `is_path_reachable`, expressed over NARF's flat mount paths.
fn under(path: &str, base: &str) -> bool {
    base == "/"
        || path == base
        || (path.starts_with(base) && path.as_bytes().get(base.len()) == Some(&b'/'))
}

/// `listmount(req, mnt_ids, nr_mnt_ids, flags)` — x86_64/arm64 458.
///
/// Enumerates the mounts reachable from `req.mnt_id` (or the namespace root
/// for `LSMT_ROOT`), excluding that mount itself, in unique-id order.
/// `req.param` is a CURSOR — the last id already seen — so a caller with more
/// mounts than buffer resumes rather than restarting, which is what makes the
/// call safe to use on a live mount table.
pub(crate) fn sys_listmount(ctx: &mut dyn TrapContext) {
    const MAXCOUNT: u64 = 1_000_000;
    let a = *ctx.args();
    let (req, out_ptr, nr, flags) = (a.arg0, a.arg1, a.arg2, a.arg3);
    if flags & !LISTMOUNT_REVERSE != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // "If the mount namespace really has more than 1 million mounts the
    // caller must iterate over the mount namespace (and reconsider their
    // system design...)."
    if nr > MAXCOUNT {
        ctx.set_return(errno_ret(EOVERFLOW));
        return;
    }
    // `access_ok` on the whole output array, BEFORE the request is read, so
    // an unwritable buffer is -EFAULT rather than a partial enumeration.
    if nr != 0 && validate_user_range(out_ptr, (nr as usize).saturating_mul(8)).is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let (_, mnt_id, last_mnt_id, _) = match mnt_id_req_from_user(req, false) {
        Ok(v) => v,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // `param` is a unique mount id cursor, held to the same floor as
    // `mnt_id`: "The first valid unique mount id is MNT_UNIQUE_ID_OFFSET +
    // 1." — `if (last_mnt_id != 0 && last_mnt_id <= MNT_UNIQUE_ID_OFFSET)
    // return -EINVAL;`. A mountinfo-style id passed as the cursor would
    // otherwise silently restart the walk from the top.
    if last_mnt_id != 0 && last_mnt_id <= MNT_UNIQUE_ID_OFFSET {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let reverse = flags & LISTMOUNT_REVERSE != 0;
    let mounts = visible_mounts();
    let base = if mnt_id == LSMT_ROOT {
        alloc::string::String::from("/")
    } else {
        match mounts.iter().find(|m| m.0 == mnt_id) {
            Some(m) => m.3.clone(),
            // `lookup_mnt_in_ns` came back NULL.
            None => {
                ctx.set_return(errno_ret(ENOENT));
                return;
            }
        }
    };
    let mut ids: alloc::vec::Vec<u64> = mounts
        .iter()
        .filter(|m| m.0 != mnt_id && under(&m.3, &base))
        .map(|m| m.0)
        .collect();
    ids.sort_unstable();
    if reverse {
        ids.reverse();
    }
    // The cursor: `mnt_find_id_at(ns, last_mnt_id + 1)` forwards,
    // `mnt_find_id_at_reverse(ns, last_mnt_id - 1)` backwards.
    if last_mnt_id != 0 {
        ids.retain(|&id| if reverse { id < last_mnt_id } else { id > last_mnt_id });
    }
    ids.truncate(nr as usize);
    let mut bytes = alloc::vec::Vec::with_capacity(ids.len() * 8);
    for id in &ids {
        bytes.extend_from_slice(&id.to_ne_bytes());
    }
    if !bytes.is_empty() {
        // SAFETY: the range was validated above and `bytes` is exactly
        // `ids.len() * 8` long.
        if unsafe { copy_to_user(out_ptr, &bytes) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(ids.len() as u64));
}

/// `statmount(req, buf, bufsize, flags)` — x86_64/arm64 457.
pub(crate) fn sys_statmount(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (req, buf, bufsize, flags) = (a.arg0, a.arg1, a.arg2, a.arg3);
    if flags & !STATMOUNT_BY_FD != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // STATMOUNT_BY_FD asks for the mount behind an open descriptor. NARF has
    // no fd -> mount mapping, and inventing one would answer about the wrong
    // mount; -EOPNOTSUPP says so. The bit is still VALIDATED above, so a
    // caller can tell "this kernel refuses the flag" from "this kernel does
    // not know the flag".
    if flags & STATMOUNT_BY_FD != 0 {
        ctx.set_return(errno_ret(EOPNOTSUPP));
        return;
    }
    // `copy_mnt_id_req` runs BEFORE `prepare_kstatmount`'s `access_ok(buf)`,
    // so a malformed request outranks an unwritable buffer (probed on 6.18:
    // bad size + bad buffer is EINVAL). `listmount` is the other way round.
    let (_, mnt_id, mask, _) = match mnt_id_req_from_user(req, false) {
        Ok(v) => v,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if validate_user_range(buf, bufsize as usize).is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // `prepare_kstatmount`: asking for a string with no room past the fixed
    // struct is -EOVERFLOW, decided before the mount is even looked up.
    if mask & STATMOUNT_STRING_REQ != 0 && bufsize as usize == STATMOUNT_SIZE {
        ctx.set_return(errno_ret(EOVERFLOW));
        return;
    }
    let mounts = visible_mounts();
    let Some(m) = mounts.iter().find(|m| m.0 == mnt_id) else {
        ctx.set_return(errno_ret(ENOENT));
        return;
    };
    let (unique, parent_unique, old_id, path, fstype, mnt_opts, sb_opts) =
        (m.0, m.1, m.2, &m.3, &m.4, &m.5, &m.6);

    // Build the string area first: each `[str]` field is a u32 OFFSET into
    // it, so the offsets are only knowable once the area exists.
    let mut strs: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let push = |s: &str, strs: &mut alloc::vec::Vec<u8>| -> u32 {
        let at = strs.len() as u32;
        strs.extend_from_slice(s.as_bytes());
        strs.push(0);
        at
    };
    let mut sm = Statmount::zeroed();
    let mut got: u64 = 0;

    if mask & STATMOUNT_SB_BASIC != 0 {
        got |= STATMOUNT_SB_BASIC;
        // sb_dev_major/minor and sb_magic stay 0: NARF's filesystems are not
        // backed by a numbered block device here, and
        // `/proc/self/mountinfo` reports the same 0:0 for them.
        // SB_RDONLY (1) is the only superblock flag NARF models.
        sm.sb_flags = u32::from(mnt_opts.starts_with("ro"));
    }
    if mask & STATMOUNT_MNT_BASIC != 0 {
        got |= STATMOUNT_MNT_BASIC;
        sm.mnt_id = unique;
        sm.mnt_parent_id = parent_unique;
        sm.mnt_id_old = old_id as u32;
        sm.mnt_parent_id_old = (parent_unique - MNT_UNIQUE_ID_OFFSET) as u32;
        // `mnt_attr` is the MOUNT_ATTR_* set — the same information the
        // mountinfo option column carries, in the form `mount_setattr` uses.
        const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
        const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
        const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
        const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
        let mut attr = 0u64;
        if mnt_opts.split(',').any(|o| o == "ro") {
            attr |= MOUNT_ATTR_RDONLY;
        }
        for (needle, bit) in [
            ("nosuid", MOUNT_ATTR_NOSUID),
            ("nodev", MOUNT_ATTR_NODEV),
            ("noexec", MOUNT_ATTR_NOEXEC),
        ] {
            if mnt_opts.split(',').any(|o| o == needle) {
                attr |= bit;
            }
        }
        sm.mnt_attr = attr;
        // mnt_propagation stays 0 (MS_PRIVATE), and peer_group/master with
        // it: NARF has no propagation, which is exactly what a private
        // mount reports in Linux.
    }
    if mask & STATMOUNT_MNT_NS_ID != 0 {
        got |= STATMOUNT_MNT_NS_ID;
    }
    if mask & STATMOUNT_SUPPORTED_MASK != 0 {
        got |= STATMOUNT_SUPPORTED_MASK;
        sm.supported_mask = STATMOUNT_SUPPORTED;
    }
    // `mnt_root` is the mount's root WITHIN its filesystem. NARF mounts
    // whole filesystems, so that is always "/".
    if mask & STATMOUNT_MNT_ROOT != 0 {
        got |= STATMOUNT_MNT_ROOT;
        sm.mnt_root = push("/", &mut strs);
    }
    if mask & STATMOUNT_MNT_POINT != 0 {
        got |= STATMOUNT_MNT_POINT;
        sm.mnt_point = push(path, &mut strs);
    }
    if mask & STATMOUNT_FS_TYPE != 0 {
        got |= STATMOUNT_FS_TYPE;
        sm.fs_type = push(fstype, &mut strs);
    }
    if mask & STATMOUNT_MNT_OPTS != 0 {
        got |= STATMOUNT_MNT_OPTS;
        // The filesystem's own options (`show_options`), which is what
        // Linux's `mnt_opts` carries — not the per-attachment MNT_* set,
        // which `mnt_attr` above reports.
        sm.mnt_opts = push(sb_opts.trim_start_matches(','), &mut strs);
    }
    if mask & STATMOUNT_SB_SOURCE != 0 {
        got |= STATMOUNT_SB_SOURCE;
        sm.sb_source = push(fstype, &mut strs);
    }
    sm.mask = got;

    // `copy_statmount_to_user`: the strings go past the fixed struct, then
    // `size` reports the total and the struct is copied.
    let copysize = core::cmp::min(bufsize as usize, STATMOUNT_SIZE);
    sm.size = (copysize + strs.len()) as u32;
    if !strs.is_empty() {
        // `statmount_string`: `if (kbufsize >= s->bufsize) return
        // -EOVERFLOW;` — the buffer must be strictly larger than the struct
        // plus the NUL-terminated strings (probed on 6.18: "/tmp/qn" fails at
        // 512 + 8 and succeeds at 512 + 9).
        if (bufsize as usize) <= STATMOUNT_SIZE + strs.len() {
            ctx.set_return(errno_ret(EOVERFLOW));
            return;
        }
        // SAFETY: the whole `bufsize` range was validated above, and this
        // write stays inside it (checked immediately above).
        if unsafe { copy_to_user(buf + STATMOUNT_SIZE as u64, &strs) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    // SAFETY: `Statmount` is repr(C) and plain-old-data, so its bytes are
    // the wire image; `copysize` <= bufsize and the range was validated.
    let raw = unsafe {
        core::slice::from_raw_parts(&sm as *const Statmount as *const u8, STATMOUNT_SIZE)
    };
    // SAFETY: as above — `copysize` <= STATMOUNT_SIZE and <= bufsize.
    if unsafe { copy_to_user(buf, &raw[..copysize]) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

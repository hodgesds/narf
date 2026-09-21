//! `openat2(2)` — `fs/open.c`.

#[allow(unused_imports)]
use super::*;

// Pre-negated spellings: this file returns its errnos verbatim. The
// explicit import shadows the positive `E*` from `use super::*`.
use crate::errno::wire::{E2BIG, EFAULT, EINVAL};
// Guard the shadowing above — see the note in sys_quotactl.rs.
const _: () = assert!(EINVAL == -22 && E2BIG == -7 && EFAULT == -14);

/// `OPEN_HOW_SIZE_VER0` — `sizeof(struct open_how)`:
/// `{ __u64 flags; __u64 mode; __u64 resolve; }`. Still the latest version.
const OPEN_HOW_SIZE_VER0: usize = 24;

/// `VALID_OPEN_FLAGS` (`include/linux/fcntl.h:9`).
///
/// `openat2` differs from `openat` precisely here: "older syscalls
/// implicitly clear all of the invalid flags or argument values before
/// calling `build_open_flags()`, but `openat2(2)` checks all of its
/// arguments." Silently dropping a flag is what the new syscall exists to
/// stop.
const VALID_OPEN_FLAGS: u64 = 0o3
    | 0o100      // O_CREAT
    | 0o200      // O_EXCL
    | 0o400      // O_NOCTTY
    | 0o1000     // O_TRUNC
    | 0o2000     // O_APPEND
    | 0o4000     // O_NONBLOCK / O_NDELAY
    | 0o4010000  // __O_SYNC | O_DSYNC
    | 0o20000    // FASYNC
    | 0o40000    // O_DIRECT
    | 0o100000   // O_LARGEFILE
    | 0o200000   // O_DIRECTORY
    | 0o400000   // O_NOFOLLOW
    | 0o1000000  // O_NOATIME
    | 0o2000000  // O_CLOEXEC
    | 0o10000000 // O_PATH
    | 0o20200000; // __O_TMPFILE (0o20000000 | O_DIRECTORY)

const O_CREAT: u64 = 0o100;
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;
const O_CLOEXEC: u64 = 0o2000000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE_BIT: u64 = 0o20000000;
/// `O_PATH_FLAGS` (`fs/open.c:1163`).
const O_PATH_FLAGS: u64 = O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC;
/// `S_IALLUGO` — the permission bits a mode may carry.
const S_IALLUGO: u64 = 0o7777;

/// `RESOLVE_*` (`include/uapi/linux/openat2.h`).
///
/// NARF honours NONE of them yet, and that is why `VALID_RESOLVE_FLAGS`
/// below is empty rather than Linux's full set — see [`sys_openat2`].
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;

/// `VALID_RESOLVE_FLAGS` (`include/linux/fcntl.h:16`) — all six, all
/// honoured. See [`sys_openat2`] for how each is enforced.
const VALID_RESOLVE_FLAGS: u64 = RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
    | RESOLVE_IN_ROOT
    | RESOLVE_CACHED;

/// `SYSCALL_DEFINE4(openat2, int dfd, const char __user *filename,
/// struct open_how __user *how, size_t usize)`.
pub(crate) fn sys_openat2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how_ptr = args.arg2;
    let size = args.arg3 as usize;

    // `if (usize < OPEN_HOW_SIZE_VER0) return -EINVAL;`
    // `if (usize > PAGE_SIZE) return -E2BIG;`
    //
    // EINVAL first here, where `clone3` checks E2BIG first. Unobservable —
    // no size is both below 24 and above 4096 — but worth not "tidying"
    // into a single range check, because the two syscalls really do differ
    // and a reader comparing them should see that.
    if how_ptr == 0 {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        return;
    }
    if size < OPEN_HOW_SIZE_VER0 {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        return;
    }
    if size > 4096 {
        ctx.set_return(SyscallReturn::ok(E2BIG as u64));
        return;
    }

    // SAFETY: copy_from_user_vec range-validates the 24-byte read.
    let how = match unsafe { copy_from_user_vec(how_ptr, OPEN_HOW_SIZE_VER0) } {
        Ok(b) => b,
        Err(_) => {
            // Was the shared `-1` sentinel, which reaches libc as EPERM —
            // an answer about permission for a caller whose only mistake
            // was an unreadable pointer.
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
    };
    // `copy_struct_from_user`: bytes past the struct this kernel knows must
    // be zero. Reading only the first 24 and ignoring the rest silently
    // drops whatever a newer caller set.
    if size > OPEN_HOW_SIZE_VER0 {
        let rest = size - OPEN_HOW_SIZE_VER0;
        // SAFETY: the tail lies inside the caller-declared struct;
        // copy_from_user_vec range-validates it.
        let tail = match unsafe { copy_from_user_vec(how_ptr + OPEN_HOW_SIZE_VER0 as u64, rest) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(EFAULT as u64));
                return;
            }
        };
        if tail.iter().any(|&b| b != 0) {
            ctx.set_return(SyscallReturn::ok(E2BIG as u64));
            return;
        }
    }

    let flags = u64::from_ne_bytes(how[0..8].try_into().unwrap());
    let mode = u64::from_ne_bytes(how[8..16].try_into().unwrap());
    let resolve = u64::from_ne_bytes(how[16..24].try_into().unwrap());

    if let Err(e) = validate_open_how(flags, mode, resolve) {
        ctx.set_return(SyscallReturn::ok(e as u64));
        return;
    }

    // `RESOLVE_CACHED`: "only complete if it can be done without any
    // blocking operations". NARF's walk drives `poll_blocking` at every
    // component — it has no cached-only mode to fall back to — so it can
    // never satisfy the request and says so. Linux answers -EAGAIN in the
    // same situation (`fs/namei.c:2680`, LOOKUP_CACHED without LOOKUP_RCU),
    // and the flag exists precisely so a caller can retry without it.
    if resolve & RESOLVE_CACHED != 0 {
        use crate::errno::wire::EAGAIN;
        ctx.set_return(SyscallReturn::ok(EAGAIN as u64));
        return;
    }

    let task = current_task_id();
    let scope = match build_scope(task, args.arg0, resolve) {
        Ok(s) => s,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };

    // `RESOLVE_BENEATH` is checked at the STEP, not at the destination.
    // `follow_dotdot` (`fs/namei.c:2186`) refuses the moment a `..` would
    // leave the scope, so `../dir/file` is rejected even though it lands
    // back inside — and an absolute pathname is rejected outright, because
    // it is not below the dirfd by construction. A destination-only check
    // permits both, which is weaker than what the caller asked for.
    //
    // `RESOLVE_IN_ROOT` deliberately does NOT get this: there, `..` at the
    // root clamps to the root rather than escaping, which is the whole
    // difference between the two flags.
    if scope.beneath {
        let raw = match copy_user_cstr_checked(args.arg1, 4096) {
            Ok(p) => p,
            Err(errno) => {
                ctx.set_return(SyscallReturn::ok((-errno) as u64));
                return;
            }
        };
        if lexically_escapes(&raw) {
            use crate::errno::wire::EXDEV;
            ctx.set_return(SyscallReturn::ok(EXDEV as u64));
            return;
        }
    }

    // `openat2` is an extensible version of `openat`, not of NARF's legacy
    // length-delimited `open` ABI. In particular, retain `dirfd`: systemd's
    // mount-unit path walker opens each child relative to an O_PATH parent
    // and later uses that parent in mkdirat(). Routing through `sys_open`
    // discarded the directory fd, so the returned descriptor had no usable
    // backing path for the subsequent mkdirat.
    let proxy_args = SyscallArgs {
        arg0: args.arg0,
        arg1: args.arg1,
        arg2: flags,
        arg3: mode,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = ReshapeArgs {
        inner: ctx,
        args: proxy_args,
    };
    // The scope lives for exactly this resolution — Linux's
    // `current->nameidata`, which is why the resolver can consult it
    // without every frame in between threading it down.
    with_resolve_scope(task, scope, || sys_openat(&mut proxy));
}

/// Translate the `resolve` mask into a [`ResolveScope`].
///
/// `RESOLVE_BENEATH` and `RESOLVE_IN_ROOT` both need the dirfd's path: the
/// first as the boundary the walk may not cross, the second as the "/" it
/// is measured from. `AT_FDCWD` means the working directory, which is what
/// `nd->root` is set to for a relative walk.
fn build_scope(task: u64, dirfd: u64, resolve: u64) -> Result<ResolveScope, i64> {
    let mut scope = ResolveScope {
        no_symlinks: resolve & RESOLVE_NO_SYMLINKS != 0,
        no_magiclinks: resolve & RESOLVE_NO_MAGICLINKS != 0,
        no_xdev: resolve & RESOLVE_NO_XDEV != 0,
        beneath: resolve & RESOLVE_BENEATH != 0,
        in_root: resolve & RESOLVE_IN_ROOT != 0,
        root: alloc::string::String::new(),
    };
    if !(scope.beneath || scope.in_root) {
        return Ok(scope);
    }
    const AT_FDCWD: i32 = -100;
    let root = if dirfd as u32 as i32 == AT_FDCWD {
        cwd_of(task)
    } else {
        // A scoped resolution against a descriptor that is not a directory
        // — or not open at all — has no root to be measured from.
        fd_path_for_task(task, dirfd as u32).ok_or(-9i64)?
    };
    scope.root = apply_chroot(&root);
    Ok(scope)
}

/// `build_open_flags` (`fs/open.c`), the argument-checking half.
fn validate_open_how(flags: u64, mode: u64, resolve: u64) -> Result<(), i64> {
    // `flags &= ~strip;` — O_CLOEXEC is not part of the decision.
    let flags_checked = flags & !O_CLOEXEC;
    if flags_checked & !VALID_OPEN_FLAGS != 0 {
        return Err(EINVAL);
    }
    // See `VALID_RESOLVE_FLAGS`: this rejects every `RESOLVE_*` bit, on
    // purpose, rather than accepting a restriction it would not apply.
    if resolve & !VALID_RESOLVE_FLAGS != 0 {
        let _ = (
            RESOLVE_NO_XDEV,
            RESOLVE_NO_MAGICLINKS,
            RESOLVE_NO_SYMLINKS,
            RESOLVE_BENEATH,
            RESOLVE_IN_ROOT,
            RESOLVE_CACHED,
        );
        return Err(EINVAL);
    }

    // `if (WILL_CREATE(flags)) { if (how->mode & ~S_IALLUGO) return -EINVAL; }
    //  else { if (how->mode != 0) return -EINVAL; }`
    //
    // The else-branch is the one `openat` cannot have: a legacy caller's
    // stray `mode` is ignored, and openat2 refuses it so the caller learns
    // the mode was never going to be used.
    let will_create = flags & (O_CREAT | O_TMPFILE_BIT) != 0;
    if will_create {
        if mode & !S_IALLUGO != 0 {
            return Err(EINVAL);
        }
    } else if mode != 0 {
        return Err(EINVAL);
    }

    // "Block bugs where O_DIRECTORY | O_CREAT created regular files."
    if flags & (O_DIRECTORY | O_CREAT) == (O_DIRECTORY | O_CREAT) {
        return Err(EINVAL);
    }
    // `__O_TMPFILE` must be raised with O_DIRECTORY — the way a caller gets
    // an explicit error on a kernel too old to know O_TMPFILE — and must ask
    // for write access, since an unwritable temporary file is useless.
    if flags & O_TMPFILE_BIT != 0 {
        if flags & O_DIRECTORY == 0 {
            return Err(EINVAL);
        }
        // `!(acc_mode & MAY_WRITE)`: O_RDONLY is 0, so the access mode must
        // be O_WRONLY or O_RDWR.
        if flags & 0o3 == 0 {
            return Err(EINVAL);
        }
    }
    // "O_PATH only permits certain other flags to be set."
    if flags & O_PATH != 0 && flags_checked & !O_PATH_FLAGS != 0 {
        return Err(EINVAL);
    }
    Ok(())
}

/// Would this pathname leave the scope by its own text?
///
/// True for an absolute path — not below the dirfd by construction — and
/// for any `..` that pops above the starting directory. Tracking the depth
/// rather than normalising first is the point: normalising collapses
/// `../dir/file` back to `dir/file` and loses the step that escaped.
fn lexically_escapes(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let mut depth: i64 = 0;
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

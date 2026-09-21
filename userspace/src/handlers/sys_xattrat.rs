#[allow(unused_imports)]
use super::*;

/// `AT_FDCWD` as it arrives in an argument register.
pub(crate) const AT_FDCWD_ARG: i64 = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW_ARG: u32 = 0x100;
pub(crate) const AT_EMPTY_PATH_ARG: u32 = 0x1000;

// ── The four shared bodies ───────────────────────────────────────────
//
// `fs/xattr.c` has exactly these: `path_setxattrat`, `path_getxattrat`,
// `path_listxattrat`, `path_removexattrat`. Every one of the sixteen xattr
// entry points is a preset over one of them — plain (`AT_FDCWD, path, 0`),
// `l` (`AT_FDCWD, path, AT_SYMLINK_NOFOLLOW`), `f` (`fd, NULL,
// AT_EMPTY_PATH`) and `*at` (the caller's own three). Sharing the body is
// the point: the namespace rules, the permission gate and the size limits
// then cannot drift between forms, which is how `setxattr` came to behave
// like `lsetxattr` here in the first place.

pub(crate) fn xattr_set_at(dfd: i64, path_ptr: u64, at_flags: u32, ctx: &mut dyn TrapContext) {
    match xattr_at_path(dfd, path_ptr, at_flags) {
        Ok((path, _follow)) => xattr_set_core(path, ctx),
        Err(errno) => ctx.set_return(SyscallReturn::ok(errno as u64)),
    }
}

pub(crate) fn xattr_get_at(dfd: i64, path_ptr: u64, at_flags: u32, ctx: &mut dyn TrapContext) {
    match xattr_at_path(dfd, path_ptr, at_flags) {
        Ok((path, _follow)) => xattr_get_core(path, ctx),
        Err(errno) => ctx.set_return(SyscallReturn::ok(errno as u64)),
    }
}

pub(crate) fn xattr_list_at(dfd: i64, path_ptr: u64, at_flags: u32, ctx: &mut dyn TrapContext) {
    match xattr_at_path(dfd, path_ptr, at_flags) {
        Ok((path, _follow)) => xattr_list_core(path, ctx),
        Err(errno) => ctx.set_return(SyscallReturn::ok(errno as u64)),
    }
}

pub(crate) fn xattr_remove_at(dfd: i64, path_ptr: u64, at_flags: u32, ctx: &mut dyn TrapContext) {
    match xattr_at_path(dfd, path_ptr, at_flags) {
        Ok((path, _follow)) => xattr_remove_core(path, ctx),
        Err(errno) => ctx.set_return(SyscallReturn::ok(errno as u64)),
    }
}

/// Re-present a syscall's arguments to a core that expects a different
/// register layout.
///
/// The four cores read `name`/`value`/`size`/`flags` from arg1..arg4,
/// because that is where the twelve legacy calls put them. The `*at` forms
/// put them elsewhere, and pack two of them inside a `struct xattr_args`.
/// This forwards the return and control-flow hooks unchanged and rewrites
/// only `args`, which is the same shape `chown_legacy` uses to reach the
/// `fchownat` body.
struct Reshaped<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
}

impl TrapContext for Reshaped<'_> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.inner.set_return(r);
    }
    fn user_rsp(&self) -> u64 {
        self.inner.user_rsp()
    }
    fn rip(&self) -> u64 {
        self.inner.rip()
    }
    fn set_rip(&mut self, rip: u64) {
        self.inner.set_rip(rip);
    }
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        self.inner.redirect_to_kernel(rip, rsp)
    }
}

// ── The four new syscalls ────────────────────────────────────────────

/// `setxattrat(dfd, pathname, at_flags, name, uargs, usize)` — x86_64 463.
///
/// ```text
/// SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
///                 unsigned int, at_flags, const char __user *, name,
///                 const struct xattr_args __user *, uargs, size_t, usize)
/// ```
///
/// The value and flags arrive inside `struct xattr_args` rather than as
/// registers, so the struct is read first (with its extensible-struct size
/// rules) and then presented to the shared body in the layout it expects.
pub(crate) fn sys_setxattrat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (value, size, flags) = match xattr_args_from_user(a.arg4, a.arg5) {
        Ok(v) => v,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let mut shim = Reshaped {
        args: SyscallArgs {
            arg1: a.arg3,            // name
            arg2: value,             // value
            arg3: u64::from(size),   // size
            arg4: u64::from(flags),  // flags
            ..a
        },
        inner: ctx,
    };
    xattr_set_at(a.arg0 as i64, a.arg1, a.arg2 as u32, &mut shim);
}

/// `getxattrat(dfd, pathname, at_flags, name, uargs, usize)` — x86_64 464.
///
/// Same struct as `setxattrat`, with one extra rule: `getxattrat` has no
/// flags to carry, so `if (args.flags != 0) return -EINVAL;` — a caller
/// reusing a `struct xattr_args` from a set call is told, rather than
/// having the field ignored.
pub(crate) fn sys_getxattrat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (value, size, flags) = match xattr_args_from_user(a.arg4, a.arg5) {
        Ok(v) => v,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    if flags != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let mut shim = Reshaped {
        args: SyscallArgs {
            arg1: a.arg3,          // name
            arg2: value,           // value
            arg3: u64::from(size), // size
            ..a
        },
        inner: ctx,
    };
    xattr_get_at(a.arg0 as i64, a.arg1, a.arg2 as u32, &mut shim);
}

/// `listxattrat(dfd, pathname, at_flags, list, size)` — x86_64 465.
///
/// `SYSCALL_DEFINE5` — no `struct xattr_args` here, because a list has no
/// value and no flags to carry.
pub(crate) fn sys_listxattrat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mut shim = Reshaped {
        args: SyscallArgs {
            arg1: a.arg3, // list
            arg2: a.arg4, // size
            ..a
        },
        inner: ctx,
    };
    xattr_list_at(a.arg0 as i64, a.arg1, a.arg2 as u32, &mut shim);
}

/// `removexattrat(dfd, pathname, at_flags, name)` — x86_64 466.
pub(crate) fn sys_removexattrat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mut shim = Reshaped {
        args: SyscallArgs {
            arg1: a.arg3, // name
            ..a
        },
        inner: ctx,
    };
    xattr_remove_at(a.arg0 as i64, a.arg1, a.arg2 as u32, &mut shim);
}

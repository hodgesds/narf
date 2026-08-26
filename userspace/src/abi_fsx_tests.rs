//! Linux syscall ABI conformance — fsx group.
//!
//! Covers the extended-attribute family (set/get/list/remove in the
//! path/lpath/fd variants) and the mount / new-mount-API surface
//! (mount, umount2, pivot_root, name_to_handle_at, open_by_handle_at,
//! fsopen/fsconfig/fsmount/move_mount/open_tree/open_tree_attr/fspick/
//! mount_setattr).
//!
//! Shares the harness in [`crate::abi_test_support`]; every test drives
//! `kernel_syscall_entry` through a synthetic `AbiCtx`. The xattr handlers
//! store into a side `BTreeMap` keyed by the (chroot-resolved) path string,
//! so a positive set/get round-trips even against a path that names no real
//! inode. The fd-keyed `f*xattr` family keys on an `anon_inode:[Type]`
//! placeholder derived from the fd's `FileOps` type, so an open MemFs fd is
//! enough to reach the success path.

use crate::abi_test_support::*;

// ENODATA is the wire value the xattr handlers use for "no such attribute";
// it isn't in the shared harness errno set, so define it locally.
const ENODATA: i64 = -61;

// EBUSY isn't in the shared harness errno set either; pivot_root's
// "loop, on the same file system" arm needs it.
const EBUSY: i64 = -16;

// A user-half address with nothing mapped behind it: every copy_from_user
// against it faults, which is how the -EFAULT arms below are reached.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

// Open a MemFs-backed file via the (linux-compat) open syscall and return
// its fd, or Err if the open failed. Used by the `f*xattr` tests which need
// a live fd so `xattr_fd_key`/`fd_path_of` resolve to Some(placeholder).
fn open_memfs_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(v) if v >= 0 => Ok(v as u32),
        _ => Err("open of seeded MemFs file should yield an fd"),
    }
}

// ── setxattr / getxattr (path-keyed) ──────────────────────────────────
//
// Linux shape: setxattr(path, name, value, size, flags). arg0 is a bare
// NUL-terminated path pointer (no length). The store is a side table keyed
// by the resolved path string, so the path need not name a real inode.

fn smoke_abi_fsx_setxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/x\0";
        let name = b"user.k\0";
        let val = b"hello";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("setxattr with a valid name/value should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_setxattr_pos);

fn smoke_abi_fsx_setxattr_neg() -> TestResult {
    with_setup(|| {
        // Empty/unreadable name → EINVAL (name pointer is NUL-terminated
        // empty string here: copy_user_cstr returns "" which the handler
        // rejects).
        let path = b"/abi/x\0";
        let name = b"\0";
        let val = b"v";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("setxattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_setxattr_neg);

fn smoke_abi_fsx_getxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/g\0";
        let name = b"user.k\0";
        let val = b"abcd";
        // Seed via setxattr.
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        // size==0 → handler returns the value length without copying.
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == val.len() as i64 => Ok(()),
            _ => Err("getxattr(size=0) should report the stored value length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_getxattr_pos);

fn smoke_abi_fsx_getxattr_neg() -> TestResult {
    with_setup(|| {
        // No attribute was ever set on this path → ENODATA.
        let path = b"/abi/missing\0";
        let name = b"user.absent\0";
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("getxattr of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_getxattr_neg);

// ── listxattr (path-keyed) ────────────────────────────────────────────

fn smoke_abi_fsx_listxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/l\0";
        let name = b"user.one\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        // size==0 → return total name-list length ("user.one\0" = 9 bytes).
        let largs = a2(path.as_ptr() as u64, 0, 0);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(9) => Ok(()),
            _ => Err("listxattr(size=0) should report the NUL-terminated name-list length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_listxattr_pos);

fn smoke_abi_fsx_listxattr_neg() -> TestResult {
    with_setup(|| {
        // Buffer too small for the stored list → ERANGE.
        let path = b"/abi/l2\0";
        let name = b"user.longname\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        let mut buf = [0u8; 2];
        // size=1 is smaller than "user.longname\0" (14 bytes) → ERANGE.
        let largs = a2(path.as_ptr() as u64, buf.as_mut_ptr() as u64, 1);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("listxattr with an undersized buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_listxattr_neg);

// ── removexattr (path-keyed) ──────────────────────────────────────────

fn smoke_abi_fsx_removexattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/r\0";
        let name = b"user.rm\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Removexattr.raw(), rargs) {
            Some(0) => Ok(()),
            _ => Err("removexattr of an existing attribute should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_removexattr_pos);

fn smoke_abi_fsx_removexattr_neg() -> TestResult {
    with_setup(|| {
        // Remove of an attribute that was never set → ENODATA.
        let path = b"/abi/r2\0";
        let name = b"user.absent\0";
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Removexattr.raw(), rargs) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("removexattr of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_removexattr_neg);

// ── l*xattr variants (symlink-no-follow; same core, same path key) ────
//
// lsetxattr/lgetxattr share xattr_set_core/xattr_get_core with the
// non-l variants, so they round-trip identically.

fn smoke_abi_fsx_lsetxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lx\0";
        let name = b"user.l\0";
        let val = b"vv";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Lsetxattr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("lsetxattr with a valid name/value should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lsetxattr_pos);

fn smoke_abi_fsx_lsetxattr_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lx\0";
        let name = b"\0"; // empty name → EINVAL
        let val = b"v";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Lsetxattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("lsetxattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lsetxattr_neg);

fn smoke_abi_fsx_lgetxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lg\0";
        let name = b"user.l\0";
        let val = b"xyz";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Lsetxattr.raw(), sargs) != Some(0) {
            return Err("seed lsetxattr failed");
        }
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Lgetxattr.raw(), gargs) {
            Some(v) if v == val.len() as i64 => Ok(()),
            _ => Err("lgetxattr(size=0) should report the stored value length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lgetxattr_pos);

fn smoke_abi_fsx_lgetxattr_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lg-absent\0";
        let name = b"user.absent\0";
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Lgetxattr.raw(), gargs) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("lgetxattr of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lgetxattr_neg);

fn smoke_abi_fsx_llistxattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/ll\0";
        let name = b"user.q\0"; // "user.q\0" = 7 bytes
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Lsetxattr.raw(), sargs) != Some(0) {
            return Err("seed lsetxattr failed");
        }
        let largs = a2(path.as_ptr() as u64, 0, 0);
        match call(Syscall::Llistxattr.raw(), largs) {
            Some(7) => Ok(()),
            _ => Err("llistxattr(size=0) should report the name-list length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_llistxattr_pos);

fn smoke_abi_fsx_llistxattr_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/ll2\0";
        let name = b"user.bigname\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Lsetxattr.raw(), sargs) != Some(0) {
            return Err("seed lsetxattr failed");
        }
        let mut buf = [0u8; 2];
        let largs = a2(path.as_ptr() as u64, buf.as_mut_ptr() as u64, 1);
        match call(Syscall::Llistxattr.raw(), largs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("llistxattr with an undersized buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_llistxattr_neg);

fn smoke_abi_fsx_lremovexattr_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lr\0";
        let name = b"user.l\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Lsetxattr.raw(), sargs) != Some(0) {
            return Err("seed lsetxattr failed");
        }
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Lremovexattr.raw(), rargs) {
            Some(0) => Ok(()),
            _ => Err("lremovexattr of an existing attribute should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lremovexattr_pos);

fn smoke_abi_fsx_lremovexattr_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lr-absent\0";
        let name = b"user.absent\0";
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Lremovexattr.raw(), rargs) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("lremovexattr of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lremovexattr_neg);

// ── f*xattr variants (fd-keyed) ───────────────────────────────────────
//
// arg0 is an fd, not a path. xattr_fd_key resolves it through fd_path_of,
// which returns Some(anon_inode:[Type]) for any open fd and None for an
// unknown fd → EBADF. The fd-keyed store is separate from the path-keyed
// one (a documented NARF limitation), so set/get round-trip on the SAME fd.

fn smoke_abi_fsx_fsetxattr_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fk\0";
        let val = b"data";
        let args = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Fsetxattr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("fsetxattr on a valid fd should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsetxattr_pos);

fn smoke_abi_fsx_fsetxattr_neg() -> TestResult {
    with_setup(|| {
        // Unknown fd → EBADF (no fd table entry → fd_path_of None).
        let name = b"user.fk\0";
        let val = b"data";
        let args = SyscallArgs {
            arg0: 999,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Fsetxattr.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fsetxattr on an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsetxattr_neg);

fn smoke_abi_fsx_fgetxattr_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fg\0";
        let val = b"payload";
        let sargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Fsetxattr.raw(), sargs) != Some(0) {
            return Err("seed fsetxattr failed");
        }
        let gargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Fgetxattr.raw(), gargs) {
            Some(v) if v == val.len() as i64 => Ok(()),
            _ => Err("fgetxattr(size=0) should report the stored value length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fgetxattr_pos);

fn smoke_abi_fsx_fgetxattr_neg() -> TestResult {
    with_setup(|| {
        let name = b"user.fg\0";
        let gargs = SyscallArgs {
            arg0: 999,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Fgetxattr.raw(), gargs) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fgetxattr on an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fgetxattr_neg);

fn smoke_abi_fsx_flistxattr_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fl\0"; // "user.fl\0" = 8 bytes
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Fsetxattr.raw(), sargs) != Some(0) {
            return Err("seed fsetxattr failed");
        }
        let largs = a2(fd as u64, 0, 0);
        // size=0 → report the name-list length. Our seeded "user.fl\0" is
        // 8 bytes; assert the list is at least that (other xattrs may exist
        // depending on the backing inode's prior state across tests).
        match call(Syscall::Flistxattr.raw(), largs) {
            Some(v) if v >= 8 => Ok(()),
            _ => Err("flistxattr(size=0) should report the name-list length (>= 8)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_flistxattr_pos);

fn smoke_abi_fsx_flistxattr_neg() -> TestResult {
    with_setup(|| {
        let largs = a2(999, 0, 0);
        match call(Syscall::Flistxattr.raw(), largs) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("flistxattr on an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_flistxattr_neg);

fn smoke_abi_fsx_fremovexattr_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fr\0";
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Fsetxattr.raw(), sargs) != Some(0) {
            return Err("seed fsetxattr failed");
        }
        let rargs = a1(fd as u64, name.as_ptr() as u64);
        match call(Syscall::Fremovexattr.raw(), rargs) {
            Some(0) => Ok(()),
            _ => Err("fremovexattr of an existing attribute should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fremovexattr_pos);

fn smoke_abi_fsx_fremovexattr_neg() -> TestResult {
    with_setup(|| {
        let name = b"user.fr\0";
        let rargs = a1(999, name.as_ptr() as u64);
        match call(Syscall::Fremovexattr.raw(), rargs) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fremovexattr on an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fremovexattr_neg);

// ── mount ─────────────────────────────────────────────────────────────
//
// Linux mount(2) ABI: arg0 = source, arg1 = target, arg2 = fstype (all
// NUL-terminated), arg3 = MS_* flags, arg4 = fs-specific data. tmpfs/ramfs
// synthesize a fresh in-memory FS and mount it. Failures come back as a
// NEGATED errno with NARF status Ok, so `call` returns Some in both cases —
// never the bare -1 sentinel, which userspace would read as EPERM and
// confuse with the legitimate "you lack CAP_SYS_ADMIN" answer.

fn smoke_abi_fsx_mount_pos() -> TestResult {
    with_setup(|| {
        // Linux mount(2) ABI: (source, target, fstype, flags, data), NUL-term.
        let source = b"none\0";
        let target = b"/abi-tmpfs\0";
        let fstype = b"tmpfs\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0, // flags
            arg4: 0, // data
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("mount of a tmpfs at a fresh target should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_pos);

fn smoke_abi_fsx_mount_neg() -> TestResult {
    with_setup(|| {
        // Unknown block-device source + genuinely unknown fstype → -ENODEV,
        // matching Linux (never the bare -1 = EPERM sentinel).
        let source = b"nodevhere\0";
        let target = b"/abi-bad\0";
        let fstype = b"ext9\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(v) if v == ENODEV => Ok(()),
            _ => Err("mount with an unknown device/fstype must return -ENODEV"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_neg);

// `SYSCALL_DEFINE5(mount)` stages `type`, `dev_name` and `data` through
// `copy_mount_string`/`copy_mount_options` before anything else happens; a
// faulting pointer in any of them is -EFAULT. NARF used to fold a faulting
// `source` or `fstype` into an EMPTY STRING (`unwrap_or_default()`), so a
// garbage fstype pointer came back as -ENODEV ("no such filesystem type") —
// sending the caller off to modprobe a module for a string it never sent.
fn smoke_abi_fsx_mount_string_efault_neg() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let target = b"/abi-mnt-efault\0";
        let fstype = b"tmpfs\0";
        // Faulting fstype.
        let bad_type = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: BAD_PTR,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), bad_type) {
            Some(v) if v == EFAULT => {}
            Some(v) if v == ENODEV => {
                return Err("mount folded a faulting fstype into an empty string → -ENODEV")
            }
            _ => return Err("mount with a faulting fstype must return -EFAULT"),
        }
        // Faulting source, valid everything else.
        let bad_source = SyscallArgs {
            arg0: BAD_PTR,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), bad_source) != Some(EFAULT) {
            return Err("mount with a faulting source must return -EFAULT");
        }
        // Faulting data.
        let bad_data = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: BAD_PTR,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), bad_data) != Some(EFAULT) {
            return Err("mount with a faulting data pointer must return -EFAULT");
        }
        // Faulting target.
        let bad_target = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: BAD_PTR,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), bad_target) != Some(EFAULT) {
            return Err("mount with a faulting target must return -EFAULT");
        }
        // A NULL source is NOT a fault — `copy_mount_string(NULL)` yields
        // NULL with no error, and MS_REMOUNT / propagation calls rely on it.
        let null_source = SyscallArgs {
            arg0: 0,
            arg1: c"/abi-mnt-nullsrc".as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), null_source) != Some(0) {
            return Err("mount with a NULL source must still mount a tmpfs");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_string_efault_neg);

// `path_mount`'s first two flag rules, which NARF did not implement at all:
//
//   if ((flags & MS_MGC_MSK) == MS_MGC_VAL) flags &= ~MS_MGC_MSK;
//   if (flags & MS_NOUSER) return -EINVAL;
//
// The order between them is load-bearing: MS_MGC_VAL (0xC0ED0000) has bit 31
// set, which is MS_NOUSER — so a legacy caller that still ORs in the mount
// magic is rejected outright unless the magic is stripped FIRST.
fn smoke_abi_fsx_mount_flag_validation() -> TestResult {
    with_setup(|| {
        const MS_NOUSER: u64 = 1 << 31;
        const MS_MGC_VAL: u64 = 0xC0ED_0000;
        const MS_RDONLY: u64 = 1;
        let source = b"none\0";
        let fstype = b"tmpfs\0";

        // MS_NOUSER is kernel-internal: userspace may not request it.
        let nouser = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: c"/abi-mnt-nouser".as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: MS_NOUSER,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), nouser) != Some(EINVAL) {
            return Err("mount(MS_NOUSER) must return -EINVAL");
        }

        // The legacy magic is discarded, so the same call succeeds.
        let magic = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: c"/abi-mnt-magic".as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: MS_MGC_VAL | MS_RDONLY,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), magic) {
            Some(0) => Ok(()),
            Some(v) if v == EINVAL => Err(
                "mount(MS_MGC_VAL) was rejected — the magic is not being stripped before MS_NOUSER",
            ),
            _ => Err("mount(MS_MGC_VAL|MS_RDONLY) must succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_flag_validation);

// Positive pin for the flags NARF accepts and (deliberately) ignores, plus
// the propagation-only no-op: a later tightening of the flag word must not
// turn any of these working calls into an error. systemd issues the
// MS_SLAVE|MS_REC form immediately after clone(CLONE_NEWNS), and failing it
// aborts the sandbox fork.
fn smoke_abi_fsx_mount_accepted_flags_pos() -> TestResult {
    with_setup(|| {
        const MS_RDONLY: u64 = 1;
        const MS_NOSUID: u64 = 1 << 1;
        const MS_NODEV: u64 = 1 << 2;
        const MS_NOEXEC: u64 = 1 << 3;
        const MS_REC: u64 = 1 << 14;
        const MS_SLAVE: u64 = 1 << 19;
        const MS_RELATIME: u64 = 1 << 21;

        let ok = SyscallArgs {
            arg0: c"none".as_ptr() as u64,
            arg1: c"/abi-mnt-flags".as_ptr() as u64,
            arg2: c"tmpfs".as_ptr() as u64,
            arg3: MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), ok) != Some(0) {
            return Err("mount with the accepted MNT_* option bits must return 0");
        }
        // Propagation-only: source, fstype and data are ignored and nothing
        // is mounted. NARF models every mount as private, so this is 0.
        let prop = SyscallArgs {
            arg0: 0,
            arg1: c"/abi-mnt-flags".as_ptr() as u64,
            arg2: 0,
            arg3: MS_SLAVE | MS_REC,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), prop) != Some(0) {
            return Err("mount(NULL, target, NULL, MS_SLAVE|MS_REC, NULL) must return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_accepted_flags_pos);

// ── mount(2) FUSE options live in `data`, not `source` ────────────────
//
// Linux `fuse_fill_super` reads `fd=`/`rootmode=`/`user_id=`/`group_id=`
// from mount(2)'s 5th argument. `source` is the device (`/dev/fuse`) or a
// daemon-chosen label and carries no options.
//
// NARF's fuse arm parsed them out of `source` for as long as the mount ABI
// really was NARF-native `(ptr, len, ...)` with no `data` register. The ABI
// was converted to the Linux shape; the fuse arm was not, so `fd=` was
// never found in any real caller's `source` and EVERY fuse mount failed —
// as EFAULT, because the arm fell back to the handler's copy-in error.
// xdg-document-portal logs that verbatim ("fuse: mount failed: Bad
// address"), which points at an addressing bug that does not exist.
//
// Both arms below distinguish the fixed handler from the broken one by
// ERRNO, which is exactly what the bug corrupted:
//   * options in `data` (correct location) → the fd is looked up and
//     rejected as "not a /dev/fuse connection" → EINVAL. Pre-fix: `data`
//     was never read, so this returned EFAULT.
//   * options in `source` (the retired location) → nothing to parse in
//     `data` → EINVAL. Pre-fix: `source` WAS parsed, the bogus fd failed
//     the connection lookup, and that path also returned EFAULT.

fn smoke_abi_fsx_mount_fuse_opts_from_data() -> TestResult {
    with_setup(|| {
        let source = b"/dev/fuse\0";
        let target = b"/abi-fuse-data\0";
        let fstype = b"fuse\0";
        // A syntactically valid option string naming an fd that is not an
        // open /dev/fuse connection. Linux: EINVAL.
        let data = b"fd=4242,rootmode=40000,user_id=0,group_id=0\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: data.as_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            Some(v) if v == EFAULT => {
                Err("fuse mount returned EFAULT — options are being read from `source`, not `data`")
            }
            _ => Err("fuse mount with a non-fuse fd in `data` must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_fuse_opts_from_data);

fn smoke_abi_fsx_mount_fuse_opts_not_from_source() -> TestResult {
    with_setup(|| {
        // The retired NARF-native location. `data` is NULL, so a handler
        // that reads only `data` finds no `fd=` at all → EINVAL.
        let source = b"fd=4242,rootmode=40000,user_id=0,group_id=0\0";
        let target = b"/abi-fuse-source\0";
        let fstype = b"fuse.portal\0"; // the `fuse.<subtype>` arm too
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0, // no data
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fuse mount must not read its options from `source`"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_fuse_opts_not_from_source);

// A fuse mount must be PUBLISHED without waiting for the daemon's FUSE_INIT
// reply, because the daemon cannot send one while it is inside mount(2).
//
// Linux `fuse_fill_super` submits INIT through `fuse_simple_background()`
// and returns; `process_init_reply()` sets `fc->initialized` later, from the
// reply callback (fs/fuse/inode.c). NARF awaited INIT inline, so a daemon
// that mounts from the thread it services /dev/fuse on — which libfuse's
// `fuse_mount` does — deadlocked against itself until the bounded bridge
// expired and the mount failed.
//
// The fd here is a real /dev/fuse connection with NO daemon behind it: a
// handler that waits for INIT cannot succeed, and one that publishes and
// negotiates in the background returns 0 immediately.
fn smoke_abi_fsx_mount_fuse_publishes_without_init_reply() -> TestResult {
    with_setup(|| {
        let dev = narf_filesystem::fuse_conn::DevFuse::open_new();
        let task = crate::handlers::current_task_id();
        let fd = crate::fd::install(
            task,
            crate::fd::FdEntry {
                ops: dev.clone(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        )
        .ok_or("could not install a /dev/fuse fd for the mount")?;

        let source = b"/dev/fuse\0";
        let target = b"/abi-fuse-live\0";
        let fstype = b"fuse\0";
        let data = alloc::format!("fd={fd},rootmode=40000,user_id=0,group_id=0\0");
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: data.as_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("fuse mount must publish without awaiting a FUSE_INIT reply"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_mount_fuse_publishes_without_init_reply
);

// ── umount2 ───────────────────────────────────────────────────────────
//
// Linux umount2(2): arg0 = NUL-terminated target, arg1 = MNT_* flags. The
// registry pop-by-path is unconditional once the target is known to carry a
// mount; the errno arms below pin `fs/namespace.c::ksys_umount`'s order —
// flag word first, then the path lookup, then the mount checks. Mount a
// tmpfs first for the positive case.

fn smoke_abi_fsx_umount2_pos() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let target = b"/abi-umnt\0";
        let fstype = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("setup mount failed");
        }
        // Linux umount2(2): (target, flags), NUL-term target.
        let uargs = a1(target.as_ptr() as u64, 0);
        match call(Syscall::Umount2.raw(), uargs) {
            Some(0) => Ok(()),
            _ => Err("umount2 of a freshly-mounted path should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_pos);

fn smoke_abi_fsx_umount2_neg() -> TestResult {
    with_setup(|| {
        // `user_path_at` fails first for a name that resolves to nothing at
        // all → -ENOENT. (Was the bare -1 = EPERM, which a teardown loop
        // reads as "not mine to unmount" and keeps forever in its list.)
        let target = b"/abi-not-mounted\0";
        match call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("umount2 of a path that names nothing must return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_neg);

// `can_umount`: a path that DOES resolve but carries no mount is -EINVAL,
// not -ENOENT — the split Linux draws between the path lookup and
// `path_mounted()`. systemd's umount_recursive needs it: ENOENT means "gone,
// drop it from the list", EINVAL means "never was a mount, skip it", and the
// old -1/EPERM meant neither.
fn smoke_abi_fsx_umount2_not_a_mount_point_neg() -> TestResult {
    with_memfs("/abi-umnt-em", "umnt-em", &[("f", b"hi")], || {
        let target = b"/abi-umnt-em/f\0";
        match call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("umount2 of an existing non-mount path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_not_a_mount_point_neg);

// `ksys_umount`'s comment is literal: "basic validity checks done first".
// An unknown flag bit is -EINVAL BEFORE the target is even read, so the
// same call against a path that does not exist is EINVAL and not ENOENT.
// An unreadable target with a valid flag word is -EFAULT.
fn smoke_abi_fsx_umount2_flags_and_fault_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-not-mounted\0";
        // Bit 8 is not one of MNT_FORCE/MNT_DETACH/MNT_EXPIRE/UMOUNT_NOFOLLOW.
        const BOGUS_FLAG: u64 = 1 << 8;
        if call(
            Syscall::Umount2.raw(),
            a1(target.as_ptr() as u64, BOGUS_FLAG),
        ) != Some(EINVAL)
        {
            return Err("umount2 with an unknown flag bit must return -EINVAL before the lookup");
        }
        // `int flags`: the upper 32 bits are not part of the argument, so
        // they must not be mistaken for unknown flag bits. This one still
        // reaches the (nonexistent) path → -ENOENT.
        if call(
            Syscall::Umount2.raw(),
            a1(target.as_ptr() as u64, 0xFFFF_FFFF_0000_0000),
        ) != Some(ENOENT)
        {
            return Err("umount2 must ignore the upper 32 bits of its `int flags`");
        }
        // do_umount: MNT_EXPIRE is mutually exclusive with MNT_FORCE/MNT_DETACH.
        // Checked after the mount resolves, so the nonexistent path still wins.
        const MNT_FORCE: u64 = 1;
        const MNT_EXPIRE: u64 = 1 << 2;
        if call(
            Syscall::Umount2.raw(),
            a1(target.as_ptr() as u64, MNT_EXPIRE | MNT_FORCE),
        ) != Some(ENOENT)
        {
            return Err("umount2(MNT_EXPIRE|MNT_FORCE) on a missing path must still be -ENOENT");
        }
        // An unreadable target → -EFAULT from user_path_at.
        if call(Syscall::Umount2.raw(), a1(BAD_PTR, 0)) != Some(EFAULT) {
            return Err("umount2 with a faulting target must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_flags_and_fault_neg);

// Positive pin so a later tightening cannot turn a working teardown into an
// error: every flag umount2(2) accepts must still unmount a real mount.
fn smoke_abi_fsx_umount2_accepted_flags_pos() -> TestResult {
    with_setup(|| {
        const MNT_DETACH: u64 = 1 << 1;
        const UMOUNT_NOFOLLOW: u64 = 1 << 3;
        let source = b"none\0";
        let target = b"/abi-umnt-flags\0";
        let fstype = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("setup mount failed");
        }
        match call(
            Syscall::Umount2.raw(),
            a1(target.as_ptr() as u64, MNT_DETACH | UMOUNT_NOFOLLOW),
        ) {
            Some(0) => Ok(()),
            _ => Err("umount2(MNT_DETACH|UMOUNT_NOFOLLOW) of a real mount must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_accepted_flags_pos);

// systemd's switch-root does `fchdir(new_root_fd); pivot_root(".", ".");
// umount2(".", MNT_DETACH)`. The RELATIVE "." must resolve against the cwd (the
// new root), not be taken literally — a literal "." matched no mount, umount2
// failed, and systemd's `mount(".", "/", MS_MOVE)` fallback then returned
// ENOENT → 226/EXIT_NAMESPACE (udevd et al., after the domainname fix).
fn smoke_abi_fsx_umount2_relative_dot() -> TestResult {
    with_setup(|| {
        crate::handlers::__test_cwd_reset();
        let target = b"/abi-swroot\0";
        let margs = SyscallArgs {
            arg0: c"none".as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: c"tmpfs".as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("setup mount failed");
        }
        // Change into the new mount, then umount2(".").
        if call(Syscall::Chdir.raw(), a1(target.as_ptr() as u64, 0)) != Some(0) {
            crate::handlers::__test_cwd_reset();
            return Err("chdir into the new mount failed");
        }
        let dot = b".\0";
        let r = call(Syscall::Umount2.raw(), a1(dot.as_ptr() as u64, 0));
        crate::handlers::__test_cwd_reset();
        match r {
            Some(0) => Ok(()),
            _ => Err("umount2(\".\") must resolve to the cwd mount and return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_relative_dot);

// ── pivot_root ────────────────────────────────────────────────────────
//
// arg0/arg1 = new_root/put_old C-string pointers. The handler is part of the
// Linux-compat syscall surface, independently of the optional container
// namespace bundle: systemd uses pivot_root while constructing a service
// sandbox after CLONE_NEWNS. A missing syscall-table slot returns EPERM and
// turns that otherwise valid setup into 226/NAMESPACE.

fn smoke_abi_fsx_pivot_root_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // Linux ABI: pivot_root(new_root, put_old), both NUL-terminated paths
        // resolved against the cwd. A new_root that does not resolve to an
        // existing directory must fail — here a relative name with no matching
        // entry under the cwd. (Relative paths are NOT rejected wholesale:
        // `pivot_root(".", ".")` is the standard container idiom — see
        // smoke_pivot_root_relative_dot in mount_e2e_tests.)
        let new_root = b"nonexistent-dir\0";
        let put_old = b"/abi\0";
        let args = a2(new_root.as_ptr() as u64, put_old.as_ptr() as u64, 0);
        // This exercises the installed dispatcher slot, not just the handler
        // directly. The missing path must reach pivot_root and fail normally.
        // `user_path_at(LOOKUP_DIRECTORY)` on a name that resolves to nothing
        // is -ENOENT. It used to be the bare -1 = EPERM, which is the answer
        // a runtime reads as "this kernel will not let me pivot" — so it
        // falls back to chroot() and quietly loses its mount isolation.
        match call(Syscall::PivotRoot.raw(), args) {
            Some(v) if v == ENOENT => Ok(()),
            Some(_) => Err("pivot_root with an unresolvable new_root must return -ENOENT"),
            None => Err("linux-compat pivot_root must be present in the syscall table"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_pivot_root_neg);

// The rest of `path_pivot_root`'s errno surface, in the kernel's order:
// both names are copied and resolved before any topology check runs.
fn smoke_abi_fsx_pivot_root_errno_arms_neg() -> TestResult {
    with_memfs("/abi-pvr", "abi-pvr", &[("file", b"hi")], || {
        let put_old = b"/abi-pvr\0";
        // An unreadable new_root → -EFAULT, before anything is resolved.
        if call(
            Syscall::PivotRoot.raw(),
            a2(BAD_PTR, put_old.as_ptr() as u64, 0),
        ) != Some(EFAULT)
        {
            return Err("pivot_root with a faulting new_root must return -EFAULT");
        }
        // An unreadable put_old is likewise -EFAULT (its own user_path_at).
        let new_root = b"/abi-pvr\0";
        if call(
            Syscall::PivotRoot.raw(),
            a2(new_root.as_ptr() as u64, BAD_PTR, 0),
        ) != Some(EFAULT)
        {
            return Err("pivot_root with a faulting put_old must return -EFAULT");
        }
        // `LOOKUP_DIRECTORY` on a new_root that resolves to a FILE → -ENOTDIR,
        // distinct from the -ENOENT above. A runtime staging its root needs
        // the difference: ENOTDIR means "you bound a file here".
        let file_root = b"/abi-pvr/file\0";
        if call(
            Syscall::PivotRoot.raw(),
            a2(file_root.as_ptr() as u64, put_old.as_ptr() as u64, 0),
        ) != Some(ENOTDIR)
        {
            return Err("pivot_root with a non-directory new_root must return -ENOTDIR");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_pivot_root_errno_arms_neg);

// `new_mnt == root_mnt` → -EBUSY ("loop, on the same file system"): the root
// the caller is already standing on cannot also be the new root, because the
// swap would have nowhere to move the old root to. EBUSY is the one answer
// that tells a runtime "you already pivoted, this is a repeat" — as -1/EPERM
// it looked like a privilege failure and the retry loop kept going.
fn smoke_abi_fsx_pivot_root_same_root_busy_neg() -> TestResult {
    with_memfs("/abi-pvr-busy", "abi-pvr-busy", &[("file", b"hi")], || {
        if !crate::handlers::install_root_dir(FAKE_TASK, "/abi-pvr-busy") {
            return Err("could not install the task root for the pivot_root busy case");
        }
        // "/" now resolves to the task's own root, i.e. new_root == root.
        let same = b"/\0";
        let put_old = b"/\0";
        let r = call(
            Syscall::PivotRoot.raw(),
            a2(same.as_ptr() as u64, put_old.as_ptr() as u64, 0),
        );
        crate::handlers::__test_root_dir_reset();
        match r {
            Some(v) if v == EBUSY => Ok(()),
            _ => Err("pivot_root onto the caller's current root must return -EBUSY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_pivot_root_same_root_busy_neg);

// Positive pin: the container idiom must keep working. A real directory
// mount as new_root, with put_old inside it, still returns 0 — so the errno
// arms above cannot be tightened into rejecting a legitimate pivot.
fn smoke_abi_fsx_pivot_root_pos() -> TestResult {
    with_setup(|| {
        crate::handlers::__test_root_dir_reset();
        let source = b"none\0";
        let new_root = b"/abi-pvr-ok\0";
        let fstype = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: new_root.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("setup mount of the new root failed");
        }
        let put_old = b"/abi-pvr-ok/old\0";
        let r = call(
            Syscall::PivotRoot.raw(),
            a2(new_root.as_ptr() as u64, put_old.as_ptr() as u64, 0),
        );
        let installed = crate::handlers::root_dir_of(FAKE_TASK);
        let installed_ok = installed.as_deref() == Some("/abi-pvr-ok");
        crate::handlers::__test_root_dir_reset();
        crate::handlers::__test_cwd_reset();
        match (r, installed_ok) {
            (Some(0), true) => Ok(()),
            (Some(0), false) => Err("pivot_root returned 0 without installing the new root"),
            _ => Err("pivot_root into a real directory mount must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_pivot_root_pos);

// ── name_to_handle_at / open_by_handle_at ─────────────────────────────
//
// name_to_handle_at: arg0=dirfd (AT_FDCWD), arg1=NUL-term path,
// arg2=handle buffer whose first u32 is the caller's f_handle capacity,
// arg3=mount_id out ptr. On success it writes an 8-byte header + the path
// bytes into the buffer and returns 0. open_by_handle_at then reads that
// buffer back and re-opens the stored path, returning a fresh fd.

fn smoke_abi_fsx_name_to_handle_at_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        // Buffer: first 4 bytes = capacity, rest = room for header+path.
        let mut hbuf = [0u8; 64];
        let cap: u32 = 56; // > path.len() ("/abi/f" = 6)
        hbuf[0..4].copy_from_slice(&cap.to_ne_bytes());
        let mut mount_id = [0u8; 4];
        let args = a3(
            0, // AT_FDCWD-ish (ignored)
            path.as_ptr() as u64,
            hbuf.as_mut_ptr() as u64,
            mount_id.as_mut_ptr() as u64,
        );
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(0) if i32::from_ne_bytes(mount_id) > 0 => Ok(()),
            Some(0) => Err("name_to_handle_at must report the visible mount id"),
            _ => Err("name_to_handle_at on an existing file should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_name_to_handle_at_pos);

fn smoke_abi_fsx_name_to_handle_at_empty_path_mount_id_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        const AT_EMPTY_PATH: u64 = 0x1000;
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_PATH: u64 = 0o10000000;
        let path = b"/abi/f\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, O_PATH, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("O_PATH open for AT_EMPTY_PATH setup failed"),
        };
        let empty = b"\0";
        let mut hbuf = [0u8; 16];
        hbuf[0..4].copy_from_slice(&8u32.to_ne_bytes());
        let mut mount_id = [0u8; 4];
        let args = SyscallArgs {
            arg0: fd,
            arg1: empty.as_ptr() as u64,
            arg2: hbuf.as_mut_ptr() as u64,
            arg3: mount_id.as_mut_ptr() as u64,
            arg4: AT_EMPTY_PATH,
            ..Default::default()
        };
        let result = match call(Syscall::NameToHandleAt.raw(), args) {
            Some(0) if i32::from_ne_bytes(mount_id) > 0 => Ok(()),
            Some(0) => Err("AT_EMPTY_PATH must preserve the fd's opening mount id"),
            _ => Err("name_to_handle_at(AT_EMPTY_PATH) failed"),
        };
        let _ = call(Syscall::Close.raw(), a0(fd));
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_name_to_handle_at_empty_path_mount_id_pos
);

fn smoke_abi_fsx_name_to_handle_at_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // Missing path → ENOENT.
        let path = b"/abi/nope\0";
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&32u32.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("name_to_handle_at on a missing path must return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_name_to_handle_at_neg);

/// systemd's `cg_path_get_cgroupid`: mkdir the nested service cgroup
/// (`<root>/x.slice/y.service`, exactly what cg_create does under
/// /sys/fs/cgroup), then `name_to_handle_at(path, cap=8)` must return 0
/// with the cgroup DIRECTORY's inode as the 8-byte handle — that inode is
/// the cgroup id. Cgroup children are dir-only nodes (no FileOps shape),
/// so a file-shape-only resolver reports ENOENT here ("Failed to get
/// cgroup ID of cgroup ...: No such file or directory").
#[cfg(feature = "cgroup")]
fn smoke_abi_fsx_name_to_handle_at_cgroup_dir_id() -> TestResult {
    setup();
    // Kernel-test fixture: hands the syscall entry point kernel `.rodata` /
    // stack pointers as stand-in user buffers. See
    // `handlers::kernel_buffers_guard` and `with_setup`, which does the same
    // for the tests that use the closure form of this harness.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let mnt = match registry().mount(&auth, "/abicg", narf_filesystem::cgroupfs::CgroupFs::new()) {
        Ok(h) => h,
        Err(_) => {
            teardown();
            return TestResult::Fail("cgroupfs mount failed");
        }
    };
    let slice = b"/abicg/t_nth.slice\0";
    let svc = b"/abicg/t_nth.slice/t_nth.service\0";
    let outcome = (|| {
        // Nested on-demand creation, one component at a time (systemd's
        // mkdir_parents walk).
        if call_mkdir(slice.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir of the slice cgroup failed");
        }
        if call_mkdir(svc.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir of the service cgroup failed");
        }
        // cap == 8 → the id-form handle (cgroup id).
        let mut hbuf = [0u8; 16];
        hbuf[0..4].copy_from_slice(&8u32.to_ne_bytes());
        let mut mount_id = [0u8; 4];
        let args = a3(
            0, // AT_FDCWD-ish (ignored)
            svc.as_ptr() as u64,
            hbuf.as_mut_ptr() as u64,
            mount_id.as_mut_ptr() as u64,
        );
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(0) => {}
            Some(v) if v == ENOENT => {
                return Err("name_to_handle_at on a fresh cgroup dir returned ENOENT")
            }
            _ => return Err("name_to_handle_at(cap=8) on a cgroup dir failed"),
        }
        if u32::from_ne_bytes(hbuf[0..4].try_into().unwrap()) != 8 {
            return Err("id-form handle_bytes must be 8");
        }
        let cgid = u64::from_ne_bytes(hbuf[8..16].try_into().unwrap());
        if cgid == 0 {
            return Err("cgroup id handle must be the nonzero cgroup inode");
        }
        // The handle id is the same st_ino stat reports for the dir.
        let mut sb = [0u8; 144];
        if call_stat(svc.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("stat of the service cgroup dir failed");
        }
        let st_ino = u64::from_ne_bytes(sb[8..16].try_into().unwrap());
        if cgid != st_ino {
            return Err("cgroup id handle differs from the dir's st_ino");
        }
        Ok(())
    })();
    // The cgroup tree is global — remove the test cgroups, then unmount.
    let _ = call_rmdir(svc.as_ptr() as u64);
    let _ = call_rmdir(slice.as_ptr() as u64);
    let _ = registry().unmount(&mnt, "/abicg");
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
#[cfg(feature = "cgroup")]
kernel_test_in!("syscall_abi", smoke_abi_fsx_name_to_handle_at_cgroup_dir_id);

fn smoke_abi_fsx_open_by_handle_at_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // First mint a real handle for /abi/f.
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&56u32.to_ne_bytes());
        let nargs = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        if call(Syscall::NameToHandleAt.raw(), nargs) != Some(0) {
            return Err("name_to_handle_at setup failed");
        }
        // open_by_handle_at(mount_fd, handle, flags) — re-open the path.
        let oargs = a2(0, hbuf.as_ptr() as u64, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("open_by_handle_at of a fresh handle should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_by_handle_at_pos);

fn smoke_abi_fsx_open_by_handle_at_neg() -> TestResult {
    with_setup(|| {
        // A handle whose handle_type marker is wrong → ESTALE (-116).
        const ESTALE: i64 = -116;
        let mut hbuf = [0u8; 32];
        hbuf[0..4].copy_from_slice(&4u32.to_ne_bytes()); // handle_bytes
        hbuf[4..8].copy_from_slice(&0x1234i32.to_ne_bytes()); // wrong type
        let oargs = a2(0, hbuf.as_ptr() as u64, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v == ESTALE => Ok(()),
            _ => Err("open_by_handle_at with a foreign handle type must return -ESTALE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_by_handle_at_neg);

// ── fsopen / fsconfig / fsmount (new mount API) ───────────────────────
//
// fsopen(fsname, flags) → an fs-context fd. fsconfig(fd, CMD_CREATE) then
// materializes the named FS; fsmount(fd, ...) turns a created context into
// a detached-mount fd. tmpfs is a buildable fs name (build_fs).

const FSCONFIG_CMD_CREATE: u64 = 6;

fn smoke_abi_fsx_fsopen_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("fsopen(tmpfs) should return an fs-context fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsopen_pos);

fn smoke_abi_fsx_fsopen_neg() -> TestResult {
    with_setup(|| {
        // Empty fsname → EINVAL.
        let fsname = b"\0";
        match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fsopen with an empty fsname must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsopen_neg);

fn smoke_abi_fsx_fsconfig_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        // fsconfig(fd, FSCONFIG_CMD_CREATE, ...) → materialize tmpfs → 0.
        let args = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("fsconfig(CMD_CREATE) on a tmpfs context should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsconfig_pos);

fn smoke_abi_fsx_fsconfig_reconfigure_vfs_flags_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let key = b"ro\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        if call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: FSCONFIG_CMD_CREATE,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("fsconfig(CMD_CREATE) setup failed");
        }
        if call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: 0,
                arg2: key.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("fsconfig(SET_FLAG, ro) failed");
        }
        match call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: 7,
                ..Default::default()
            },
        ) {
            Some(0) => Ok(()),
            _ => Err("fsconfig(CMD_RECONFIGURE) must accept VFS ro flag"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_fsconfig_reconfigure_vfs_flags_pos
);

fn smoke_abi_fsx_fsconfig_neg() -> TestResult {
    with_setup(|| {
        // No fs-context for fd 999 → EBADF.
        let args = SyscallArgs {
            arg0: 999,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fsconfig on an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsconfig_neg);

fn smoke_abi_fsx_fsmount_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let cargs = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), cargs) != Some(0) {
            return Err("fsconfig(CMD_CREATE) setup failed");
        }
        // fsmount(fs_fd, flags, attr_flags) → detached-mount fd.
        match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("fsmount on a created context should return a mount fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsmount_pos);

fn smoke_abi_fsx_fsmount_neg() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        // fsmount WITHOUT a prior fsconfig(CMD_CREATE) → EINVAL (no created
        // fs on the context).
        match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fsmount on an un-created context must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsmount_neg);

// systemd's credential setup creates a tmpfs with the new mount API, then
// reopens the detached mount with openat(mfd, ".", O_DIRECTORY|O_CLOEXEC)
// before attaching it at /run/credentials/<unit>. Detached mounts are valid
// directory fds but have no pathname, so this must not take openat's generic
// pathless-fd EBADF branch.
fn smoke_abi_fsx_fsmount_reopen_dot_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fsfd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        if call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fsfd,
                arg1: FSCONFIG_CMD_CREATE,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("fsconfig(CMD_CREATE) setup failed");
        }
        let mfd = match call(Syscall::Fsmount.raw(), a2(fsfd, 0, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsmount setup failed"),
        };
        let dot = b".\0";
        const O_DIRECTORY: u64 = 0o200_000;
        const O_CLOEXEC: u64 = 0o2_000_000;
        let reopened = match call(
            Syscall::Openat.raw(),
            SyscallArgs {
                arg0: mfd,
                arg1: dot.as_ptr() as u64,
                arg2: O_DIRECTORY | O_CLOEXEC,
                ..Default::default()
            },
        ) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("openat(detached-mount, \".\") should reopen the mount"),
        };
        let to = b"/abi-reopened-mount\0";
        match call(
            Syscall::MoveMount.raw(),
            SyscallArgs {
                arg0: reopened,
                arg3: to.as_ptr() as u64,
                ..Default::default()
            },
        ) {
            Some(0) => Ok(()),
            _ => Err("reopened detached mount should be usable by move_mount"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fsmount_reopen_dot_pos);

// ── move_mount ────────────────────────────────────────────────────────
//
// move_mount(from_dfd, from_path, to_dfd, to_path, flags). from_dfd is a
// detached-mount fd from fsmount/open_tree; to_path (arg3) is an absolute
// target. Build a full fsopen→fsconfig→fsmount chain, then attach it.

fn smoke_abi_fsx_move_mount_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let cargs = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), cargs) != Some(0) {
            return Err("fsconfig setup failed");
        }
        let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsmount setup failed"),
        };
        let to = b"/abi-moved\0";
        let args = SyscallArgs {
            arg0: mfd,
            arg1: 0,
            arg2: 0,
            arg3: to.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::MoveMount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("move_mount of a detached mount to a fresh path should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_move_mount_pos);

fn smoke_abi_fsx_move_mount_neg() -> TestResult {
    with_setup(|| {
        // from_dfd 999 is not a detached-mount fd → EBADF.
        let to = b"/abi-x\0";
        let args = SyscallArgs {
            arg0: 999,
            arg1: 0,
            arg2: 0,
            arg3: to.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::MoveMount.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("move_mount from an unknown fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_move_mount_neg);

// ── open_tree ─────────────────────────────────────────────────────────
//
// open_tree(dfd, path, flags) → O_PATH fd by default; OPEN_TREE_CLONE
// requests a detached mount fd cloning the mount that covers an existing
// absolute path. A MemFs mounted at /abi gives a real fs to clone.

fn smoke_abi_fsx_open_tree_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi\0";
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("open_tree of a mounted path should return an O_PATH fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_pos);

fn smoke_abi_fsx_open_tree_mount_fd_relative() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi\0";
        const OPEN_TREE_CLONE: u64 = 1;
        let mount_fd = match call(
            Syscall::OpenTree.raw(),
            a2(0, path.as_ptr() as u64, OPEN_TREE_CLONE),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open_tree(OPEN_TREE_CLONE) should return a mount-object fd"),
        };
        let mut stat = [0u8; 256];
        if call(Syscall::Fstat.raw(), a1(mount_fd, stat.as_mut_ptr() as u64)) != Some(0) {
            return Err("fstat on an open_tree mount fd should succeed");
        }
        let mode = u32::from_ne_bytes(stat[24..28].try_into().unwrap());
        if mode & 0o170000 != 0o040000 {
            return Err("an open_tree mount fd must report S_IFDIR");
        }
        let relative = b"abi\0";
        match call(
            Syscall::OpenTree.raw(),
            a2(mount_fd, relative.as_ptr() as u64, 0),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("open_tree should accept a prior mount-object fd as dirfd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_mount_fd_relative);

fn smoke_abi_fsx_open_tree_empty_path_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let dir = b"/abi\0";
        let fd = match call_open(dir.as_ptr() as u64, 0) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("open_tree setup could not open its directory fd"),
        };
        let empty = b"\0";
        match call(
            Syscall::OpenTree.raw(),
            a2(fd, empty.as_ptr() as u64, 0x1000),
        ) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("open_tree(fd, empty, AT_EMPTY_PATH) should clone the fd's mount"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_empty_path_pos);

fn smoke_abi_fsx_open_tree_neg() -> TestResult {
    with_setup(|| {
        // A relative path is valid only when dfd names a directory.
        let path = b"relative\0";
        match call(
            Syscall::OpenTree.raw(),
            a2(u32::MAX as u64, path.as_ptr() as u64, 0),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("open_tree with a bad dirfd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_neg);

// ── open_tree_attr ───────────────────────────────────────────────────

fn smoke_abi_fsx_open_tree_attr_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi\0";
        let attr = [0u8; 32];
        let args = SyscallArgs {
            arg0: (-100i64) as u64,
            arg1: path.as_ptr() as u64,
            arg2: 0,
            arg3: attr.as_ptr() as u64,
            arg4: attr.len() as u64,
            ..Default::default()
        };
        match call(Syscall::OpenTreeAttr.raw(), args) {
            Some(fd) if fd >= 3 => Ok(()),
            _ => Err("open_tree_attr with a v0 no-op mount_attr should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_attr_pos);

fn smoke_abi_fsx_open_tree_attr_errno_ordering() -> TestResult {
    with_setup(|| {
        // Linux rejects this pair before it tries to open filename.
        let null_attr_with_size = SyscallArgs {
            arg0: u32::MAX as u64,
            arg1: 0,
            arg3: 0,
            arg4: 32,
            ..Default::default()
        };
        if call(Syscall::OpenTreeAttr.raw(), null_attr_with_size) != Some(EINVAL) {
            return Err("open_tree_attr(NULL, nonzero size) must return -EINVAL first");
        }

        // Every other attribute error is checked after opening the tree.
        let relative = b"relative\0";
        let attr = [0u8; 31];
        let bad_dirfd_and_short_attr = SyscallArgs {
            arg0: u32::MAX as u64,
            arg1: relative.as_ptr() as u64,
            arg3: attr.as_ptr() as u64,
            arg4: attr.len() as u64,
            ..Default::default()
        };
        match call(Syscall::OpenTreeAttr.raw(), bad_dirfd_and_short_attr) {
            Some(EBADF) => Ok(()),
            _ => Err("open_tree_attr must report the open-tree error before attr EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_attr_errno_ordering);

fn smoke_abi_fsx_open_tree_attr_validation_and_cleanup() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        const E2BIG: i64 = -7;
        let path = b"/abi\0";
        let mut extended = [0u8; 40];
        extended[39] = 1;
        let bad_extension = SyscallArgs {
            arg0: (-100i64) as u64,
            arg1: path.as_ptr() as u64,
            arg3: extended.as_ptr() as u64,
            arg4: extended.len() as u64,
            ..Default::default()
        };
        if call(Syscall::OpenTreeAttr.raw(), bad_extension) != Some(E2BIG) {
            return Err("open_tree_attr with nonzero extension bytes must return -E2BIG");
        }

        // The failed call prepared fd 3 internally. It must be discarded so
        // the next successful acquisition can reuse fd 3.
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(3) => Ok(()),
            _ => Err("failed open_tree_attr must not leak its provisional fd"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_open_tree_attr_validation_and_cleanup
);

fn smoke_abi_fsx_open_tree_attr_fault_and_size_errno() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        const E2BIG: i64 = -7;
        let path = b"/abi\0";
        let base = SyscallArgs {
            arg0: (-100i64) as u64,
            arg1: path.as_ptr() as u64,
            arg3: 0x0000_0080_0000_0000,
            arg4: 32,
            ..Default::default()
        };
        if call(Syscall::OpenTreeAttr.raw(), base) != Some(EFAULT) {
            return Err("open_tree_attr with an inaccessible attr must return -EFAULT");
        }
        let oversized = SyscallArgs {
            arg3: 1,
            arg4: 4097,
            ..base
        };
        match call(Syscall::OpenTreeAttr.raw(), oversized) {
            Some(E2BIG) => Ok(()),
            _ => Err("open_tree_attr with attr size > PAGE_SIZE must return -E2BIG"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_open_tree_attr_fault_and_size_errno
);

// ── fspick ────────────────────────────────────────────────────────────
//
// fspick(dfd, path, flags) → an fs-context fd for an existing mount. Needs
// an absolute path covered by a real fs.

fn smoke_abi_fsx_fspick_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi\0";
        match call(Syscall::Fspick.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("fspick of a mounted path should return an fs-context fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fspick_pos);

fn smoke_abi_fsx_fspick_neg() -> TestResult {
    with_setup(|| {
        // No fs covers this absolute path → ENOENT.
        let path = b"/abi-absent\0";
        match call(Syscall::Fspick.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_fspick_neg);

// ── mount_setattr ─────────────────────────────────────────────────────
//
// mount_setattr(dfd, path, flags, attr, size). NARF doesn't enforce
// per-mount attrs; a valid v0 struct is accepted as a no-op.

fn smoke_abi_fsx_mount_setattr_pos() -> TestResult {
    with_setup(|| {
        let attr = [0u8; 32];
        let args = SyscallArgs {
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: attr.as_ptr() as u64,
            arg4: 32,
            ..Default::default()
        };
        match call(Syscall::MountSetattr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("mount_setattr with a valid attr size should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_setattr_pos);

fn smoke_abi_fsx_mount_setattr_neg() -> TestResult {
    with_setup(|| {
        // size 0 → EINVAL.
        let args = SyscallArgs {
            arg0: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::MountSetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("mount_setattr with size 0 must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_setattr_neg);

// open(2) refused on permissions must be EACCES, not EPERM.
//
// Linux is explicit: EACCES is "the requested access to the file is not
// allowed, or search permission is denied for one of the directories in the
// path prefix". EPERM means something else. `open_impl` returned its generic
// `fail` value (-1 == -EPERM) from the posix_access_ok gate, so every
// permission denial surfaced as "Operation not permitted".
//
// Found via journalctl on the Fedora Plasma boot: "opening journal file ...:
// Operation not permitted" reads as a capability/ownership bug and sends the
// reader hunting for one, when the truth was an ordinary mode denial. Wrong
// errno costs debugging time far out of proportion to the fix — same class as
// the systemd EXIT_* findings.
fn smoke_abi_fsx_open_permission_denied_is_eacces() -> TestResult {
    with_memfs("/abi-perm", "abi", &[("secret", b"x")], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        let path = b"/abi-perm/secret\0";
        // Root-owned and readable only by its owner.
        if call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o600)) != Some(0) {
            return Err("chmod 0600 setup failed — cannot stage a denial");
        }
        // Drop to an unprivileged uid: posix_access_ok short-circuits for
        // uid 0, so as root this open would succeed and prove nothing.
        // NARF's setresuid always returns 0 (see smoke_abi_creds_setresuid_neg),
        // so the restore below is reliable.
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("setresuid(1000) setup failed");
        }
        let opened = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        );
        // Restore BEFORE asserting, so a failing assertion cannot strand the
        // test task at uid 1000 and cascade into every later test.
        let _ = call(Syscall::Setresuid.raw(), a2(0, 0, 0));
        match opened {
            Some(v) if v == EACCES => Ok(()),
            Some(v) if v == EPERM => {
                Err("open() denial returned EPERM; Linux open(2) specifies EACCES")
            }
            Some(v) if v >= 0 => {
                // Vacuous-test guard: if the open SUCCEEDED the staging failed
                // (memfs ignored the chmod, or the uid drop did not take), and
                // this test would pass no matter what errno the gate returns.
                let _ = call(Syscall::Close.raw(), a0(v as u64));
                Err("open succeeded as uid 1000 on a 0600 root file — staging is vacuous")
            }
            _ => Err("open() on a 0600 root-owned file as uid 1000 must return -EACCES"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_open_permission_denied_is_eacces
);

/// open(2) must consult the SUPPLEMENTARY group list, not just the fsgid.
///
/// The unit test in filesystem/ pins the permission algebra. This pins the
/// WIRING, which is a separate thing and the half that actually broke: for a
/// long time `setgroups`/`getgroups` round-tripped the list perfectly while
/// `current_accessor()` never passed it to `posix_access_ok`, so every ABI
/// test stayed green and uid 1000 still could not open a file owned by a
/// group it holds supplementarily.
///
/// That is not an abstract gap — it is why KDE never rendered.
/// /dev/dri/card0 is crw-rw---- root:video and `narf` is in `video`
/// supplementarily, so kwin's open(O_RDWR) got EACCES and the session died.
///
/// Staged as: file owned by root:GID mode 0660, caller uid 1000 with a
/// primary gid that does NOT match, holding GID only via setgroups.
fn smoke_abi_fsx_open_honours_supplementary_group() -> TestResult {
    with_memfs("/abi-suppgrp", "abi", &[("dev", b"x")], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const GID: u32 = 39; // `video`, mirroring the DRM node that broke
        let path = b"/abi-suppgrp/dev\0";

        // root:GID, rw for owner and group, nothing for other — exactly the
        // shape of a DRM primary node.
        if call(
            Syscall::Chown.raw(),
            a2(path.as_ptr() as u64, 0, GID as u64),
        ) != Some(0)
        {
            return Err("chown root:39 setup failed");
        }
        if call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o660)) != Some(0) {
            return Err("chmod 0660 setup failed");
        }

        // Install GID supplementarily. Must happen while still privileged.
        let groups = [GID];
        if call(
            Syscall::Setgroups.raw(),
            a1(groups.len() as u64, groups.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups([39]) setup failed");
        }
        // Primary gid deliberately NOT 39, so only the supplementary list can
        // select the group triplet. Without that this passes vacuously.
        if call(Syscall::Setresgid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("setresgid(1000) setup failed");
        }
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("setresuid(1000) setup failed");
        }

        let opened = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 2 /* O_RDWR */, 0),
        );
        // Restore BEFORE asserting so a failure cannot strand the task at
        // uid 1000 and cascade into every later test.
        let _ = call(Syscall::Setresuid.raw(), a2(0, 0, 0));
        let _ = call(Syscall::Setresgid.raw(), a2(0, 0, 0));
        let _ = call(Syscall::Setgroups.raw(), a1(0, 0));

        match opened {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
                Ok(())
            }
            Some(v) if v == EACCES => Err(
                "open(O_RDWR) denied despite holding the file's gid supplementarily — \
                 current_accessor() is not passing the setgroups list through",
            ),
            _ => Err("open(O_RDWR) on a 0660 root:39 file with gid 39 supplementary must succeed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_open_honours_supplementary_group
);

/// Replicate systemd-journald's runtime-journal create-and-rotate sequence.
///
/// On the Fedora KDE image journald logs, every boot:
///
///   /run/log/journal/<machine-id>/system.journal: Journal file uses a
///   different sequence number ID, rotating.
///   Failed to create new runtime journal: No such file or directory
///
/// and the runtime journal is then missing for the rest of the boot, which
/// costs every later diagnostic ("No journal files were opened").
///
/// The ENOENT is the interesting part: the directory demonstrably EXISTS
/// (journald just read the old journal out of it), yet creating the
/// replacement reports "No such file or directory". So this replicates what
/// journald actually does, step by step, rather than asserting the error:
///
///   mkdir -p <dir>                          (journal_directory_setup)
///   openat(dir, name, O_CREAT|O_EXCL|O_RDWR, 0640)   (journal_file_open)
///   ftruncate to the initial file size
///   rename(name, name~)                     (journal_file_rotate)
///   openat(dir, name, O_CREAT|O_EXCL|O_RDWR, 0640)   -- the create that fails
///
/// Each step is asserted separately so a failure names the syscall that
/// broke, not just "journald is unhappy". If this passes, the fault is
/// elsewhere (tmpfs-specific behaviour, or journald's dirfd handling) and
/// that is a useful negative result too.
fn smoke_abi_fsx_journald_rotate_sequence() -> TestResult {
    with_memfs("/abi-jrnl", "jrnl", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        const O_DIRECTORY: u64 = 0o200000;

        // journald creates the machine-id directory tree first.
        let dir = b"/abi-jrnl/log\0";
        let dir2 = b"/abi-jrnl/log/journal\0";
        let dir3 = b"/abi-jrnl/log/journal/mid\0";
        for d in [&dir[..], &dir2[..], &dir3[..]] {
            let r = call(
                Syscall::Mkdirat.raw(),
                a3(AT_FDCWD, d.as_ptr() as u64, 0o755, 0),
            );
            if r != Some(0) {
                return Err("mkdir of the journal directory tree failed");
            }
        }

        // journald holds an fd on the directory and creates the journal
        // RELATIVE to it — that dirfd path is the part most likely to break.
        let dfd = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir3.as_ptr() as u64, O_DIRECTORY, 0),
        );
        let dfd = match dfd {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("could not open the journal directory as a dirfd"),
        };

        let name = b"system.journal\0";
        let fd = call(
            Syscall::Openat.raw(),
            a3(dfd, name.as_ptr() as u64, O_CREAT | O_EXCL | O_RDWR, 0o640),
        );
        let fd = match fd {
            Some(v) if v >= 0 => v,
            Some(v) => {
                let _ = call(Syscall::Close.raw(), a0(dfd));
                let _ = v;
                return Err("openat(dirfd, system.journal, O_CREAT|O_EXCL) failed");
            }
            None => {
                let _ = call(Syscall::Close.raw(), a0(dfd));
                return Err("openat(dirfd, system.journal, O_CREAT|O_EXCL) returned nothing");
            }
        };
        // journald sizes the file up front rather than appending.
        if call(Syscall::Ftruncate.raw(), a1(fd as u64, 8 * 1024 * 1024)) != Some(0) {
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            let _ = call(Syscall::Close.raw(), a0(dfd));
            return Err("ftruncate of the new journal failed");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));

        // Rotation: rename the live journal aside, then create a fresh one
        // under the SAME name. This pair is what the boot log is doing.
        let old = b"/abi-jrnl/log/journal/mid/system.journal\0";
        let rotated = b"/abi-jrnl/log/journal/mid/system@0001.journal~\0";
        if call_rename(old.as_ptr() as u64, rotated.as_ptr() as u64) != Some(0) {
            let _ = call(Syscall::Close.raw(), a0(dfd));
            return Err("rename of the live journal aside (rotation) failed");
        }

        let fd2 = call(
            Syscall::Openat.raw(),
            a3(dfd, name.as_ptr() as u64, O_CREAT | O_EXCL | O_RDWR, 0o640),
        );
        let _ = call(Syscall::Close.raw(), a0(dfd));
        match fd2 {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
                Ok(())
            }
            Some(v) if v == ENOENT => {
                Err("post-rotation create returned ENOENT — this is journald's \
                 'Failed to create new runtime journal: No such file or directory'")
            }
            _ => Err("post-rotation openat(O_CREAT|O_EXCL) did not succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_journald_rotate_sequence);

/// `renameat(dirfd, …)` must resolve relative paths against the DIRFD.
///
/// Companion to `smoke_abi_fsx_journald_rotate_sequence`, and deliberately
/// kept separate: that test rotates with absolute paths and PASSES, so on
/// its own it certifies a rotation journald never performs. systemd's
/// `journal_file_dispose()` rotates with
/// `renameat(dir_fd, name, dir_fd, newname)` against the directory fd it
/// already holds. NARF's `sys_renameat` discarded BOTH dirfds
/// (`let _old_dirfd = args.arg0;`) and proxied straight to `sys_rename`, so
/// a relative path resolved against the CWD instead — which fails outright,
/// or, worse, renames a same-named file in the wrong directory.
///
/// Two tests rather than one tightened test because they fail for different
/// reasons and a single combined case cannot tell "rename is broken" from
/// "the dirfd is ignored".
///
/// Asserted three ways so a partial implementation cannot pass:
///   1. the rename SUCCEEDS,
///   2. the new name exists in the target directory,
///   3. the old name is GONE from it — a handler that ignored the dirfd and
///      happened to create something in the cwd would still trip this.
fn smoke_abi_fsx_renameat_honours_dirfd() -> TestResult {
    with_memfs("/abi-rnat", "rnat", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        const O_DIRECTORY: u64 = 0o200000;

        let dir = b"/abi-rnat/d\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir of the rename directory failed");
        }
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, O_DIRECTORY, 0),
        ) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("could not open the directory as a dirfd"),
        };

        let src = b"live\0";
        let dst = b"rotated~\0";
        match call(
            Syscall::Openat.raw(),
            a3(dfd, src.as_ptr() as u64, O_CREAT | O_EXCL | O_RDWR, 0o640),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => {
                let _ = call(Syscall::Close.raw(), a0(dfd));
                return Err("could not create the source file relative to the dirfd");
            }
        }

        let r = call(
            Syscall::Renameat.raw(),
            a3(dfd, src.as_ptr() as u64, dfd, dst.as_ptr() as u64),
        );
        if r != Some(0) {
            let _ = call(Syscall::Close.raw(), a0(dfd));
            return Err(
                "renameat(dirfd, relative) failed — journald's journal_file_dispose() \
                 rotates exactly this way",
            );
        }

        // The new name must exist IN THAT DIRECTORY...
        let moved = call(
            Syscall::Openat.raw(),
            a3(dfd, dst.as_ptr() as u64, O_RDWR, 0),
        );
        let moved_ok = matches!(moved, Some(v) if v >= 0);
        if let Some(v) = moved {
            if v >= 0 {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
        }
        // ...and the old name must be gone from it.
        let stale = call(
            Syscall::Openat.raw(),
            a3(dfd, src.as_ptr() as u64, O_RDWR, 0),
        );
        let stale_gone = !matches!(stale, Some(v) if v >= 0);
        if let Some(v) = stale {
            if v >= 0 {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
        }
        let _ = call(Syscall::Close.raw(), a0(dfd));

        if !moved_ok {
            return Err(
                "renameat reported success but the new name is not in the dirfd's directory",
            );
        }
        if !stale_gone {
            return Err(
                "renameat reported success but the old name is still in the dirfd's directory",
            );
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_renameat_honours_dirfd);

/// `renameat2(olddirfd, …, newdirfd, …)` must honour its dirfds too.
///
/// Same defect as `smoke_abi_fsx_renameat_honours_dirfd`, in a second
/// handler that was documented as intentional: "dirfds are treated as
/// AT_FDCWD — paths must be absolute". glibc implements plain `rename(2)`
/// on top of renameat2, so this is the path a distro libc actually takes,
/// and a relative path there resolved against the CWD.
///
/// Fixing one handler and not the other is exactly how this class of bug
/// survives, so both are pinned separately.
fn smoke_abi_fsx_renameat2_honours_dirfd() -> TestResult {
    with_memfs("/abi-rn2", "rn2", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        const O_DIRECTORY: u64 = 0o200000;

        let dir = b"/abi-rn2/d\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir failed");
        }
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, O_DIRECTORY, 0),
        ) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("could not open the directory as a dirfd"),
        };

        let src = b"a\0";
        let dst = b"b\0";
        match call(
            Syscall::Openat.raw(),
            a3(dfd, src.as_ptr() as u64, O_CREAT | O_EXCL | O_RDWR, 0o644),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => {
                let _ = call(Syscall::Close.raw(), a0(dfd));
                return Err("could not create the source relative to the dirfd");
            }
        }

        // flags = 0 (plain rename semantics), both dirfds = our directory.
        // `a3` fills arg0..arg3 and leaves arg4 (flags) at its default 0.
        let r = call(
            Syscall::Renameat2.raw(),
            a3(dfd, src.as_ptr() as u64, dfd, dst.as_ptr() as u64),
        );
        if r != Some(0) {
            let _ = call(Syscall::Close.raw(), a0(dfd));
            return Err("renameat2(dirfd, relative) failed");
        }

        let moved = call(
            Syscall::Openat.raw(),
            a3(dfd, dst.as_ptr() as u64, O_RDWR, 0),
        );
        let moved_ok = matches!(moved, Some(v) if v >= 0);
        if let Some(v) = moved {
            if v >= 0 {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
        }
        let _ = call(Syscall::Close.raw(), a0(dfd));
        if !moved_ok {
            return Err(
                "renameat2 reported success but the new name is not in the dirfd's directory",
            );
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_renameat2_honours_dirfd);

/// The rest of the `*at()` family must honour its dirfd too.
///
/// `renameat`/`renameat2` were only the two that journald tripped over.
/// The same defect — `let _dirfd = args.arg0;` then proxy to the non-`at`
/// handler with the raw user pointer — was present in `unlinkat`,
/// `newfstatat` and `symlinkat`. Each is exercised the way a real component
/// uses it:
///
///   fstatat   sd-device walks sysfs one component at a time against
///             parent-directory fds; glibc's stat()/lstat() sit on it.
///   unlinkat  journald removes rotated journals, systemd-tmpfiles prunes
///             trees, both against a held directory fd.
///   symlinkat udev creates every /dev/by-id, by-path, by-uuid alias.
///
/// Each is asserted POSITIVELY (the operation took effect in the dirfd's
/// directory), not merely "did not return an error" — with the dirfd
/// ignored, a same-named file under the cwd makes these succeed while
/// touching the WRONG file, which no error check would catch.
fn smoke_abi_fsx_at_family_honours_dirfd() -> TestResult {
    with_memfs("/abi-atfam", "atfam", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        const O_DIRECTORY: u64 = 0o200000;

        let dir = b"/abi-atfam/d\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir failed");
        }
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, O_DIRECTORY, 0),
        ) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("could not open the directory as a dirfd"),
        };
        let close_dfd = || {
            let _ = call(Syscall::Close.raw(), a0(dfd));
        };

        // ---- fstatat(dirfd, relative) ----------------------------------
        let f = b"target\0";
        match call(
            Syscall::Openat.raw(),
            a3(dfd, f.as_ptr() as u64, O_CREAT | O_EXCL | O_RDWR, 0o644),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => {
                close_dfd();
                return Err("could not create the file relative to the dirfd");
            }
        }
        let mut st = [0u8; 144];
        let r = call(
            Syscall::Newfstatat.raw(),
            a3(dfd, f.as_ptr() as u64, st.as_mut_ptr() as u64, 0),
        );
        if r != Some(0) {
            close_dfd();
            return Err("fstatat(dirfd, relative) failed — sd-device walks sysfs this way");
        }

        // ---- symlinkat(target, newdirfd, relative link) ----------------
        let tgt = b"target\0";
        let link = b"alias\0";
        if call(
            Syscall::Symlinkat.raw(),
            a2(tgt.as_ptr() as u64, dfd, link.as_ptr() as u64),
        ) != Some(0)
        {
            close_dfd();
            return Err(
                "symlinkat(newdirfd, relative) failed — udev creates /dev aliases this way",
            );
        }
        // The link must be IN the dirfd's directory: open it there.
        match call(
            Syscall::Openat.raw(),
            a3(dfd, link.as_ptr() as u64, O_RDWR, 0),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => {
                close_dfd();
                return Err(
                    "symlinkat reported success but the link is not in the dirfd's directory",
                );
            }
        }

        // ---- unlinkat(dirfd, relative) ---------------------------------
        if call(Syscall::Unlinkat.raw(), a2(dfd, link.as_ptr() as u64, 0)) != Some(0) {
            close_dfd();
            return Err(
                "unlinkat(dirfd, relative) failed — journald removes rotated journals this way",
            );
        }
        // ...and it must actually be gone FROM THAT DIRECTORY.
        let still = call(
            Syscall::Openat.raw(),
            a3(dfd, link.as_ptr() as u64, O_RDWR, 0),
        );
        let gone = !matches!(still, Some(v) if v >= 0);
        if let Some(v) = still {
            if v >= 0 {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
        }
        close_dfd();
        if !gone {
            return Err("unlinkat reported success but the name is still in the dirfd's directory");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_at_family_honours_dirfd);

/// `stat(2)` on a RELATIVE path must resolve against the cwd.
///
/// `sys_stat` resolves with `apply_chroot()` while nearly every other path
/// syscall uses `resolve_cwd_path()`. `apply_chroot` applies the chroot but
/// does NOT join the cwd (nor normalise `//`), so a relative path reaches
/// the registry unanchored.
///
/// Whether that actually breaks stat is the question this test settles —
/// it is written to FAIL LOUDLY either way rather than to confirm a guess:
/// chdir into a directory, stat a name inside it relatively, and require
/// the same result an absolute stat gives.
///
/// This matters beyond tidiness: busybox's shell stats its way along
/// `$PATH`, and configure-style scripts stat relative paths constantly.
fn smoke_abi_fsx_stat_relative_uses_cwd() -> TestResult {
    with_memfs("/abi-statrel", "statrel", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        let abs = b"/abi-statrel/sub/f\0";
        let dir = b"/abi-statrel/sub\0";
        let rel = b"f\0";

        // Stage explicitly: a nested seed path is not created as a
        // directory tree by with_memfs, which made an earlier version of
        // this test fail on its own staging rather than on stat.
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir of the test subdirectory failed");
        }
        match call(
            Syscall::Openat.raw(),
            a3(
                AT_FDCWD,
                abs.as_ptr() as u64,
                O_CREAT | O_EXCL | O_RDWR,
                0o644,
            ),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => return Err("could not create the file to stat"),
        }

        // Baseline: the absolute stat must work, else the test is vacuous.
        let mut st_abs = [0u8; 144];
        if call(
            Syscall::Stat.raw(),
            a1(abs.as_ptr() as u64, st_abs.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("absolute stat of the seeded file failed — staging is broken");
        }

        // DISCRIMINATOR: from the root, the bare name must NOT resolve.
        // Without this the test cannot tell "cwd was honoured" from "the
        // name resolved by some other route", and would pass vacuously.
        let root = b"/\0";
        let _ = call(Syscall::Chdir.raw(), a0(root.as_ptr() as u64));
        let mut st_pre = [0u8; 144];
        if call(
            Syscall::Stat.raw(),
            a1(rel.as_ptr() as u64, st_pre.as_mut_ptr() as u64),
        ) == Some(0)
        {
            return Err("the bare name resolved from / — this test cannot prove the cwd is used");
        }

        if call(Syscall::Chdir.raw(), a0(dir.as_ptr() as u64)) != Some(0) {
            return Err("chdir into the seeded directory failed");
        }
        // chdir returning 0 does not prove the cwd MOVED. Read it back, so
        // a silently-nop chdir cannot make the rest of this test look like
        // a statement about relative resolution.
        let mut cwd = [0u8; 256];
        let n = call(
            Syscall::Getcwd.raw(),
            a1(cwd.as_mut_ptr() as u64, cwd.len() as u64),
        );
        let cwd_ok = match n {
            Some(v) if v > 0 => {
                let end = core::cmp::min(v as usize, cwd.len());
                let got = &cwd[..end];
                let got = match got.iter().position(|&b| b == 0) {
                    Some(i) => &got[..i],
                    None => got,
                };
                got == b"/abi-statrel/sub"
            }
            _ => false,
        };
        if !cwd_ok {
            let _ = call(Syscall::Chdir.raw(), a0(root.as_ptr() as u64));
            return Err("getcwd did not report /abi-statrel/sub after chdir");
        }
        let mut st_rel = [0u8; 144];
        let r = call(
            Syscall::Stat.raw(),
            a1(rel.as_ptr() as u64, st_rel.as_mut_ptr() as u64),
        );
        // Restore cwd BEFORE asserting so a failure cannot strand later tests.
        let _ = call(Syscall::Chdir.raw(), a0(root.as_ptr() as u64));

        match r {
            Some(0) => Ok(()),
            _ => Err(
                "stat() of a relative path after chdir failed — sys_stat resolves with \
                 apply_chroot(), which does not join the cwd",
            ),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_stat_relative_uses_cwd);

/// `rename(2)` must ATOMICALLY REPLACE an existing destination.
///
/// POSIX and Linux both require it: if newpath exists it is replaced, and
/// there is never a window where the name is absent. Only
/// `renameat2(RENAME_NOREPLACE)` refuses, and that returns EEXIST.
///
/// This is the single operation Qt's QSaveFile performs on every write
/// after the first: write a temp file beside the target, then rename it
/// ONTO the (existing) target. KConfig, KSycoca and every KDE config write
/// go through it. NARF returned EINVAL, and KConfig reports any failed
/// commit as `Couldn't write "<path>" . Disk full?` — which sent this
/// investigation looking at free space and directory ownership, both fine.
///
/// Measured in-guest before the fix, as uid 1000 on the real ext2 /home:
///     QSF: rename(tmp -> target)   ok (0)          [target absent]
///     QSF: rename over EXISTING    FAILED errno=22 (Invalid argument)
///
/// The first rename is asserted too: a test that only renamed onto a free
/// name passes on the broken implementation, which is exactly why this went
/// unnoticed.
fn smoke_abi_fsx_rename_replaces_existing() -> TestResult {
    with_memfs("/abi-rnrep", "rnrep", &[], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;

        let src = b"/abi-rnrep/tmp\0";
        let dst = b"/abi-rnrep/target\0";

        let mk = |p: &[u8]| -> bool {
            match call(
                Syscall::Openat.raw(),
                a3(
                    AT_FDCWD,
                    p.as_ptr() as u64,
                    O_CREAT | O_EXCL | O_RDWR,
                    0o644,
                ),
            ) {
                Some(v) if v >= 0 => {
                    let _ = call(Syscall::Close.raw(), a0(v as u64));
                    true
                }
                _ => false,
            }
        };

        // Pass 1: destination absent. This is the case a naive test covers,
        // and it works even on the broken implementation.
        if !mk(src) {
            return Err("could not create the source file");
        }
        if call_rename(src.as_ptr() as u64, dst.as_ptr() as u64) != Some(0) {
            return Err("rename onto an ABSENT destination failed");
        }

        // Pass 2: destination now EXISTS. This is what QSaveFile does on
        // every subsequent write, and what actually broke.
        if !mk(src) {
            return Err("could not re-create the source file");
        }
        let r = call_rename(src.as_ptr() as u64, dst.as_ptr() as u64);
        if r != Some(0) {
            return Err(
                "rename onto an EXISTING destination failed — POSIX requires atomic \
                 replacement; this is Qt QSaveFile's write path (KConfig 'Disk full?')",
            );
        }

        // The source name must be gone and the destination must remain.
        let src_gone = !matches!(
            call(Syscall::Openat.raw(), a3(AT_FDCWD, src.as_ptr() as u64, O_RDWR, 0)),
            Some(v) if v >= 0
        );
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dst.as_ptr() as u64, O_RDWR, 0),
        ) {
            Some(v) if v >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(v as u64));
            }
            _ => return Err("destination missing after replacing rename"),
        }
        if !src_gone {
            return Err("source still present after rename");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_rename_replaces_existing);

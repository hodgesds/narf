//! Linux syscall ABI conformance — fsx group.
//!
//! Covers the extended-attribute family (set/get/list/remove in the
//! path/lpath/fd variants) and the mount / new-mount-API surface
//! (mount, umount2, pivot_root, name_to_handle_at, open_by_handle_at,
//! fsopen/fsconfig/fsmount/move_mount/open_tree/fspick/mount_setattr).
//!
//! Shares the harness in [`crate::abi_test_support`]; every test drives
//! `kernel_syscall_entry` through a synthetic `AbiCtx`. The xattr handlers
//! store into a side `BTreeMap` keyed by the (chroot-resolved) path string,
//! so a positive set/get round-trips even against a path that names no real
//! inode. The fd-keyed `f*xattr` family keys on an `anon_inode:[Type]`
//! placeholder derived from the fd's `FileOps` type, so an open MemFs fd is
//! enough to reach the success path.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// ENODATA is the wire value the xattr handlers use for "no such attribute";
// it isn't in the shared harness errno set, so define it locally.
const ENODATA: i64 = -61;

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
// NARF mount ABI: arg0/arg1 = source ptr/len, arg2/arg3 = target ptr/len,
// arg4 = fstype ptr, arg5 packs fstype_len in the top 32 bits and the MS_*
// flag word in the bottom 32 bits. tmpfs/ramfs synthesize a fresh in-memory
// FS and mount it. NOTE: the handler returns SyscallReturn::ok(!0) (value
// -1) as its failure sentinel — both success (0) and failure (-1) come back
// with NARF status Ok, so `call` returns Some in both cases.

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
        let fd = crate::fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: dev.clone(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
        })
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
// arg0/arg1 = target ptr/len, arg2 = MNT_* flags. The registry pop-by-path
// is unconditional; an unmount of a path with no mount returns the -1
// sentinel (again Ok status). Mount a tmpfs first for the positive case.

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
        let target = b"/abi-not-mounted\0";
        let uargs = a1(target.as_ptr() as u64, 0);
        // LINUX-GAP: Linux returns -EINVAL for a path that isn't a mount
        // point; NARF uses the -1 sentinel.
        match call(Syscall::Umount2.raw(), uargs) {
            Some(-1) => Ok(()),
            _ => Err("umount2 of a non-mount path must return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_neg);

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
        match call(Syscall::PivotRoot.raw(), args) {
            Some(-1) => Ok(()),
            Some(_) => Err("pivot_root with an unresolvable new_root must fail"),
            None => Err("linux-compat pivot_root must be present in the syscall table"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_pivot_root_neg);

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
// per-mount attrs; a well-formed call (struct mount_attr size 1..=64)
// just succeeds. size 0 or > 64 → EINVAL.

fn smoke_abi_fsx_mount_setattr_pos() -> TestResult {
    with_setup(|| {
        // arg4 = size = 32 (sizeof struct mount_attr) → ok(0).
        let args = SyscallArgs {
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
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
            Some(v) if v as i64 == EACCES => Ok(()),
            Some(v) if v as i64 == EPERM => {
                Err("open() denial returned EPERM; Linux open(2) specifies EACCES")
            }
            Some(v) if (v as i64) >= 0 => {
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

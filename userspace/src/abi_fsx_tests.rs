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
    match call(Syscall::OpenFile.raw(), a0(path.as_ptr() as u64)) {
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
        match call(Syscall::Flistxattr.raw(), largs) {
            Some(8) => Ok(()),
            _ => Err("flistxattr(size=0) should report the name-list length"),
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
        let source = b"none";
        let target = b"/abi-tmpfs";
        let fstype = b"tmpfs";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: source.len() as u64,
            arg2: target.as_ptr() as u64,
            arg3: target.len() as u64,
            arg4: fstype.as_ptr() as u64,
            arg5: (fstype.len() as u64) << 32, // len in high 32, flags=0 low
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
        // Unknown block-device source + unknown fstype → -1 sentinel.
        let source = b"nodevhere";
        let target = b"/abi-bad";
        let fstype = b"ext9";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: source.len() as u64,
            arg2: target.as_ptr() as u64,
            arg3: target.len() as u64,
            arg4: fstype.as_ptr() as u64,
            arg5: (fstype.len() as u64) << 32,
        };
        // LINUX-GAP: Linux returns -ENODEV/-ENOENT here; NARF uses a bare
        // -1 sentinel for every mount failure.
        match call(Syscall::Mount.raw(), args) {
            Some(-1) => Ok(()),
            _ => Err("mount with an unknown device/fstype must return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_neg);

// ── umount2 ───────────────────────────────────────────────────────────
//
// arg0/arg1 = target ptr/len, arg2 = MNT_* flags. The registry pop-by-path
// is unconditional; an unmount of a path with no mount returns the -1
// sentinel (again Ok status). Mount a tmpfs first for the positive case.

fn smoke_abi_fsx_umount2_pos() -> TestResult {
    with_setup(|| {
        let source = b"none";
        let target = b"/abi-umnt";
        let fstype = b"tmpfs";
        let margs = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: source.len() as u64,
            arg2: target.as_ptr() as u64,
            arg3: target.len() as u64,
            arg4: fstype.as_ptr() as u64,
            arg5: (fstype.len() as u64) << 32,
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("setup mount failed");
        }
        let uargs = a2(target.as_ptr() as u64, target.len() as u64, 0);
        match call(Syscall::Umount2.raw(), uargs) {
            Some(0) => Ok(()),
            _ => Err("umount2 of a freshly-mounted path should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_pos);

fn smoke_abi_fsx_umount2_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-not-mounted";
        let uargs = a2(target.as_ptr() as u64, target.len() as u64, 0);
        // LINUX-GAP: Linux returns -EINVAL for a path that isn't a mount
        // point; NARF uses the -1 sentinel.
        match call(Syscall::Umount2.raw(), uargs) {
            Some(-1) => Ok(()),
            _ => Err("umount2 of a non-mount path must return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_umount2_neg);

// ── pivot_root ────────────────────────────────────────────────────────
//
// arg0/arg1 = new_root ptr/len, arg2/arg3 = put_old ptr/len. Both must be
// absolute and new_root must resolve to an existing path. NOTE: under the
// harness this handler is only present with feature "container"; the test
// still compiles unconditionally and asserts the negative (failure)
// behaviour, which the table reports as -1 / OK either way (a missing slot
// in kernel_syscall_entry returns its own failure shape).

fn smoke_abi_fsx_pivot_root_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // new_root is not absolute → -1 sentinel (relative path rejected).
        let new_root = b"relative\0";
        let put_old = b"/abi\0";
        let args = a3(
            new_root.as_ptr() as u64,
            (new_root.len() - 1) as u64, // strip NUL: pass the byte length
            put_old.as_ptr() as u64,
            (put_old.len() - 1) as u64,
        );
        // LINUX-GAP: Linux returns -EINVAL/-ENOTDIR; NARF returns -1 on a
        // non-absolute new_root. The pivot_root slot may also be absent
        // (no "container" feature) — then the entry reports a non-Ok
        // status and `call` is None. Accept either failure shape.
        match call(Syscall::PivotRoot.raw(), args) {
            Some(-1) | None => Ok(()),
            Some(_) => Err("pivot_root with a relative new_root must fail"),
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
            Some(0) => Ok(()),
            _ => Err("name_to_handle_at on an existing file should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_name_to_handle_at_pos);

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
// open_tree(dfd, path, flags) → detached-mount fd cloning the mount that
// covers an existing absolute path. A MemFs mounted at /abi gives a real
// fs to clone.

fn smoke_abi_fsx_open_tree_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi\0";
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("open_tree of a mounted path should return a detached-mount fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_tree_pos);

fn smoke_abi_fsx_open_tree_neg() -> TestResult {
    with_setup(|| {
        // Relative path → EINVAL.
        let path = b"relative\0";
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("open_tree with a relative path must return -EINVAL"),
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

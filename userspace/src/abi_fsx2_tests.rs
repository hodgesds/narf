//! Linux syscall ABI conformance — fsx group, audit round 2.
//!
//! Additional regression pins for handler branches the first-pass
//! `abi_fsx_tests.rs` leaves uncovered:
//!   - xattr cores: EFAULT on a bad path/value pointer, EINVAL on an empty
//!     name in the get/list/remove cores, ERANGE on an undersized *get*
//!     buffer (the first file only pins ERANGE on the *list* path), and the
//!     XATTR_CREATE/XATTR_REPLACE flag branches (EEXIST / ENODATA).
//!   - name_to_handle_at: EINVAL (empty path), EFAULT (bad handle buf),
//!     EOVERFLOW (caller capacity smaller than the path).
//!   - open_by_handle_at: EINVAL (right handle type, zero handle_bytes),
//!     EFAULT (unreadable handle pointer).
//!   - mount: bind-mount success path; -1 sentinel on an unreadable target.
//!   - new-mount-API: fsconfig ENODEV (un-buildable fsname) + FSCONFIG_SET_STRING
//!     no-op success; move_mount EINVAL (valid fd, relative target);
//!     open_tree ENOENT (absolute path, no mount); fspick EINVAL (relative);
//!     mount_setattr EINVAL on the size>64 upper bound.
//!
//! Shares the harness in [`crate::abi_test_support`]; every test drives
//! `kernel_syscall_entry` through a synthetic `AbiCtx`.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// Wire values not in the shared harness set.
const ENODATA: i64 = -61;
const EOVERFLOW: i64 = -75;

// Linux setxattr flags.
const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;

// new-mount-API fsconfig commands.
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_CREATE: u64 = 6;

// Open a MemFs-backed file via the (linux-compat) open syscall.
fn open_memfs_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(v) if v >= 0 => Ok(v as u32),
        _ => Err("open of seeded MemFs file should yield an fd"),
    }
}

// ── setxattr: EFAULT on a NULL path pointer ───────────────────────────
//
// sys_setxattr → xattr_user_path(arg0); a 0/zero pointer yields None →
// the handler's second branch: ok(-EFAULT). The first file only pins the
// EINVAL (empty-name) core branch and the 0 success branch.

fn smoke_abi_fsx2_setxattr_efault_neg() -> TestResult {
    with_setup(|| {
        let name = b"user.k\0";
        let val = b"v";
        let args = SyscallArgs {
            arg0: 0, // bad path pointer → xattr_user_path None
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("setxattr with a NULL path pointer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_efault_neg);

// ── setxattr: EFAULT on a bad value pointer (size > 0) ────────────────
//
// xattr_set_core: name is valid, size != 0, so copy_from_user_vec(arg2)
// runs; a bogus value pointer fails → ok(-EFAULT).

fn smoke_abi_fsx2_setxattr_value_efault_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/vf\0";
        let name = b"user.vf\0";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0x0001_0000_0000_0000, // unmapped value pointer
            arg3: 8,                     // size != 0 forces the copy
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("setxattr with a bad value pointer (size>0) must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_value_efault_neg);

// ── setxattr: XATTR_REPLACE on a missing attribute → ENODATA ──────────
//
// xattr_set_core flag branch: flags & XATTR_REPLACE && !exists → ok(-ENODATA).

fn smoke_abi_fsx2_setxattr_replace_missing_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/repl\0";
        let name = b"user.repl\0";
        let val = b"v";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: XATTR_REPLACE,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("setxattr XATTR_REPLACE of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_replace_missing_neg);

// ── setxattr: XATTR_CREATE on an existing attribute → EEXIST ──────────
//
// Seed once, then re-set with XATTR_CREATE: flags & XATTR_CREATE && exists
// → ok(-EEXIST). This is the positive-feature path for the create flag.

fn smoke_abi_fsx2_setxattr_create_exists_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/cre\0";
        let name = b"user.cre\0";
        let val = b"v";
        let seed = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), seed) != Some(0) {
            return Err("seed setxattr failed");
        }
        let again = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: XATTR_CREATE,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), again) {
            Some(v) if v == EEXIST => Ok(()),
            _ => Err("setxattr XATTR_CREATE on an existing attribute must return -EEXIST"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_create_exists_pos);

// ── getxattr: ERANGE on an undersized destination buffer ──────────────
//
// xattr_get_core: name valid, value present, size != 0 but size < value.len()
// → ok(-ERANGE). The first file only pins getxattr(size=0) and the missing
// (ENODATA) case; ERANGE on the *value* buffer is unhit there.

fn smoke_abi_fsx2_getxattr_erange_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/ge\0";
        let name = b"user.ge\0";
        let val = b"abcdefgh"; // 8 bytes
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
        let mut buf = [0u8; 4];
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 4, // < 8 → ERANGE
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("getxattr with an undersized value buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_erange_neg);

// ── getxattr: full copy-out success path ──────────────────────────────
//
// size >= value.len() drives the copy_to_user branch and returns the value
// length. The first file only exercises getxattr(size=0) (length probe).

fn smoke_abi_fsx2_getxattr_copyout_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/gc\0";
        let name = b"user.gc\0";
        let val = b"wxyz"; // 4 bytes
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
        let mut buf = [0u8; 8];
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 8, // >= 4 → copy out, return len
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == val.len() as i64 && &buf[..4] == val => Ok(()),
            _ => Err("getxattr(size>=len) should copy the value and return its length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_copyout_pos);

// ── getxattr: EINVAL on an empty name ─────────────────────────────────
//
// xattr_get_core rejects an empty name before any lookup. Distinct from the
// first file's getxattr ENODATA (unset attribute) case.

fn smoke_abi_fsx2_getxattr_emptyname_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/gn\0";
        let name = b"\0"; // empty → EINVAL
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("getxattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_emptyname_neg);

// ── listxattr: full copy-out success path ─────────────────────────────
//
// size >= names.len() drives the copy_to_user branch in xattr_list_core and
// returns the list length with the buffer populated. The first file only
// pins listxattr(size=0) and the ERANGE case.

fn smoke_abi_fsx2_listxattr_copyout_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lc\0";
        let name = b"user.lc\0"; // "user.lc\0" = 8 bytes
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
        let mut buf = [0u8; 16];
        let largs = a2(path.as_ptr() as u64, buf.as_mut_ptr() as u64, 16);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(8) if &buf[..8] == b"user.lc\0" => Ok(()),
            _ => Err("listxattr(size>=len) should copy the name list and return its length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_listxattr_copyout_pos);

// ── listxattr: empty list (no attrs) → 0 ──────────────────────────────
//
// A path with no stored attributes yields an empty name list; size=0 returns
// 0 (not an error). Pins the "names empty, size 0" exit.

fn smoke_abi_fsx2_listxattr_empty_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/empty-list\0";
        let largs = a2(path.as_ptr() as u64, 0, 0);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(0) => Ok(()),
            _ => Err("listxattr(size=0) of a path with no attrs should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_listxattr_empty_pos);

// ── removexattr: EINVAL on an empty name ──────────────────────────────
//
// xattr_remove_core rejects an empty name. The first file pins removexattr
// ENODATA (unset attribute) but not the empty-name branch.

fn smoke_abi_fsx2_removexattr_emptyname_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/rn\0";
        let name = b"\0"; // empty → EINVAL
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Removexattr.raw(), rargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("removexattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_removexattr_emptyname_neg);

// ── fgetxattr: ERANGE on an undersized fd-keyed buffer ────────────────
//
// fd-keyed get core hits the same ERANGE branch; the first file only pins
// fgetxattr(size=0) and the EBADF case.

fn smoke_abi_fsx2_fgetxattr_erange_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fe\0";
        let val = b"longvalue"; // 9 bytes
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
        let mut buf = [0u8; 4];
        let gargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 4, // < 9 → ERANGE
            ..Default::default()
        };
        match call(Syscall::Fgetxattr.raw(), gargs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("fgetxattr with an undersized buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fgetxattr_erange_neg);

// ── name_to_handle_at: EINVAL on an empty path ────────────────────────
//
// sys_name_to_handle_at rejects an empty path BEFORE the existence check.
// The first file pins ENOENT (missing path) and 0 (success), not EINVAL.

fn smoke_abi_fsx2_name_to_handle_at_einval_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"\0"; // empty → EINVAL
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&32u32.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("name_to_handle_at with an empty path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_einval_neg);

// ── name_to_handle_at: EOVERFLOW when capacity < path length ──────────
//
// Existing path, but the caller's handle_bytes (first u32 of arg2) is
// smaller than the path length → the handler writes the needed size back
// and returns -EOVERFLOW. "/abi/f" is 6 bytes; advertise capacity 2.

fn smoke_abi_fsx2_name_to_handle_at_overflow_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        let cap: u32 = 2; // < 6 → EOVERFLOW
        hbuf[0..4].copy_from_slice(&cap.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EOVERFLOW => {
                // Handler should have written the required size (6) back.
                let needed = u32::from_ne_bytes(hbuf[0..4].try_into().unwrap());
                if needed == 6 {
                    Ok(())
                } else {
                    Err("name_to_handle_at EOVERFLOW should report the required size")
                }
            }
            _ => Err("name_to_handle_at with too-small capacity must return -EOVERFLOW"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_overflow_neg);

// ── name_to_handle_at: EFAULT on an unreadable handle buffer ──────────
//
// Existing path, but arg2 (the handle buffer whose first u32 is read) is
// unmapped → copy_from_user fails → -EFAULT.

fn smoke_abi_fsx2_name_to_handle_at_efault_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let args = a3(0, path.as_ptr() as u64, 0x0001_0000_0000_0000, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("name_to_handle_at with an unreadable handle buffer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_efault_neg);

// ── open_by_handle_at: EINVAL on zero handle_bytes (right type) ───────
//
// htype matches NARF_HANDLE_TYPE, but handle_bytes == 0 → -EINVAL. The
// first file pins ESTALE (wrong type) and the success path, not this branch.
// The correct handle type is whatever name_to_handle_at stamps, so we mint a
// real header first then zero its handle_bytes field.

fn smoke_abi_fsx2_open_by_handle_at_einval_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&56u32.to_ne_bytes());
        let nargs = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        if call(Syscall::NameToHandleAt.raw(), nargs) != Some(0) {
            return Err("name_to_handle_at setup failed");
        }
        // Keep the (correct) handle_type at bytes 4..8, zero handle_bytes.
        hbuf[0..4].copy_from_slice(&0u32.to_ne_bytes());
        let oargs = a2(0, hbuf.as_ptr() as u64, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("open_by_handle_at with zero handle_bytes must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_by_handle_at_einval_neg);

// ── open_by_handle_at: EFAULT on an unreadable handle pointer ─────────
//
// arg1 unmapped → the 8-byte header copy_from_user fails → -EFAULT.

fn smoke_abi_fsx2_open_by_handle_at_efault_neg() -> TestResult {
    with_setup(|| {
        let oargs = a2(0, 0x0001_0000_0000_0000, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("open_by_handle_at with an unreadable handle pointer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_by_handle_at_efault_neg);

// ── mount: bind-mount success path ────────────────────────────────────
//
// fstype=="bind" routes to registry().bind_mount(source, target). Bind a
// freshly-mounted tmpfs onto a second path. The first file only covers the
// tmpfs and block-device branches.

fn smoke_abi_fsx2_mount_bind_pos() -> TestResult {
    with_setup(|| {
        // Seed a real source mount so bind_mount has something to clone.
        // Linux mount(2) ABI: (source, target, fstype, flags, data), NUL-term.
        let src_source = b"none\0";
        let src_target = b"/abi-bind-src\0";
        let tmpfs = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: src_source.as_ptr() as u64,
            arg1: src_target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("source tmpfs setup mount failed");
        }
        // Now bind /abi-bind-src → /abi-bind-dst.
        let target = b"/abi-bind-dst\0";
        let fstype = b"bind\0";
        let args = SyscallArgs {
            arg0: src_target.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("bind mount of an existing source onto a fresh target should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_pos);

// ── mount: -1 sentinel on an unreadable target pointer ────────────────
//
// copy_user_str(arg2=bad, ...) fails → the handler's `fail` (-1) sentinel.
// The first file's negative pins an unknown-device path, not the EFAULT-ish
// copy-failure branch.

fn smoke_abi_fsx2_mount_badtarget_neg() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let fstype = b"tmpfs\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: 0x0001_0000_0000_0000, // unreadable target (Linux ABI arg1)
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        // LINUX-GAP: Linux returns -EFAULT for a bad target pointer; NARF
        // collapses every mount copy-failure into the bare -1 sentinel.
        match call(Syscall::Mount.raw(), args) {
            Some(-1) => Ok(()),
            _ => Err("mount with an unreadable target must return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_badtarget_neg);

// ── fsconfig: ENODEV on an un-buildable fsname ────────────────────────
//
// fsopen accepts any non-empty fsname; fsconfig(CMD_CREATE) then calls
// build_fs, which returns None for an unknown fs → ENODEV. The first file
// only pins the tmpfs CMD_CREATE success and the EBADF (unknown fd) case.

fn smoke_abi_fsx2_fsconfig_enodev_neg() -> TestResult {
    with_setup(|| {
        let fsname = b"nosuchfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen of an arbitrary fsname should still open a context"),
        };
        let args = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), args) {
            Some(v) if v == ENODEV => Ok(()),
            _ => Err("fsconfig(CMD_CREATE) on an un-buildable fsname must return -ENODEV"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fsconfig_enodev_neg);

// ── fsconfig: FSCONFIG_SET_STRING is accepted (no-op success) ─────────
//
// The SET_STRING arm validates the key/value strings are readable and
// returns 0. Distinct command arm from the first file's CMD_CREATE.

fn smoke_abi_fsx2_fsconfig_set_string_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let key = b"size\0";
        let val = b"64m\0";
        let args = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_SET_STRING,
            arg2: key.as_ptr() as u64,
            arg3: val.as_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("fsconfig(SET_STRING) should accept a readable key/value and return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fsconfig_set_string_pos);

// ── move_mount: EINVAL on a relative target (valid from_dfd) ──────────
//
// Build a real detached-mount fd, then pass a relative to_path. mount_of
// succeeds, but the to_path branch rejects a non-'/' target → EINVAL. The
// first file's negative pins EBADF (unknown from_dfd) — a different branch.

fn smoke_abi_fsx2_move_mount_relpath_neg() -> TestResult {
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
        let to = b"relative-target\0"; // not absolute → EINVAL
        let args = SyscallArgs {
            arg0: mfd,
            arg1: 0,
            arg2: 0,
            arg3: to.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::MoveMount.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("move_mount with a relative to_path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_move_mount_relpath_neg);

// ── open_tree: ENOENT on an absolute path with no covering mount ──────
//
// path is absolute (passes the EINVAL guard). open_tree resolves it via
// `fs_arc_at`, which special-cases a "/" root mount as a fallback matching
// EVERY absolute path. Whether a root mount is present when this test runs
// depends on boot-initcall ordering (the initramfs / auto-root disk mount at
// "/" may or may not have landed yet) — the same flakiness documented on
// `smoke_filesystem_resolve_absolute`. So accept either outcome: ENOENT when
// nothing covers the path, or a valid fd when a root mount does cover it.

fn smoke_abi_fsx2_open_tree_enoent_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi-no-mount-here\0";
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("open_tree: expected -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_tree_enoent_neg);

// ── fspick: EINVAL on a relative path ─────────────────────────────────
//
// The first file's fspick negative is lenient (accepts anything); pin the
// concrete EINVAL relative-path guard branch here.

fn smoke_abi_fsx2_fspick_relpath_neg() -> TestResult {
    with_setup(|| {
        let path = b"relative\0";
        match call(Syscall::Fspick.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fspick with a relative path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fspick_relpath_neg);

// ── mount_setattr: EINVAL on the size>64 upper bound ──────────────────
//
// The first file pins size==0 (lower bound) → EINVAL and size==32 success.
// Pin the size>64 upper-bound EINVAL branch.

fn smoke_abi_fsx2_mount_setattr_oversize_neg() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: 0,
            arg4: 65, // > 64 → EINVAL
            ..Default::default()
        };
        match call(Syscall::MountSetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("mount_setattr with size>64 must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_setattr_oversize_neg);

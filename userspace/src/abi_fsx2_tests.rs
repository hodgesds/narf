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

// ── name_to_handle_at: 8-byte inode handle when capacity is exactly 8 ──
//
// A caller advertising an exactly-8-byte f_handle (e.g. systemd's
// cg_path_get_cgroupid) gets the object's inode in a single u64, as Linux
// returns, rather than the path-carrying handle form.

fn smoke_abi_fsx2_name_to_handle_at_inode_form() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        let cap: u32 = 8;
        hbuf[0..4].copy_from_slice(&cap.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(0) => {
                // handle_bytes must read back as exactly 8, and the 8-byte
                // f_handle (the inode) must be nonzero.
                let hb = u32::from_ne_bytes(hbuf[0..4].try_into().unwrap());
                let ino = u64::from_ne_bytes(hbuf[8..16].try_into().unwrap());
                if hb != 8 {
                    Err("cap==8 handle_bytes not 8")
                } else if ino == 0 {
                    Err("cap==8 inode handle is zero")
                } else {
                    Ok(())
                }
            }
            _ => Err("name_to_handle_at cap==8 did not succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_inode_form);

// ── open(O_WRONLY) then fcntl(F_GETFL) reports the access mode ─────────
//
// glibc's fdopen(fd, "w") reads the fd's access mode via F_GETFL and
// rejects the stream with EINVAL unless it matches the requested mode.
// systemd fdopens a cgroup.procs it opened O_WRONLY, so the fd must
// report O_WRONLY (not just the settable status-flag bits).
fn smoke_abi_fsx2_open_wronly_fgetfl_access_mode() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        const O_WRONLY: u64 = 1;
        const F_GETFL: u64 = 3;
        const O_ACCMODE: u64 = 3;
        let path = b"/abi/f\0";
        let fd = match call_open(path.as_ptr() as u64, O_WRONLY) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("open O_WRONLY of a seeded MemFs file failed"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFL, 0)) {
            Some(fl) if (fl as u64 & O_ACCMODE) == O_WRONLY => Ok(()),
            _ => Err("F_GETFL did not report the O_WRONLY access mode"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_wronly_fgetfl_access_mode);

// ── memfd_create returns an O_RDWR fd (F_GETFL access mode) ────────────
//
// Linux memfd_create(2) always hands back a read+write fd. glibc/musl
// fdopen(fd, "w+") reads F_GETFL and rejects the stream with EINVAL
// unless the access mode is O_RDWR. systemd 257 serializes sd-executor
// state to a memfd it then fdopens "w+", so the fd must report O_RDWR.
fn smoke_abi_fsx2_memfd_create_fgetfl_rdwr() -> TestResult {
    with_setup(|| {
        const F_GETFL: u64 = 3;
        const O_ACCMODE: u64 = 3;
        const O_RDWR: u64 = 2;
        let name = b"abi-memfd\0";
        let fd = match call(Syscall::MemfdCreate.raw(), a1(name.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("memfd_create failed"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFL, 0)) {
            Some(fl) if (fl as u64 & O_ACCMODE) == O_RDWR => Ok(()),
            _ => Err("memfd_create fd did not report the O_RDWR access mode"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_memfd_create_fgetfl_rdwr);

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

fn smoke_abi_fsx2_mount_bind_subdir_pos() -> TestResult {
    with_setup(|| {
        let src_source = b"none\0";
        let src_target = b"/abi-bind-tree\0";
        let tmpfs = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: src_source.as_ptr() as u64,
            arg1: src_target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("subdirectory bind source mount failed");
        }
        let subdir = b"/abi-bind-tree/subdir\0";
        let mkdir = a2(subdir.as_ptr() as u64, 0o755, 0);
        if call(Syscall::Mkdir.raw(), mkdir) != Some(0) {
            return Err("subdirectory bind source mkdir failed");
        }
        let target = b"/abi-bind-subdir-dst\0";
        const MS_BIND: u64 = 1 << 12;
        let bind = SyscallArgs {
            arg0: subdir.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), bind) {
            Some(0) => Ok(()),
            _ => Err("bind mount of an ordinary subdirectory must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_subdir_pos);

fn smoke_abi_fsx2_mount_bind_file_to_self_pos() -> TestResult {
    with_memfs(
        "/abi-self-bind",
        "self-bind",
        &[("control", b"value")],
        || {
            let path = b"/abi-self-bind/control\0";
            const MS_BIND: u64 = 1 << 12;
            let bind = SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND,
                ..Default::default()
            };
            match call(Syscall::Mount.raw(), bind) {
                Some(0) => Ok(()),
                _ => Err("bind-mounting a live file onto itself should succeed"),
            }
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_file_to_self_pos);

fn smoke_abi_fsx2_mount_bind_proc_file_alias_pos() -> TestResult {
    with_setup(|| {
        // systemd constructs service namespaces under a staging procfs mount,
        // then protects individual controls by binding them onto the matching
        // file in the visible /proc mount.
        narf_filesystem::procfs::sys_kernel::register_all();
        let source = b"proc\0";
        let staging = b"/abi-proc-staging\0";
        let procfs = b"proc\0";
        let mount = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: staging.as_ptr() as u64,
            arg2: procfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), mount) != Some(0) {
            return Err("staging procfs mount failed");
        }

        let staged_file = b"/abi-proc-staging/sys/kernel/domainname\0";
        let visible_file = b"/proc/sys/kernel/domainname\0";
        const MS_BIND: u64 = 1 << 12;
        let bind = SyscallArgs {
            arg0: staged_file.as_ptr() as u64,
            arg1: visible_file.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), bind) {
            Some(0) => Ok(()),
            _ => Err("same procfs file through two mountpoints must bind successfully"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_proc_file_alias_pos);

fn smoke_abi_fsx2_mount_bind_remount_private_file_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MS_RDONLY: u64 = 1;
        const MS_REMOUNT: u64 = 1 << 5;
        const MS_BIND: u64 = 1 << 12;

        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            narf_filesystem::procfs::sys_kernel::register_all();
            let source = b"proc\0";
            let staging = b"/abi-private-proc\0";
            let procfs = b"proc\0";
            let mount = SyscallArgs {
                arg0: source.as_ptr() as u64,
                arg1: staging.as_ptr() as u64,
                arg2: procfs.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), mount) != Some(0) {
                return Err("private staging procfs mount failed");
            }

            let file = b"/abi-private-proc/sys/kernel/domainname\0";
            let open = a3((-100i64) as u64, file.as_ptr() as u64, 0, 0);
            let fd = match call(Syscall::Openat.raw(), open) {
                Some(fd) if (0..=u32::MAX as i64).contains(&fd) => fd as u32,
                _ => return Err("open must resolve files in the current mount namespace"),
            };
            let _ = call(Syscall::Close.raw(), a0(fd as u64));

            let remount = SyscallArgs {
                arg0: 0,
                arg1: file.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REMOUNT | MS_RDONLY,
                ..Default::default()
            };
            match call(Syscall::Mount.raw(), remount) {
                Some(0) => Ok(()),
                _ => Err("bind remount must validate files in the current mount namespace"),
            }
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mount_bind_remount_private_file_pos
);

fn smoke_abi_fsx2_mount_namespace_stack_pos() -> TestResult {
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let auth = narf_filesystem::bootstrap_mount_authority();
        let first: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("stack-first"));
        let second: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("stack-second"));
        if ns.mount_arc(&auth, "/abi-private-stack", first).is_err() {
            return Err("first private namespace mount failed");
        }
        let first_id = match ns.mount_id_at("/abi-private-stack") {
            Some(id) if id != 0 => id,
            _ => return Err("first private mount must expose a nonzero mount id"),
        };
        if ns.mount_arc(&auth, "/abi-private-stack", second).is_err() {
            return Err("private mount namespace must permit stacking at one target");
        }
        match ns.mount_id_at("/abi-private-stack") {
            Some(id) if id != first_id => {}
            _ => return Err("stacking a mount must change the visible mount id"),
        }
        match ns.list_mountinfo().last() {
            Some((_, parent, path, _)) if *parent == first_id && path == "/abi-private-stack" => {}
            _ => return Err("a stacked mount must name the covered mount as its parent"),
        }
        match ns.resolve_absolute("/abi-private-stack", |fs, _| fs.name() == "stack-second") {
            Some(true) => Ok(()),
            _ => Err("private namespace path resolution must select the topmost mount"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_namespace_stack_pos);

fn smoke_abi_fsx2_mount_namespace_move_pos() -> TestResult {
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let auth = narf_filesystem::bootstrap_mount_authority();
        let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("move-source"));
        if ns.mount_arc(&auth, "/abi-move-source", fs).is_err() {
            return Err("private namespace move setup failed");
        }
        if ns
            .move_mount("/abi-move-source", "/abi-move-target")
            .is_err()
        {
            return Err("moving a private namespace mount should succeed");
        }
        if ns.resolve_absolute("/abi-move-source", |fs, _| fs.name() == "move-source") == Some(true)
        {
            return Err("moved mount must no longer resolve at its source");
        }
        match ns.resolve_absolute("/abi-move-target", |fs, _| fs.name() == "move-source") {
            Some(true) => Ok(()),
            _ => Err("moved mount must resolve at its target"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_namespace_move_pos);

fn smoke_abi_fsx2_mount_bind_remount_null_source_pos() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let target = b"/abi-bind-remount\0";
        let tmpfs = b"tmpfs\0";
        let setup = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), setup) != Some(0) {
            return Err("bind-remount target setup failed");
        }
        const MS_RDONLY: u64 = 1;
        const MS_REMOUNT: u64 = 1 << 5;
        const MS_BIND: u64 = 1 << 12;
        let remount = SyscallArgs {
            arg0: 0,
            arg1: target.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND | MS_REMOUNT | MS_RDONLY,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), remount) {
            Some(0) => Ok(()),
            _ => Err("MS_BIND|MS_REMOUNT with NULL source must update the existing mount"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mount_bind_remount_null_source_pos
);

// ── mount: -EFAULT on an unreadable target pointer ────────────────────
//
// copy_user_cstr(arg1=bad, ...) fails → the handler's copy-failure branch,
// which returns -EFAULT. The first file's negative pins an unknown-fstype
// path (-ENODEV), a different failure branch.

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
        // A bad target pointer fails copy-in → -EFAULT (matching Linux).
        match call(Syscall::Mount.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("mount with an unreadable target must return -EFAULT"),
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

fn smoke_abi_fsx2_move_mount_private_namespace_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let fsname = b"tmpfs\0";
            let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
                Some(v) if v >= 0 => v as u64,
                _ => return Err("fsopen setup failed"),
            };
            let create = SyscallArgs {
                arg0: fd,
                arg1: FSCONFIG_CMD_CREATE,
                ..Default::default()
            };
            if call(Syscall::Fsconfig.raw(), create) != Some(0) {
                return Err("fsconfig setup failed");
            }
            let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
                Some(v) if v >= 0 => v as u64,
                _ => return Err("fsmount setup failed"),
            };
            let target = b"/proc\0";
            let attach = SyscallArgs {
                arg0: mfd,
                arg1: 0,
                arg2: (-100i64) as u64,
                arg3: target.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::MoveMount.raw(), attach) != Some(0) {
                return Err("move_mount must attach into the private namespace");
            }
            let resolved_target = crate::handlers::apply_chroot_for_test("/proc");
            let attached = crate::handlers::current_mount_namespace()
                .and_then(|ns| {
                    ns.resolve_absolute(&resolved_target, |fs, rel| {
                        rel.is_empty() && fs.name() == "tmpfs"
                    })
                })
                .unwrap_or(false);
            if !attached {
                return Err("detached mount was not visible in the current namespace");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_move_mount_private_namespace_pos
);

fn smoke_abi_fsx2_open_tree_preserves_descendant_mounts_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const OPEN_TREE_CLONE: u64 = 1;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let root: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("tree-root"));
            let child: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("tree-child"));
            if ns.mount_arc(&auth, "/abi-tree-source", root).is_err()
                || ns
                    .mount_arc(&auth, "/abi-tree-source/run/incoming", child)
                    .is_err()
            {
                return Err("detached-tree mount setup failed");
            }

            let source = b"/abi-tree-source\0";
            let mfd = match call(
                Syscall::OpenTree.raw(),
                a2((-100i64) as u64, source.as_ptr() as u64, OPEN_TREE_CLONE),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open_tree(CLONE) failed"),
            };
            let target = b"/abi-tree-target\0";
            let attach = SyscallArgs {
                arg0: mfd,
                arg1: 0,
                arg2: (-100i64) as u64,
                arg3: target.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::MoveMount.raw(), attach) != Some(0) {
                return Err("move_mount of cloned tree failed");
            }
            match ns.resolve_absolute("/abi-tree-target/run/incoming", |fs, rel| {
                rel.is_empty() && fs.name() == "tree-child"
            }) {
                Some(true) => Ok(()),
                _ => Err("move_mount must rebase descendant mounts with the detached root"),
            }
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_open_tree_preserves_descendant_mounts_pos
);

fn smoke_abi_fsx2_recursive_bind_preserves_descendant_mounts_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MS_BIND: u64 = 1 << 12;
        const MS_REC: u64 = 1 << 14;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let root: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("rbind-root"));
            let child: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("rbind-child"));
            if ns.mount_arc(&auth, "/abi-rbind-source", root).is_err()
                || ns
                    .mount_arc(&auth, "/abi-rbind-source/sys/fs/cgroup", child)
                    .is_err()
            {
                return Err("recursive-bind mount setup failed");
            }
            let source = b"/abi-rbind-source\0";
            let target = b"/abi-rbind-target\0";
            let bind = SyscallArgs {
                arg0: source.as_ptr() as u64,
                arg1: target.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REC,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), bind) != Some(0) {
                return Err("recursive bind mount failed");
            }
            match ns.resolve_absolute("/abi-rbind-target/sys/fs/cgroup", |fs, rel| {
                rel.is_empty() && fs.name() == "rbind-child"
            }) {
                Some(true) => {}
                _ => return Err("recursive bind must rebase descendant mounts"),
            }
            let before_self_bind = ns.list().len();
            let self_source = b"/abi-rbind-target/\0";
            let self_bind = SyscallArgs {
                arg0: self_source.as_ptr() as u64,
                arg1: target.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REC,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), self_bind) != Some(0) {
                return Err("recursive self-bind failed");
            }
            if ns.list().len() != before_self_bind + 1 {
                return Err("recursive self-bind must not duplicate existing descendants");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_recursive_bind_preserves_descendant_mounts_pos
);

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

// ── mount: fstype breadth for systemd's early-boot pseudo-filesystems ──
//
// systemd mounts many pseudo-filesystems (proc, sysfs, tmpfs, securityfs,
// debugfs, cgroup2, mqueue, …). The shared dispatch (mount_api::build_fs)
// backs the ones NARF can with a real FsInstance and the rest with an empty
// in-memory directory; either way the mount succeeds and the mountpoint is
// statable as a directory. Linux mount(2) ABI: (source, target, fstype,
// flags, data), all NUL-terminated.

fn mount_fstype(target: &[u8], fstype: &[u8]) -> Option<i64> {
    let source = b"none\0";
    let args = SyscallArgs {
        arg0: source.as_ptr() as u64,
        arg1: target.as_ptr() as u64,
        arg2: fstype.as_ptr() as u64,
        arg3: 0, // flags
        arg4: 0, // data
        ..Default::default()
    };
    call(Syscall::Mount.raw(), args)
}

fn smoke_abi_fsx2_mount_tmpfs_statable_pos() -> TestResult {
    with_setup(|| {
        let target = b"/abi-tmpfs-stat\0";
        let fstype = b"tmpfs\0";
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount of tmpfs at a fresh target should return 0");
        }
        // The mountpoint must now be statable as a directory.
        let mut sb = [0u8; 256];
        match call_stat(target.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("a mounted tmpfs root must be statable"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_tmpfs_statable_pos);

fn smoke_abi_fsx2_mount_securityfs_pseudo_pos() -> TestResult {
    with_setup(|| {
        // securityfs has no NARF semantics; it mounts an empty directory so
        // systemd's sys-kernel-security.mount unit succeeds.
        let target = b"/abi-securityfs\0";
        let fstype = b"securityfs\0";
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount of securityfs (empty-dir pseudo) should return 0");
        }
        let mut sb = [0u8; 256];
        match call_stat(target.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("a mounted securityfs root must be statable"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_securityfs_pseudo_pos);

// ── mount: propagation-only change is an accepted no-op ────────────────
//
// systemd marks the mount tree private/slave with
// mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL). NARF's flat mount model
// has no propagation state, so this succeeds without touching the registry.

fn smoke_abi_fsx2_mount_propagation_noop_pos() -> TestResult {
    with_setup(|| {
        const MS_PRIVATE: u64 = 1 << 18;
        const MS_REC: u64 = 1 << 14;
        let source = b"none\0";
        let target = b"/\0";
        // NULL fstype (arg2=0) + propagation flags only.
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: 0, // NULL fstype
            arg3: MS_PRIVATE | MS_REC,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("a propagation-only mount (MS_PRIVATE|MS_REC) must be a no-op success"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_propagation_noop_pos);

// ── mount: a genuinely-unknown fstype is -ENODEV, never the -1 sentinel ─

fn smoke_abi_fsx2_mount_garbage_fstype_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-garbage\0";
        let fstype = b"notarealfs\0";
        match mount_fstype(target, fstype) {
            Some(v) if v == ENODEV => Ok(()),
            _ => Err("mount of a garbage fstype must return -ENODEV"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_garbage_fstype_neg);

// ── new-mount-API: full fsopen→fsconfig(CREATE)→fsmount→move_mount chain ─
//
// The decomposed mount path must register a mount equivalent to the classic
// path. Drive the whole chain and assert the destination appears in
// registry().list().

fn smoke_abi_fsx2_new_mount_api_chain_registers_pos() -> TestResult {
    with_setup(|| {
        let dest = "/abi-newapi-chain";
        // fsopen("tmpfs").
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen(tmpfs) should return a context fd"),
        };
        // fsconfig(fd, CMD_CREATE) — materialize the backend.
        let cargs = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), cargs) != Some(0) {
            return Err("fsconfig(CMD_CREATE) should return 0");
        }
        // fsmount(fd, 0, 0) — detached mount fd.
        let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsmount on a created context should return a mount fd"),
        };
        // move_mount(mfd, "", AT_FDCWD, dest, 0).
        let empty = b"\0";
        let mut dest_c = [0u8; 32];
        dest_c[..dest.len()].copy_from_slice(dest.as_bytes());
        let mvargs = SyscallArgs {
            arg0: mfd,
            arg1: empty.as_ptr() as u64,
            arg2: 0xffffffffffffff9c, // AT_FDCWD
            arg3: dest_c.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::MoveMount.raw(), mvargs) != Some(0) {
            return Err("move_mount of the detached mount should return 0");
        }
        // The destination must now appear in the mount registry.
        let mounted = narf_filesystem::registry()
            .list()
            .iter()
            .any(|p| p.as_str() == dest);
        if mounted {
            Ok(())
        } else {
            Err("the new-mount-API chain must register the mount in registry().list()")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_new_mount_api_chain_registers_pos
);

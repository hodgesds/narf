//! Linux syscall ABI conformance — fsx group.
//!
//! Covers the extended-attribute family (set/get/list/remove in the
//! path/lpath/fd variants) and the mount / new-mount-API surface
//! (mount, umount2, pivot_root, name_to_handle_at, open_by_handle_at,
//! fsopen/fsconfig/fsmount/move_mount/open_tree/open_tree_attr/fspick/
//! mount_setattr).
//!
//! Shares the harness in [`crate::abi_test_support`]; every test drives
//! `kernel_syscall_entry` through a synthetic `AbiCtx`. The path-form xattr
//! handlers need a real inode (a missing path is -ENOENT, as in Linux), so
//! those cases run against a seeded MemFs. The fd-keyed `f*xattr` family keys on an `anon_inode:[Type]`
//! placeholder derived from the fd's `FileOps` type, so an open MemFs fd is
//! enough to reach the success path.

use crate::abi_test_support::*;

// ENODATA is the wire value the xattr handlers use for "no such attribute";
// it isn't in the shared harness errno set, so define it locally.

// EBUSY isn't in the shared harness errno set either; pivot_root's
// "loop, on the same file system" arm needs it.

// E2BIG isn't in the shared harness errno set; `setxattr`'s
// XATTR_SIZE_MAX rejection needs it. (ERANGE and EOPNOTSUPP are.)

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
// NUL-terminated path pointer (no length). The path must name a real
// inode: like Linux's `filename_lookup`, a missing one is -ENOENT.

fn smoke_abi_fsx_setxattr_pos() -> TestResult {
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("x", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("x", b"hi")], || {
        // An empty name is -ERANGE, not -EINVAL.
        // `fs/xattr.c::import_xattr_name`:
        //
        //     error = strncpy_from_user(kname->name, name, sizeof(kname->name));
        //     if (error == 0 || error == sizeof(kname->name))
        //             return -ERANGE;
        //
        // `strncpy_from_user` returns the copied length, so an empty string
        // returns 0 and takes the ERANGE arm. NARF reported EINVAL, which
        // sends a caller looking at its flags instead of its name buffer.
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
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("setxattr with an empty name must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_setxattr_neg);

/// The VFS-level `setxattr` rejections, in `setxattr_copy`'s order.
///
/// All four were missing, so a caller got either success or the wrong
/// errno: an unknown namespace was silently stored in NARF's side table
/// and read back, which is worse than any errno — `getfattr` then reports
/// an attribute the kernel never accepted.
fn smoke_abi_fsx_setxattr_vfs_rejections() -> TestResult {
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("x", b"hi")], || {
        let path = b"/abi/x\0";
        let val = b"v";
        let set = |name: &[u8], size: u64, flags: u64| {
            call(
                Syscall::Setxattr.raw(),
                SyscallArgs {
                    arg0: path.as_ptr() as u64,
                    arg1: name.as_ptr() as u64,
                    arg2: val.as_ptr() as u64,
                    arg3: size,
                    arg4: flags,
                    ..Default::default()
                },
            )
        };
        // `if (ctx->flags & ~(XATTR_CREATE|XATTR_REPLACE)) return -EINVAL;`
        if set(b"user.k\0", 1, 4) != Some(EINVAL) {
            return Err("an unknown setxattr flag must return -EINVAL");
        }
        // A name that fills the 256-byte `struct xattr_name` buffer: ERANGE.
        let mut long = [b'a'; 300];
        long[..5].copy_from_slice(b"user.");
        long[299] = 0;
        if set(&long, 1, 0) != Some(ERANGE) {
            return Err("an over-long xattr name must return -ERANGE");
        }
        // `if (ctx->size > XATTR_SIZE_MAX) return -E2BIG;` — checked
        // before the value is copied, so the bogus length is enough.
        if set(b"user.k\0", 65537, 0) != Some(E2BIG) {
            return Err("a value over XATTR_SIZE_MAX must return -E2BIG");
        }
        // `xattr_resolve_name` finds no handler for an unknown prefix.
        if set(b"nosuch.k\0", 1, 0) != Some(EOPNOTSUPP) {
            return Err("an unknown xattr namespace must return -EOPNOTSUPP");
        }
        // `system.*` resolves only for the two POSIX ACL names.
        if set(b"system.bogus\0", 1, 0) != Some(EOPNOTSUPP) {
            return Err("a non-ACL system.* name must return -EOPNOTSUPP");
        }
        // The read side of an unresolvable name is ENODATA, never a
        // success that would let a caller probe the namespace.
        let unknown = b"nosuch.k\0";
        let get = call(
            Syscall::Getxattr.raw(),
            SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: unknown.as_ptr() as u64,
                arg2: 0,
                arg3: 0,
                ..Default::default()
            },
        );
        if get != Some(EOPNOTSUPP) {
            return Err("getxattr of an unknown namespace must return -EOPNOTSUPP");
        }
        // The lookup runs BEFORE the handler is resolved: a missing path is
        // -ENOENT even for an unknown prefix, and nothing is stored.
        let missing = b"/abi/no-such-file\0";
        let missing_set = call(
            Syscall::Setxattr.raw(),
            SyscallArgs {
                arg0: missing.as_ptr() as u64,
                arg1: unknown.as_ptr() as u64,
                arg2: val.as_ptr() as u64,
                arg3: 1,
                ..Default::default()
            },
        );
        if missing_set != Some(ENOENT) {
            return Err("setxattr on a missing path must return -ENOENT");
        }
        let user = b"user.k\0";
        let missing_get = call(
            Syscall::Getxattr.raw(),
            SyscallArgs {
                arg0: missing.as_ptr() as u64,
                arg1: user.as_ptr() as u64,
                ..Default::default()
            },
        );
        if missing_get != Some(ENOENT) {
            return Err("getxattr on a missing path must return -ENOENT");
        }
        // ...and the name import runs BEFORE the lookup: `fgetxattr` on a
        // bad descriptor with an empty name is -ERANGE, not -EBADF.
        let empty = b"\0";
        let bad_fd_get = call(
            Syscall::Fgetxattr.raw(),
            SyscallArgs {
                arg0: 999,
                arg1: empty.as_ptr() as u64,
                ..Default::default()
            },
        );
        if bad_fd_get != Some(ERANGE) {
            return Err("fgetxattr(bad fd, \"\") must return -ERANGE before -EBADF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_setxattr_vfs_rejections);

/// Mount a private tmpfs for a test, at a target no other test uses.
///
/// These tests must NOT reach for `/tmp`. The `userspace/mount` smokes
/// unmount it as their cleanup and never put it back, so whether `/tmp`
/// exists depends on test ordering — which is exactly the kind of
/// dependency that makes a suite pass in one selection and fail in
/// another. A fresh mount also guarantees the filesystem under test IS
/// tmpfs, which is what these tests are about.
fn mount_private_tmpfs(target: &[u8]) -> bool {
    let source = b"tmpfs\0";
    let fstype = b"tmpfs\0";
    call(
        Syscall::Mount.raw(),
        SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        },
    ) == Some(0)
}

fn unmount_private_tmpfs(target: &[u8]) {
    let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
}

/// A DIRECTORY is an inode with extended attributes.
///
/// Path resolution hands back `DirOps` for a directory, so the xattr
/// handlers — which only ever asked for `FileOps` — could never reach one.
/// Every `setfattr` on a directory silently landed in the path-keyed side
/// table instead.
///
/// RENAMING the directory is what tells the two apart, and it is the
/// user-visible consequence: an attribute stored against the inode moves
/// with it, while one stored against a path string stays behind on a name
/// that no longer exists.
fn smoke_abi_fsx_directory_xattr_reaches_the_inode() -> TestResult {
    with_setup(|| {
        let mount = b"/abi-xattr-mnt\0";
        if !mount_private_tmpfs(mount) {
            return Err("mounting a private tmpfs for the test failed");
        }
        let first = b"/abi-xattr-mnt/dir\0";
        let second = b"/abi-xattr-mnt/dir2\0";
        let name = b"user.label\0";
        let val = b"dir";
        let finish = |outcome: Result<(), &'static str>| {
            unmount_private_tmpfs(mount);
            outcome
        };
        if call_mkdir(first.as_ptr() as u64, 0o755) != Some(0) {
            return finish(Err("mkdir of the test directory failed"));
        }
        let set = call(
            Syscall::Setxattr.raw(),
            SyscallArgs {
                arg0: first.as_ptr() as u64,
                arg1: name.as_ptr() as u64,
                arg2: val.as_ptr() as u64,
                arg3: val.len() as u64,
                arg4: 0,
                ..Default::default()
            },
        );
        if set != Some(0) {
            return finish(Err("setxattr on a directory should succeed"));
        }
        let getxattr = |path: &[u8], out: &mut [u8]| {
            call(
                Syscall::Getxattr.raw(),
                SyscallArgs {
                    arg0: path.as_ptr() as u64,
                    arg1: name.as_ptr() as u64,
                    arg2: out.as_mut_ptr() as u64,
                    arg3: out.len() as u64,
                    ..Default::default()
                },
            )
        };
        let mut out = [0u8; 8];
        if getxattr(first, &mut out) != Some(val.len() as i64) || &out[..val.len()] != val {
            return finish(Err("getxattr on a directory did not read back the value"));
        }
        // The attribute belongs to the INODE, so it follows the rename.
        if call_rename(first.as_ptr() as u64, second.as_ptr() as u64) != Some(0) {
            return finish(Err("renaming the test directory failed"));
        }
        let mut moved = [0u8; 8];
        let followed = getxattr(second, &mut moved);
        let left_behind = getxattr(first, &mut out);
        if followed != Some(val.len() as i64) || &moved[..val.len()] != val {
            return finish(Err(
                "the directory xattr did not follow its inode through a rename",
            ));
        }
        if left_behind != Some(ENODATA) {
            return finish(Err("the old directory name still answered for the xattr"));
        }
        finish(Ok(()))
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_directory_xattr_reaches_the_inode
);

/// A default ACL on a parent directory REPLACES the umask for everything
/// created inside it.
///
/// This is the whole reason `setfacl -d` exists: a shared group directory
/// sets one so that files land group-writable no matter what umask the
/// creating process happens to carry. `fs/posix_acl.c::posix_acl_create`
/// implements it by applying the umask only on the `!dir_default` path —
/// where a default ACL exists it narrows the mode through the ACL and
/// leaves the umask entirely alone.
///
/// The umask is a property of the task, so this can only be tested through
/// the syscalls: the filesystem layer never sees it. The 0o077 umask below
/// is the discriminator — without inheritance it would force 0o700 and
/// 0o600, which is exactly what NARF produced before.
fn smoke_abi_fsx_default_acl_replaces_umask() -> TestResult {
    use narf_filesystem::{AclEntry, AclType, PosixAcl};
    use narf_filesystem::{
        ACL_EXECUTE, ACL_GROUP_OBJ, ACL_OTHER, ACL_READ, ACL_USER_OBJ, ACL_WRITE,
    };
    with_setup(|| {
        let mount = b"/abi-acl-mnt\0";
        if !mount_private_tmpfs(mount) {
            return Err("mounting a private tmpfs for the test failed");
        }
        let parent = b"/abi-acl-mnt/parent\0";
        let child_dir = b"/abi-acl-mnt/parent/sub\0";
        let child_file = b"/abi-acl-mnt/parent/file\0";
        let finish = |outcome: Result<(), &'static str>| {
            unmount_private_tmpfs(mount);
            outcome
        };
        if call_mkdir(parent.as_ptr() as u64, 0o777) != Some(0) {
            return finish(Err("mkdir of the ACL parent failed"));
        }
        // u::rwx, g::rwx, o::r-x — group-writable by inheritance.
        let default = PosixAcl::from_entries(alloc::vec![
            AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE | ACL_EXECUTE),
            AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ | ACL_WRITE | ACL_EXECUTE),
            AclEntry::tagged(ACL_OTHER, ACL_READ | ACL_EXECUTE),
        ])
        .to_xattr();
        let mut name_c = alloc::vec::Vec::from(AclType::Default.xattr_name().as_bytes());
        name_c.push(0);
        let set = call(
            Syscall::Setxattr.raw(),
            SyscallArgs {
                arg0: parent.as_ptr() as u64,
                arg1: name_c.as_ptr() as u64,
                arg2: default.as_ptr() as u64,
                arg3: default.len() as u64,
                arg4: 0,
                ..Default::default()
            },
        );
        if set != Some(0) {
            return finish(Err("setxattr of a default ACL on a directory failed"));
        }
        // A umask that would visibly bite if it were still applied.
        let previous = call(Syscall::Umask.raw(), a0(0o077));
        let mode_of = |path: &[u8]| -> Option<u32> {
            let mut st = [0u8; 144];
            if call_stat(path.as_ptr() as u64, st.as_mut_ptr() as u64) != Some(0) {
                return None;
            }
            // `struct stat` x86_64: st_mode is a u32 at offset 24.
            Some(u32::from_ne_bytes([st[24], st[25], st[26], st[27]]) & 0o7777)
        };
        let dir_made = call_mkdir(child_dir.as_ptr() as u64, 0o777);
        let created = call(
            Syscall::Openat.raw(),
            a3(
                AT_FDCWD,
                child_file.as_ptr() as u64,
                // O_CREAT | O_RDWR
                0o100 | 0o2,
                0o666,
            ),
        );
        if let Some(fd) = created {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        let dir_mode = mode_of(child_dir);
        let file_mode = mode_of(child_file);
        if let Some(mask) = previous {
            let _ = call(Syscall::Umask.raw(), a0(mask as u64));
        }
        if dir_made != Some(0) {
            return finish(Err("mkdir inside the ACL parent failed"));
        }
        if created.map(|fd| fd < 0).unwrap_or(true) {
            return finish(Err("creating a file inside the ACL parent failed"));
        }
        // 0o777 narrowed through the default ACL is 0o775; the 0o077 umask
        // would have produced 0o700.
        if dir_mode != Some(0o775) {
            return finish(Err("a subdirectory did not inherit the default ACL's mode"));
        }
        // 0o666 narrowed through the same ACL is 0o664; umask would give 0o600.
        if file_mode != Some(0o664) {
            return finish(Err("a new file did not inherit the default ACL's mode"));
        }
        finish(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_default_acl_replaces_umask);

/// The sticky bit actually stops a delete.
///
/// `/tmp` is mode 01777: world-writable, so its permission bits alone let
/// anyone remove anything in it. `fs/namei.c::__check_sticky` is the entire
/// reason that is safe —
///
/// ```text
/// if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, inode), fsuid)) return 0;
/// if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, dir), fsuid)) return 0;
/// return !capable_wrt_inode_uidgid(idmap, inode, CAP_FOWNER);
/// ```
///
/// — and NARF checked nothing at all on unlink, so any task could delete
/// any other user's file anywhere. The refusal is EPERM, not EACCES:
/// `may_delete` returns `-EPERM` from the sticky arm and reserves EACCES
/// for the directory-permission arm above it.
fn smoke_abi_fsx_sticky_bit_protects_other_users_files() -> TestResult {
    with_memfs("/abi-sticky", "abi-sticky", &[], || {
        let dir = b"/abi-sticky/shared\0";
        let victim = b"/abi-sticky/shared/theirs\0";
        if call_mkdir(dir.as_ptr() as u64, 0o777) != Some(0) {
            return Err("mkdir of the shared directory failed");
        }
        // 01777, exactly as /tmp is.
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o1777)) != Some(0) {
            return Err("chmod 01777 of the shared directory failed");
        }
        // A file owned by uid 1000, created while still privileged.
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, victim.as_ptr() as u64, 0o100 | 0o2, 0o666),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return Err("creating the victim file failed"),
        }
        if call(Syscall::Chown.raw(), a2(victim.as_ptr() as u64, 1000, 1000)) != Some(0) {
            return Err("chown of the victim file failed");
        }
        // A DIFFERENT unprivileged user may not remove it, even though the
        // directory is world-writable. `setresuid` is what drops the
        // capabilities along with the uid (`cap_emulate_setxuid`); without
        // that, CAP_DAC_OVERRIDE would let the check pass and this test
        // would prove nothing.
        let task = crate::handlers::current_task_id();
        if call(Syscall::Setresuid.raw(), a2(2000, 2000, 2000)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("setresuid(2000) setup failed");
        }
        let stranger = call_unlink(victim.as_ptr() as u64);
        match stranger {
            Some(v) if v == EPERM => {}
            Some(0) => {
                crate::handlers::__test_uidgid_reset();
                return Err("a stranger deleted another user's file from a sticky directory");
            }
            Some(v) if v == EACCES => {
                crate::handlers::__test_uidgid_reset();
                return Err("sticky refusal reported EACCES; may_delete's sticky arm is EPERM");
            }
            _ => {
                crate::handlers::__test_uidgid_reset();
                return Err("unlink in a sticky directory by a stranger must return -EPERM");
            }
        }
        // The file's OWNER may remove it — the first arm of __check_sticky.
        // Without this the test would pass on a blanket "deny everyone".
        //
        // The identity move goes through the test hook rather than
        // `setresuid`: the task is already unprivileged, so it no longer
        // holds the CAP_SETUID that switching to a third uid would need.
        crate::handlers::__test_set_fsids(task, 1000, 1000);
        let owner = call_unlink(victim.as_ptr() as u64);
        crate::handlers::__test_uidgid_reset();
        if owner != Some(0) {
            return Err("the file's own owner was refused by the sticky check");
        }
        let _ = call_rmdir(dir.as_ptr() as u64);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_sticky_bit_protects_other_users_files
);

/// Changing a directory's contents requires write permission ON THAT
/// DIRECTORY.
///
/// `may_create` and `may_delete` both end at
/// `inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC)`, and NARF ran
/// neither: `unlink`, `rmdir`, `rename`, `link`, `symlink`, `mknod` and
/// `open(O_CREAT)` all went straight to the filesystem. A 0755 directory
/// owned by root was writable by everyone.
///
/// The errno is EACCES — the same one `open` uses for a mode denial.
fn smoke_abi_fsx_directory_write_permission_is_required() -> TestResult {
    with_memfs("/abi-dirperm", "abi-dirperm", &[], || {
        let dir = b"/abi-dirperm/ro\0";
        let existing = b"/abi-dirperm/ro/file\0";
        let fresh = b"/abi-dirperm/ro/new\0";
        let subdir = b"/abi-dirperm/ro/sub\0";
        let renamed = b"/abi-dirperm/ro/moved\0";
        if call_mkdir(dir.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir of the read-only directory failed");
        }
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, existing.as_ptr() as u64, 0o100 | 0o2, 0o666),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return Err("seeding a file in the directory failed"),
        }
        // Root-owned, 0755: other users have r-x and no write.
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o755)) != Some(0) {
            return Err("chmod 0755 of the directory failed");
        }
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("setresuid(1000) setup failed");
        }
        let created = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, fresh.as_ptr() as u64, 0o100 | 0o2, 0o666),
        );
        if let Some(fd) = created {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        let made_dir = call_mkdir(subdir.as_ptr() as u64, 0o755);
        let removed = call_unlink(existing.as_ptr() as u64);
        let moved = call_rename(existing.as_ptr() as u64, renamed.as_ptr() as u64);
        let linked = call(
            Syscall::Symlinkat.raw(),
            a2(existing.as_ptr() as u64, AT_FDCWD, fresh.as_ptr() as u64),
        );
        // Restore BEFORE asserting so a failure cannot strand the task.
        let _ = call(Syscall::Setresuid.raw(), a2(0, 0, 0));
        if created.map(|fd| fd >= 0).unwrap_or(false) {
            return Err("O_CREAT succeeded in a directory the caller cannot write");
        }
        if created != Some(EACCES) {
            return Err("O_CREAT in an unwritable directory must return -EACCES");
        }
        if made_dir != Some(EACCES) {
            return Err("mkdir in an unwritable directory must return -EACCES");
        }
        if removed != Some(EACCES) {
            return Err("unlink in an unwritable directory must return -EACCES");
        }
        if moved != Some(EACCES) {
            return Err("rename in an unwritable directory must return -EACCES");
        }
        if linked != Some(EACCES) {
            return Err("symlink in an unwritable directory must return -EACCES");
        }
        // Discriminator: the same operations must SUCCEED once the caller
        // can write the directory, or every assertion above is vacuous.
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o777)) != Some(0) {
            return Err("chmod 0777 of the directory failed");
        }
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("setresuid(1000) setup failed");
        }
        let now_created = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, fresh.as_ptr() as u64, 0o100 | 0o2, 0o666),
        );
        if let Some(fd) = now_created {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        let _ = call(Syscall::Setresuid.raw(), a2(0, 0, 0));
        if !now_created.map(|fd| fd >= 0).unwrap_or(false) {
            return Err("O_CREAT still failed on a world-writable directory — test is vacuous");
        }
        let _ = call_unlink(fresh.as_ptr() as u64);
        let _ = call_unlink(existing.as_ptr() as u64);
        let _ = call_rmdir(dir.as_ptr() as u64);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_directory_write_permission_is_required
);

/// A setgid directory hands its group to everything created inside it.
///
/// `fs/inode.c::inode_init_owner`:
///
/// ```text
/// inode_fsuid_set(inode, idmap);
/// if (dir && dir->i_mode & S_ISGID) {
///         inode->i_gid = dir->i_gid;
///         /* Directories are special, and always inherit S_ISGID */
///         if (S_ISDIR(mode))
///                 mode |= S_ISGID;
/// } else
///         inode_fsgid_set(inode, idmap);
/// ```
///
/// This is the whole mechanism behind a shared group directory: `chgrp
/// staff dir; chmod g+s dir` makes everything created inside belong to
/// `staff` whatever group the creator is in, and the S_ISGID copied onto a
/// new SUBDIRECTORY is what keeps that true all the way down. NARF stamped
/// the creator's fsgid unconditionally, so the group never propagated and
/// the bit never appeared on a child.
///
/// The caller cannot ask for S_ISGID on a directory itself:
/// `vfs_prepare_mode(.., S_IRWXUGO | S_ISVTX, 0)` masks it off, so a bit
/// that appears can only have been inherited.
fn smoke_abi_fsx_setgid_directory_propagates_its_group() -> TestResult {
    with_memfs("/abi-sgid", "abi-sgid", &[], || {
        const GROUP: u32 = 5150;
        let dir = b"/abi-sgid/shared\0";
        let child_dir = b"/abi-sgid/shared/sub\0";
        let child_file = b"/abi-sgid/shared/file\0";
        if call_mkdir(dir.as_ptr() as u64, 0o770) != Some(0) {
            return Err("mkdir of the shared directory failed");
        }
        if call(
            Syscall::Chown.raw(),
            a2(dir.as_ptr() as u64, 0, GROUP as u64),
        ) != Some(0)
        {
            return Err("chgrp of the shared directory failed");
        }
        // 02770: setgid + rwxrwx---.
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o2770)) != Some(0) {
            return Err("chmod g+s of the shared directory failed");
        }
        let stat_of = |path: &[u8]| -> Option<(u32, u32)> {
            let mut sb = [0u8; 144];
            if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
                return None;
            }
            // x86_64 `struct stat`: st_mode u32 @24, st_gid u32 @32.
            let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]) & 0o7777;
            let gid = u32::from_ne_bytes([sb[32], sb[33], sb[34], sb[35]]);
            Some((mode, gid))
        };
        // Guard against a vacuous pass: the staging must actually have set
        // the bit and the group on the parent.
        match stat_of(dir) {
            Some((mode, gid)) if mode & 0o2000 != 0 && gid == GROUP => {}
            _ => return Err("the shared directory is not setgid and group-owned — staging failed"),
        }
        // A file created inside takes the directory's group, not the
        // creator's (which is 0 here), and does NOT become setgid.
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, child_file.as_ptr() as u64, 0o100 | 0o2, 0o666),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return Err("creating a file in the shared directory failed"),
        }
        match stat_of(child_file) {
            Some((mode, gid)) => {
                if gid != GROUP {
                    return Err("a new file did not inherit the setgid directory's group");
                }
                if mode & 0o2000 != 0 {
                    return Err("a new regular file was made setgid; only directories inherit it");
                }
            }
            None => return Err("stat of the new file failed"),
        }
        // A subdirectory takes the group AND the bit, so inheritance keeps
        // going below it.
        if call_mkdir(child_dir.as_ptr() as u64, 0o770) != Some(0) {
            return Err("mkdir inside the shared directory failed");
        }
        match stat_of(child_dir) {
            Some((mode, gid)) => {
                if gid != GROUP {
                    return Err("a new subdirectory did not inherit the setgid group");
                }
                if mode & 0o2000 == 0 {
                    return Err("a new subdirectory did not inherit S_ISGID");
                }
            }
            None => return Err("stat of the new subdirectory failed"),
        }
        // Discriminator: without the bit on the parent, the creator's own
        // fsgid is what lands — otherwise this test would pass on a
        // blanket "always copy the parent's group".
        let plain = b"/abi-sgid/plain\0";
        let plain_file = b"/abi-sgid/plain/f\0";
        if call_mkdir(plain.as_ptr() as u64, 0o777) != Some(0) {
            return Err("mkdir of the plain directory failed");
        }
        if call(
            Syscall::Chown.raw(),
            a2(plain.as_ptr() as u64, 0, GROUP as u64),
        ) != Some(0)
        {
            return Err("chgrp of the plain directory failed");
        }
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, plain_file.as_ptr() as u64, 0o100 | 0o2, 0o666),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return Err("creating a file in the plain directory failed"),
        }
        match stat_of(plain_file) {
            Some((_, gid)) if gid == GROUP => {
                return Err("a non-setgid directory's group was inherited anyway")
            }
            Some(_) => {}
            None => return Err("stat of the plain file failed"),
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_setgid_directory_propagates_its_group
);

/// Changing an inode's ACL needs `inode_owner_or_capable`; changing an
/// ordinary xattr needs write permission on the inode.
///
/// `do_setxattr` splits the two: the POSIX ACL names go to
/// `do_set_acl` -> `vfs_set_acl` -> `set_posix_acl`, whose only check is
///
/// ```text
/// if (!inode_owner_or_capable(idmap, inode))
///         return -EPERM;
/// ```
///
/// while everything else goes through `vfs_setxattr` -> `xattr_permission`,
/// which ends at `inode_permission(idmap, inode, mask)` — EACCES. NARF ran
/// neither, so any task that could name an inode could rewrite its
/// `security.*` label, or rewrite its access ACL and with it (via
/// `posix_acl_update_mode`) its permission bits.
///
/// Conflating the two would get both errnos wrong, so both are pinned.
fn smoke_abi_fsx_xattr_and_acl_writes_are_permission_checked() -> TestResult {
    use narf_filesystem::{AclEntry, AclType, PosixAcl};
    use narf_filesystem::{
        ACL_EXECUTE, ACL_GROUP_OBJ, ACL_OTHER, ACL_READ, ACL_USER_OBJ, ACL_WRITE,
    };
    with_memfs("/abi-xperm", "abi-xperm", &[("victim", b"x")], || {
        let path = b"/abi-xperm/victim\0";
        let acl = PosixAcl::from_entries(alloc::vec![
            AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE | ACL_EXECUTE),
            AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ | ACL_WRITE | ACL_EXECUTE),
            AclEntry::tagged(ACL_OTHER, ACL_READ | ACL_EXECUTE),
        ])
        .to_xattr();
        let mut acl_name = alloc::vec::Vec::from(AclType::Access.xattr_name().as_bytes());
        acl_name.push(0);
        let setxattr = |name: &[u8], value: &[u8]| {
            call(
                Syscall::Setxattr.raw(),
                SyscallArgs {
                    arg0: path.as_ptr() as u64,
                    arg1: name.as_ptr() as u64,
                    arg2: value.as_ptr() as u64,
                    arg3: value.len() as u64,
                    arg4: 0,
                    ..Default::default()
                },
            )
        };
        // Both succeed while we are the owner — otherwise the denials
        // below would prove nothing.
        let plain_name = b"user.k\0";
        if setxattr(plain_name, b"v") != Some(0) {
            return Err("setxattr as the owner failed — staging is vacuous");
        }
        // The attribute must be on the INODE, not in the path-keyed side
        // table: the side table is not permission-checked, so a test whose
        // attribute lives there would report "allowed" no matter what the
        // gate decides. Renaming the file is what tells them apart.
        let moved = b"/abi-xperm/victim-moved\0";
        if call_rename(path.as_ptr() as u64, moved.as_ptr() as u64) != Some(0) {
            return Err("renaming the victim file failed");
        }
        let followed = call(
            Syscall::Getxattr.raw(),
            SyscallArgs {
                arg0: moved.as_ptr() as u64,
                arg1: plain_name.as_ptr() as u64,
                arg2: 0,
                arg3: 0,
                ..Default::default()
            },
        );
        if call_rename(moved.as_ptr() as u64, path.as_ptr() as u64) != Some(0) {
            return Err("renaming the victim file back failed");
        }
        if followed != Some(1) {
            return Err("the xattr did not reach the inode — the gate would be untested");
        }
        if setxattr(&acl_name, &acl) != Some(0) {
            return Err("setting an ACL as the owner failed — staging is vacuous");
        }
        // Only NOW fix the mode. Installing an access ACL rewrites the mode
        // through `posix_acl_update_mode`, so a chmod before this would be
        // undone — which is how the first version of this test ended up
        // staging a file the unprivileged caller could write.
        if call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o644)) != Some(0) {
            return Err("chmod 0644 setup failed");
        }
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("setresuid(1000) setup failed");
        }
        // Vacuity guard: the xattr gate ends at `inode_permission(inode,
        // MAY_WRITE)`, so if this caller can open the file for writing at
        // all, a permitted setxattr is the CORRECT answer and the test
        // would be asserting the wrong thing.
        let writable = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o1, 0),
        );
        if let Some(fd) = writable {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        let plain = setxattr(plain_name, b"w");
        let as_acl = setxattr(&acl_name, &acl);
        let removed = call(
            Syscall::Removexattr.raw(),
            a1(path.as_ptr() as u64, plain_name.as_ptr() as u64),
        );
        // Reading is still allowed: the file is 0644, and `vfs_get_acl`
        // performs no check at all.
        let read_back = call(
            Syscall::Getxattr.raw(),
            SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: plain_name.as_ptr() as u64,
                arg2: 0,
                arg3: 0,
                ..Default::default()
            },
        );
        // `security.*` skips `inode_permission` altogether; commoncap's
        // `cap_inode_setxattr` refuses it without CAP_SYS_ADMIN: EPERM.
        let security = setxattr(b"security.k\0", b"v");
        // The `setattr_prepare` gates for a non-owner (Linux 6.18 probe):
        // chmod EPERM; chown EPERM unless nothing changes; an explicit
        // timestamp EPERM; a plain `touch` without write permission EACCES.
        let chmod = call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o600));
        let chown_noop = call(
            Syscall::Chown.raw(),
            a2(path.as_ptr() as u64, u32::MAX as u64, u32::MAX as u64),
        );
        let chown = call(
            Syscall::Chown.raw(),
            a2(path.as_ptr() as u64, 1000, u32::MAX as u64),
        );
        let touch = call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        );
        let explicit: [i64; 4] = [5, 0, 5, 0];
        let stamp = call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, explicit.as_ptr() as u64, 0),
        );
        crate::handlers::__test_uidgid_reset();
        if security != Some(EPERM) {
            return Err("setxattr(security.*) without CAP_SYS_ADMIN must return -EPERM");
        }
        if chmod != Some(EPERM) {
            return Err("chmod by a non-owner must return -EPERM");
        }
        if chown_noop != Some(0) {
            return Err("chown(-1, -1) by a non-owner changes nothing and must succeed");
        }
        if chown != Some(EPERM) {
            return Err("chown by a non-owner must return -EPERM");
        }
        if touch != Some(EACCES) {
            return Err("utimensat(NULL) on an unwritable file must return -EACCES");
        }
        if stamp != Some(EPERM) {
            return Err("utimensat(explicit times) by a non-owner must return -EPERM");
        }
        if writable.map(|fd| fd >= 0).unwrap_or(false) {
            return Err("the unprivileged caller can write the file — the mode staging is vacuous");
        }
        match plain {
            Some(v) if v == EACCES => {}
            Some(0) => return Err("setxattr on an unwritable file SUCCEEDED"),
            Some(v) if v == EPERM => {
                return Err("setxattr denial returned EPERM; xattr_permission uses EACCES")
            }
            _ => return Err("setxattr on an unwritable file must return -EACCES"),
        }
        if removed != Some(EACCES) {
            return Err("removexattr on an unwritable file must return -EACCES");
        }
        // EPERM, not EACCES: the ACL path never reaches `inode_permission`.
        if as_acl != Some(EPERM) {
            return Err("setting an ACL as a non-owner must return -EPERM");
        }
        if read_back != Some(1) {
            return Err("getxattr of a readable file was refused");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_xattr_and_acl_writes_are_permission_checked
);

/// `mount -o ro` actually makes the mount read-only.
///
/// `path_mount` turns the caller's `MS_*` into the mount's `MNT_*` set,
/// and every syscall that changes something on a mount passes
/// `fs/namespace.c::mnt_want_write` first:
///
/// ```text
/// if (mnt->mnt_sb->s_readonly_remount || __mnt_is_readonly(mnt))
///         return -EROFS;
/// ```
///
/// NARF accepted the flags and dropped them — the handler's own comment
/// called that "the dangerous kind" of divergence, because a sandbox that
/// mounts `MS_RDONLY|MS_NOSUID|MS_NODEV` got a success reply and no
/// enforcement at all.
///
/// EROFS and not EACCES: read-only is a property of the MOUNT, not of the
/// caller, and userspace branches on the difference. It therefore holds
/// for root too, which is the entire point of a read-only bind.
fn smoke_abi_fsx_readonly_mount_refuses_writes() -> TestResult {
    with_setup(|| {
        const MS_RDONLY: u64 = 1 << 0;
        const MS_REMOUNT: u64 = 1 << 5;
        let target = b"/abi-ro\0";
        let source = b"tmpfs\0";
        let fstype = b"tmpfs\0";
        let mount_with = |flags: u64| {
            call(
                Syscall::Mount.raw(),
                SyscallArgs {
                    arg0: source.as_ptr() as u64,
                    arg1: target.as_ptr() as u64,
                    arg2: fstype.as_ptr() as u64,
                    arg3: flags,
                    arg4: 0,
                    ..Default::default()
                },
            )
        };
        // Writable first: everything below must SUCCEED here, or the
        // read-only assertions prove nothing.
        if mount_with(0) != Some(0) {
            return Err("mounting a writable tmpfs failed");
        }
        let file = b"/abi-ro/f\0";
        let dir = b"/abi-ro/d\0";
        let finish = |outcome: Result<(), &'static str>| {
            let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
            outcome
        };
        let create = || {
            call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, file.as_ptr() as u64, 0o100 | 0o2, 0o666),
            )
        };
        match create() {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return finish(Err("creating a file on a writable tmpfs failed")),
        }
        if call_mkdir(dir.as_ptr() as u64, 0o755) != Some(0) {
            return finish(Err("mkdir on a writable tmpfs failed"));
        }
        // Seal it with `mount -o remount,ro` — `do_reconfigure_mnt`.
        if mount_with(MS_REMOUNT | MS_RDONLY) != Some(0) {
            return finish(Err("remount,ro failed"));
        }
        // Every shape of write now reports EROFS, as root.
        let second = b"/abi-ro/f2\0";
        let second_dir = b"/abi-ro/d2\0";
        let created = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, second.as_ptr() as u64, 0o100 | 0o2, 0o666),
        );
        if created != Some(EROFS) {
            return finish(Err("O_CREAT on a read-only mount must return -EROFS"));
        }
        // Opening an EXISTING file for writing is refused too.
        let opened_w = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, file.as_ptr() as u64, 0o1, 0),
        );
        if opened_w != Some(EROFS) {
            return finish(Err(
                "opening a file for write on a read-only mount must be -EROFS",
            ));
        }
        if call_mkdir(second_dir.as_ptr() as u64, 0o755) != Some(EROFS) {
            return finish(Err("mkdir on a read-only mount must return -EROFS"));
        }
        if call_unlink(file.as_ptr() as u64) != Some(EROFS) {
            return finish(Err("unlink on a read-only mount must return -EROFS"));
        }
        if call_rmdir(dir.as_ptr() as u64) != Some(EROFS) {
            return finish(Err("rmdir on a read-only mount must return -EROFS"));
        }
        if call_rename(file.as_ptr() as u64, second.as_ptr() as u64) != Some(EROFS) {
            return finish(Err("rename on a read-only mount must return -EROFS"));
        }
        if call(Syscall::Chmod.raw(), a1(file.as_ptr() as u64, 0o600)) != Some(EROFS) {
            return finish(Err("chmod on a read-only mount must return -EROFS"));
        }
        if call(Syscall::Truncate.raw(), a1(file.as_ptr() as u64, 0)) != Some(EROFS) {
            return finish(Err("truncate on a read-only mount must return -EROFS"));
        }
        // Reading still works — read-only, not inaccessible.
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, file.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return finish(Err("a read-only mount refused a READ open")),
        }
        // And `remount,rw` lifts it again: `do_reconfigure_mnt` replaces the
        // flag set wholesale rather than accumulating it.
        if mount_with(MS_REMOUNT) != Some(0) {
            return finish(Err("remount,rw failed"));
        }
        match create() {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return finish(Err("remount,rw did not make the mount writable again")),
        }
        finish(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_readonly_mount_refuses_writes);

/// `noexec` and `nodev` are enforced, and `/proc/mounts` reports them.
///
/// `do_open_execat` opens the binary with `MAY_EXEC`, and `may_open`
/// refuses that on a `noexec` mount (`if (path_noexec(path)) return
/// -EACCES;`); the same function refuses to open a device node on a
/// `nodev` mount. Both are properties of the MOUNT, so a sandbox gets them
/// even against a privileged process inside it — which is why they are
/// worth having at all.
fn smoke_abi_fsx_noexec_nodev_are_enforced_and_reported() -> TestResult {
    with_setup(|| {
        const MS_NOSUID: u64 = 1 << 1;
        const MS_NODEV: u64 = 1 << 2;
        const MS_NOEXEC: u64 = 1 << 3;
        let target = b"/abi-noexec\0";
        let source = b"tmpfs\0";
        let fstype = b"tmpfs\0";
        if call(
            Syscall::Mount.raw(),
            SyscallArgs {
                arg0: source.as_ptr() as u64,
                arg1: target.as_ptr() as u64,
                arg2: fstype.as_ptr() as u64,
                arg3: MS_NOSUID | MS_NODEV | MS_NOEXEC,
                arg4: 0,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("mounting a nosuid,nodev,noexec tmpfs failed");
        }
        let finish = |outcome: Result<(), &'static str>| {
            let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
            outcome
        };
        // A device node on the mount cannot be opened.
        const S_IFCHR: u64 = 0o020000;
        let node = b"/abi-noexec/null\0";
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, node.as_ptr() as u64, S_IFCHR | 0o666, 0x0103),
        ) != Some(0)
        {
            return finish(Err("mknod of a device node on the test mount failed"));
        }
        let opened = call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, node.as_ptr() as u64, 0, 0),
        );
        if let Some(fd) = opened {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        if opened != Some(EACCES) {
            return finish(Err(
                "opening a device node on a nodev mount must return -EACCES",
            ));
        }
        // A regular file on the same mount still opens — `nodev` bars
        // device nodes, not everything.
        let plain = b"/abi-noexec/plain\0";
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, plain.as_ptr() as u64, 0o100 | 0o2, 0o755),
        ) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return finish(Err("a nodev mount refused an ordinary file")),
        }
        // Executing anything from the mount is refused before the image is
        // even read, so a non-ELF file is still -EACCES and not ENOEXEC.
        let execed = call(Syscall::Execve.raw(), a2(plain.as_ptr() as u64, 0, 0));
        if execed != Some(EACCES) {
            return finish(Err("execve from a noexec mount must return -EACCES"));
        }
        // And the flags are visible where userspace looks for them:
        // `show_vfsmnt` prints this attachment's MNT_* set as the fourth
        // column, which is what systemd compares against the options a
        // mount unit asked for.
        let mut buf = [0u8; 4096];
        let proc_mounts = b"/proc/mounts\0";
        let fd = match call_open(proc_mounts.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return finish(Err("opening /proc/mounts failed")),
        };
        let n = call(
            Syscall::Read.raw(),
            a2(fd, buf.as_mut_ptr() as u64, buf.len() as u64),
        );
        let _ = call(Syscall::Close.raw(), a0(fd));
        let n = match n {
            Some(n) if n >= 0 => n as usize,
            _ => return finish(Err("reading /proc/mounts failed")),
        };
        let text = match core::str::from_utf8(&buf[..n]) {
            Ok(text) => text,
            Err(_) => return finish(Err("/proc/mounts is not utf-8")),
        };
        match text
            .lines()
            .find(|line| line.split(' ').nth(1) == Some("/abi-noexec"))
        {
            Some(line) => {
                let opts = line.split(' ').nth(3).unwrap_or("");
                if !opts.starts_with("rw,nosuid,nodev,noexec") {
                    return finish(Err("/proc/mounts did not report the mount's flags"));
                }
            }
            None => return finish(Err("the test mount is missing from /proc/mounts")),
        }
        finish(Ok(()))
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_noexec_nodev_are_enforced_and_reported
);

/// `execve` of a set-user-ID binary raises privilege, and every guard on
/// that is real.
///
/// `fs/exec.c::bprm_fill_uid` is the one place an unprivileged task can
/// gain privilege, and NARF did not implement it at all — set-user-ID
/// binaries simply did not work, which is also why `MS_NOSUID` had nothing
/// to suppress.
///
/// This drives the decision directly rather than through a real `execve`:
/// a full exec needs a loadable image and a task switch that the ABI
/// harness cannot stage. The decision is the security-critical half.
///
/// Each guard is asserted separately because each one, missing, is a
/// privilege-escalation bug on its own.
fn smoke_abi_fsx_setuid_exec_transition_and_its_guards() -> TestResult {
    const OWNER: u32 = 4000;
    const GROUP: u32 = 4100;
    const CALLER: u32 = 1000;
    with_memfs("/abi-suid", "abi-suid", &[("prog", b"\x7fELF")], || {
        let path = "/abi-suid/prog";
        let cpath = b"/abi-suid/prog\0";
        let task = crate::handlers::current_task_id();
        let stage = |mode: u64| -> Result<(), &'static str> {
            // Staging is a privileged step: chown/chmod of a file the
            // caller does not own is EPERM (`setattr_prepare`), and the
            // previous case left the task as CALLER with the effective
            // capability set cleared by its exec.
            crate::handlers::__test_uidgid_reset();
            crate::handlers::__test_caps_reset();
            if call(
                Syscall::Chown.raw(),
                a2(cpath.as_ptr() as u64, OWNER as u64, GROUP as u64),
            ) != Some(0)
            {
                return Err("chown of the test binary failed");
            }
            if call(Syscall::Chmod.raw(), a1(cpath.as_ptr() as u64, mode)) != Some(0) {
                return Err("chmod of the test binary failed");
            }
            Ok(())
        };
        let as_caller = || {
            crate::handlers::__test_set_fsids(task, CALLER, CALLER);
        };

        // ── set-user-ID: euid becomes the file's owner ────────────────
        stage(0o4755)?;
        as_caller();
        let (euid, _, fsuid, _) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        if euid != OWNER {
            crate::handlers::__test_uidgid_reset();
            return Err("a set-user-ID binary did not move the effective uid");
        }
        // Every DAC decision reads fsuid, so leaving it behind would grant
        // the privilege for `access()` and deny it for `open()`.
        if fsuid != OWNER {
            crate::handlers::__test_uidgid_reset();
            return Err("the filesystem uid did not follow the effective uid");
        }

        // ── S_ISGID WITHOUT group-execute is not a privilege request ──
        // It is the mandatory file-locking marker; Linux requires
        // `(mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)`.
        stage(0o2745)?;
        as_caller();
        let (_, egid, _, _) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        if egid == GROUP {
            crate::handlers::__test_uidgid_reset();
            return Err("S_ISGID without group-execute granted the file's group");
        }

        // ── S_ISGID WITH group-execute does transition ───────────────
        stage(0o2755)?;
        as_caller();
        let (_, egid, _, _) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        if egid != GROUP {
            crate::handlers::__test_uidgid_reset();
            return Err("a set-group-ID binary did not move the effective gid");
        }

        // ── a shebang confers nothing ────────────────────────────────
        // The kernel executes the INTERPRETER; honouring the script's bits
        // would hand its privilege to an interpreter never audited for it.
        stage(0o4755)?;
        as_caller();
        let (euid, _, _, _) = crate::handlers::__test_bprm_fill_uid(task, path, true);
        if euid == OWNER {
            crate::handlers::__test_uidgid_reset();
            return Err("a set-user-ID script granted privilege through its interpreter");
        }

        // ── no_new_privs refuses the transition ──────────────────────
        stage(0o4755)?;
        as_caller();
        const PR_SET_NO_NEW_PRIVS: u64 = 38;
        if call(Syscall::Prctl.raw(), a2(PR_SET_NO_NEW_PRIVS, 1, 0)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("prctl(PR_SET_NO_NEW_PRIVS) failed");
        }
        let (euid, _, _, _) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        crate::handlers::__test_prctl_reset();
        if euid == OWNER {
            crate::handlers::__test_uidgid_reset();
            return Err("no_new_privs did not stop a set-user-ID transition");
        }

        // ── a setuid-ROOT binary regenerates capabilities ────────────
        // Without this the new program would be uid 0 with an empty
        // permitted set — the one state Linux never leaves a process in.
        // Staged as root again, for the same reason as `stage`.
        crate::handlers::__test_uidgid_reset();
        crate::handlers::__test_caps_reset();
        if call(Syscall::Chown.raw(), a2(cpath.as_ptr() as u64, 0, 0)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("chown root of the test binary failed");
        }
        // The chmod must come AFTER the chown: changing an owner clears
        // the set-user-ID bit (`setattr_should_drop_suidgid`), so staging
        // them the other way round would leave an ordinary 0755 binary and
        // the assertion below would be about nothing.
        if call(Syscall::Chmod.raw(), a1(cpath.as_ptr() as u64, 0o4755)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("chmod setuid-root of the test binary failed");
        }
        as_caller();
        let (euid, _, _, effective) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        crate::handlers::__test_uidgid_reset();
        if euid != 0 {
            return Err("a set-user-ID-root binary did not reach uid 0");
        }
        if effective == 0 {
            return Err("a set-user-ID-root binary got uid 0 with no capabilities");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_setuid_exec_transition_and_its_guards
);

/// `nosuid` is what it says: a set-user-ID binary on such a mount confers
/// nothing.
///
/// `bprm_fill_uid` opens with `if (!mnt_may_suid(file->f_path.mnt))
/// return;`, and `mnt_may_suid` is `!(mnt->mnt_flags & MNT_NOSUID) && ...`.
/// This is the pairing that makes both halves worth having: storing the
/// flag was pointless while nothing could be suppressed, and implementing
/// set-user-ID execution without honouring the flag would have handed
/// every sandbox a privilege-escalation path it had explicitly asked to
/// close.
fn smoke_abi_fsx_nosuid_mount_confers_no_privilege() -> TestResult {
    const OWNER: u32 = 4200;
    const CALLER: u32 = 1200;
    const MS_NOSUID: u64 = 1 << 1;
    with_setup(|| {
        let target = b"/abi-nosuid\0";
        let source = b"tmpfs\0";
        let fstype = b"tmpfs\0";
        let mount_with = |flags: u64| {
            call(
                Syscall::Mount.raw(),
                SyscallArgs {
                    arg0: source.as_ptr() as u64,
                    arg1: target.as_ptr() as u64,
                    arg2: fstype.as_ptr() as u64,
                    arg3: flags,
                    arg4: 0,
                    ..Default::default()
                },
            )
        };
        let cpath = b"/abi-nosuid/prog\0";
        let path = "/abi-nosuid/prog";
        let task = crate::handlers::current_task_id();
        let finish = |outcome: Result<(), &'static str>| {
            crate::handlers::__test_uidgid_reset();
            let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
            outcome
        };
        let stage = || -> Result<(), &'static str> {
            match call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, cpath.as_ptr() as u64, 0o100 | 0o2, 0o755),
            ) {
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a0(fd as u64));
                }
                _ => return Err("creating the test binary failed"),
            }
            // chown first: it clears the set-user-ID bit.
            if call(
                Syscall::Chown.raw(),
                a2(cpath.as_ptr() as u64, OWNER as u64, OWNER as u64),
            ) != Some(0)
            {
                return Err("chown of the test binary failed");
            }
            if call(Syscall::Chmod.raw(), a1(cpath.as_ptr() as u64, 0o4755)) != Some(0) {
                return Err("chmod setuid of the test binary failed");
            }
            Ok(())
        };

        // Baseline on a PLAIN mount: the transition must happen, or the
        // nosuid assertion below would pass for the wrong reason.
        if mount_with(0) != Some(0) {
            return Err("mounting a plain tmpfs failed");
        }
        if let Err(msg) = stage() {
            return finish(Err(msg));
        }
        crate::handlers::__test_set_fsids(task, CALLER, CALLER);
        let (euid, ..) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        crate::handlers::__test_uidgid_reset();
        // `__test_bprm_fill_uid` performs the WHOLE exec credential step,
        // and that step ends in `pE' = fE ? pP' : pA'` — so an exec as a
        // non-root uid clears the effective set, exactly as Linux does. The
        // harness uses this hook as a credential setter and then keeps
        // issuing privileged syscalls (the second mount below), so it has
        // to put the boot credential back; a real process would have been
        // replaced by the new image instead.
        crate::handlers::__test_caps_reset();
        if euid != OWNER {
            return finish(Err(
                "the baseline setuid transition did not happen — test is vacuous",
            ));
        }
        let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));

        // Same binary, same bits, on a `nosuid` mount: nothing.
        if mount_with(MS_NOSUID) != Some(0) {
            return Err("mounting a nosuid tmpfs failed");
        }
        if let Err(msg) = stage() {
            return finish(Err(msg));
        }
        crate::handlers::__test_set_fsids(task, CALLER, CALLER);
        let (euid, ..) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        if euid == OWNER {
            return finish(Err("a nosuid mount granted a set-user-ID transition"));
        }
        if euid != CALLER {
            return finish(Err("a nosuid mount changed the effective uid at all"));
        }
        finish(Ok(()))
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_nosuid_mount_confers_no_privilege
);

/// Writing to a file strips its set-user-ID bit.
///
/// `vfs_write` -> `file_remove_privs` -> `setattr_should_drop_suidgid`:
///
/// ```text
/// /* suid always must be killed */
/// if (unlikely(mode & S_ISUID))
///         kill = ATTR_KILL_SUID;
/// kill |= setattr_should_drop_sgid(idmap, inode);
/// if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
///         return kill;
/// ```
///
/// This became load-bearing the moment set-user-ID execution started
/// working: without it, "can write this file" silently means "can become
/// whoever owns it", because an attacker appends their payload to a
/// set-user-ID-root binary and it stays set-user-ID-root.
///
/// The set-group-ID half is conditional, and the condition is the point:
/// S_ISGID WITHOUT group-execute is the mandatory file-locking marker, and
/// `setattr_should_drop_sgid` spares it for a writer who is in the file's
/// own group.
fn smoke_abi_fsx_write_strips_setuid() -> TestResult {
    with_memfs(
        "/abi-privs",
        "abi-privs",
        &[("prog", b"x"), ("locked", b"x")],
        || {
            let prog = b"/abi-privs/prog\0";
            let locked = b"/abi-privs/locked\0";
            let mode_of = |path: &[u8]| -> Option<u32> {
                let mut sb = [0u8; 144];
                if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
                    return None;
                }
                Some(u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]) & 0o7777)
            };
            // Stage BOTH files while still fully privileged. Dropping uid
            // also drops capabilities, and there is no way back, so every
            // chown/chmod has to happen before the single drop below.
            //
            // chown comes before chmod in each pair: changing an owner
            // clears the very bits being staged.
            //
            // `prog` is a set-user-ID, set-group-ID EXECUTABLE owned by the
            // caller, so the caller can write it at all.
            if call(Syscall::Chown.raw(), a2(prog.as_ptr() as u64, 1000, 1000)) != Some(0) {
                return Err("chown of the test binary failed");
            }
            if call(Syscall::Chmod.raw(), a1(prog.as_ptr() as u64, 0o6755)) != Some(0) {
                return Err("chmod 6755 setup failed");
            }
            // `locked` is 02666: set-group-ID with NO group-execute — the
            // mandatory-locking marker — and group-writable.
            //
            // Its group is 0 because `setresuid` below moves only the UIDs;
            // the writer keeps fsgid 0, so group 0 is the group it is
            // actually IN. Staging this as group 1000 would make the writer
            // a non-member, and `setattr_should_drop_sgid` would then
            // correctly strip the bit — testing the opposite rule by
            // accident.
            if call(Syscall::Chown.raw(), a2(locked.as_ptr() as u64, 0, 0)) != Some(0) {
                return Err("chgrp of the locked file failed");
            }
            if call(Syscall::Chmod.raw(), a1(locked.as_ptr() as u64, 0o2666)) != Some(0) {
                return Err("chmod 2666 setup failed");
            }
            if mode_of(prog) != Some(0o6755) || mode_of(locked) != Some(0o2666) {
                return Err("the setuid bits did not stick — staging is vacuous");
            }

            // Write as an UNPRIVILEGED task: CAP_FSETID is precisely the
            // right to KEEP these bits, so as root the write would
            // legitimately preserve them and this test would prove nothing.
            if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
                crate::handlers::__test_uidgid_reset();
                return Err("setresuid(1000) setup failed");
            }
            let write_to = |path: &[u8]| -> Option<i64> {
                let fd = call(
                    Syscall::Openat.raw(),
                    a3(AT_FDCWD, path.as_ptr() as u64, 0o1, 0),
                );
                match fd {
                    Some(fd) if fd >= 0 => {
                        let payload = b"payload";
                        let n = call(
                            Syscall::Write.raw(),
                            a2(fd as u64, payload.as_ptr() as u64, payload.len() as u64),
                        );
                        let _ = call(Syscall::Close.raw(), a0(fd as u64));
                        n
                    }
                    _ => None,
                }
            };
            let wrote_prog = write_to(prog);
            let wrote_locked = write_to(locked);
            crate::handlers::__test_uidgid_reset();

            if wrote_prog.map(|n| n <= 0).unwrap_or(true) {
                return Err("the unprivileged write did not happen — staging is vacuous");
            }
            if wrote_locked.map(|n| n <= 0).unwrap_or(true) {
                return Err("the group-member write did not happen — staging is vacuous");
            }
            match mode_of(prog) {
                Some(mode) if mode & 0o4000 != 0 => {
                    return Err("a write left the set-user-ID bit in place")
                }
                Some(mode) if mode & 0o2000 != 0 => {
                    return Err("a write left a set-group-ID EXECUTABLE bit in place")
                }
                Some(0o755) => {}
                Some(_) => return Err("a write changed more than the privilege bits"),
                None => return Err("stat after the write failed"),
            }
            // S_ISGID without group-execute is the mandatory-locking marker,
            // not a privilege, and `setattr_should_drop_sgid` spares it for a
            // writer who is in the file's own group.
            match mode_of(locked) {
                Some(mode) if mode & 0o2000 == 0 => {
                    Err("a write stripped the mandatory-locking S_ISGID from a group member")
                }
                Some(_) => Ok(()),
                None => Err("stat after the locked-file write failed"),
            }
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_write_strips_setuid);

/// Creating a device node needs CAP_MKNOD; a FIFO does not.
///
/// `vfs_mknod`:
///
/// ```text
/// if ((S_ISCHR(mode) || S_ISBLK(mode)) && !is_whiteout &&
///     !capable(CAP_MKNOD))
///         return -EPERM;
/// ```
///
/// A device node is a direct handle on a driver, so an unprivileged task
/// that could `mknod` its own `/dev/sda` would read the disk past every
/// file permission on it. NARF let anyone with write access to a
/// directory create one. The check deliberately names only the two device
/// types: a FIFO or socket carries no such authority, and requiring
/// privilege for `mkfifo` would break ordinary programs.
fn smoke_abi_fsx_mknod_device_requires_cap_mknod() -> TestResult {
    const S_IFCHR: u64 = 0o020000;
    const S_IFIFO: u64 = 0o010000;
    with_memfs("/abi-mknod", "abi-mknod", &[], || {
        let dev = b"/abi-mknod/dev\0";
        let fifo = b"/abi-mknod/fifo\0";
        let root_dev = b"/abi-mknod/rootdev\0";
        // Make the directory world-writable, so the refusal below can only
        // come from the capability check and not from `may_create`.
        let dir = b"/abi-mknod\0";
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o777)) != Some(0) {
            return Err("chmod 0777 of the test directory failed");
        }
        // Privileged baseline: a device node IS creatable with CAP_MKNOD,
        // or the denial below would prove nothing.
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, root_dev.as_ptr() as u64, S_IFCHR | 0o666, 0x0103),
        ) != Some(0)
        {
            return Err("a privileged mknod of a device node failed — test is vacuous");
        }
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("setresuid(1000) setup failed");
        }
        let made_dev = call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, dev.as_ptr() as u64, S_IFCHR | 0o666, 0x0103),
        );
        let made_fifo = call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, fifo.as_ptr() as u64, S_IFIFO | 0o666, 0),
        );
        crate::handlers::__test_uidgid_reset();
        if made_dev != Some(EPERM) {
            return Err("an unprivileged mknod of a device node must return -EPERM");
        }
        if made_fifo != Some(0) {
            return Err("an unprivileged mkfifo was refused; CAP_MKNOD covers device nodes only");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mknod_device_requires_cap_mknod);

/// A setgid directory cannot be used to manufacture a set-group-ID binary.
///
/// `vfs_prepare_mode` -> `fs/inode.c::mode_strip_sgid`:
///
/// ```text
/// if ((mode & (S_ISGID | S_IXGRP)) != (S_ISGID | S_IXGRP)) return mode;
/// if (S_ISDIR(mode) || !dir || !(dir->i_mode & S_ISGID))   return mode;
/// if (in_group_or_capable(idmap, dir, i_gid_into_vfsgid(idmap, dir)))
///                                                          return mode;
/// return mode & ~S_ISGID;
/// ```
///
/// The attack it closes: a setgid directory hands its group to every new
/// file, so a caller who is NOT in that group could otherwise create a
/// group-executable set-group-ID binary owned by a group it does not
/// belong to — privilege manufactured out of write access to a shared
/// directory.
///
/// NARF masked the set-group-ID bit off every create instead, which
/// blocked the attack by blocking the feature: `open(path, O_CREAT,
/// 02755)` silently produced a plain file. The mask is now Linux's
/// `S_IALLUGO`, and this is the guard.
fn smoke_abi_fsx_setgid_dir_cannot_manufacture_setgid_binary() -> TestResult {
    const GROUP: u32 = 7700;
    with_memfs("/abi-sgidstrip", "abi-sgidstrip", &[], || {
        let dir = b"/abi-sgidstrip/shared\0";
        let member = b"/abi-sgidstrip/shared/member\0";
        let stranger = b"/abi-sgidstrip/shared/stranger\0";
        let mode_of = |path: &[u8]| -> Option<u32> {
            let mut sb = [0u8; 144];
            if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
                return None;
            }
            Some(u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]) & 0o7777)
        };
        if call_mkdir(dir.as_ptr() as u64, 0o777) != Some(0) {
            return Err("mkdir of the shared directory failed");
        }
        // Group 0 — which the root-credentialed creator below IS in.
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o2777)) != Some(0) {
            return Err("chmod g+s of the shared directory failed");
        }
        let create = |path: &[u8]| {
            call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, path.as_ptr() as u64, 0o100 | 0o2, 0o2755),
            )
        };
        // A member of the directory's group KEEPS the bit — otherwise this
        // test would pass on a blanket "always strip", which is the
        // behaviour it exists to rule out.
        match create(member) {
            Some(fd) if fd >= 0 => {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            _ => return Err("creating the member's file failed"),
        }
        match mode_of(member) {
            Some(mode) if mode & 0o2000 != 0 => {}
            Some(_) => return Err("a group member's set-group-ID request was stripped"),
            None => return Err("stat of the member's file failed"),
        }
        // Now a caller in a DIFFERENT group. The directory hands down its
        // own group, so the file would end up set-group-ID to a group the
        // creator is not in.
        if call(
            Syscall::Chown.raw(),
            a2(dir.as_ptr() as u64, 0, GROUP as u64),
        ) != Some(0)
        {
            return Err("chgrp of the shared directory failed");
        }
        if call(Syscall::Chmod.raw(), a1(dir.as_ptr() as u64, 0o2777)) != Some(0) {
            return Err("re-chmod g+s of the shared directory failed");
        }
        // The caller must be UNPRIVILEGED: CAP_FSETID is exactly the right
        // to KEEP the bit, and a root creator legitimately holds it — so
        // staging this as root would be asserting the opposite rule.
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("setresuid(1000) setup failed");
        }
        let made = create(stranger);
        if let Some(fd) = made {
            if fd >= 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
        }
        crate::handlers::__test_uidgid_reset();
        if made.map(|fd| fd < 0).unwrap_or(true) {
            return Err("creating the stranger's file failed");
        }
        match mode_of(stranger) {
            Some(mode) if mode & 0o2000 != 0 => {
                Err("a non-member manufactured a set-group-ID binary in a setgid directory")
            }
            Some(_) => Ok(()),
            None => Err("stat of the stranger's file failed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_setgid_dir_cannot_manufacture_setgid_binary
);

/// `chattr +i` — an immutable file refuses every change, including by
/// root.
///
/// The flags themselves come from `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS`
/// (`fs/file_attr.c`), and the refusals are spread across the VFS:
/// `inode_permission`'s "Nobody gets write access to an immutable file",
/// `may_delete`, `may_setattr`, `may_write_xattr` and `vfs_link`. NARF
/// modelled none of it, so `chattr +i` had nowhere to be stored and
/// nothing to enforce it.
///
/// Everything below runs as ROOT on purpose: immutability that root can
/// undo by ignoring it is not immutability. Root can only lift the flag
/// first, which is the last thing this checks.
fn smoke_abi_fsx_immutable_file_refuses_changes() -> TestResult {
    const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
    const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
    with_memfs(
        "/abi-imm",
        "abi-imm",
        &[("f", b"data"), ("other", b"x")],
        || {
            let path = b"/abi-imm/f\0";
            let other = b"/abi-imm/other\0";
            let moved = b"/abi-imm/moved\0";
            let set_flags = |flags: u32| -> Option<i64> {
                let fd = call_open(path.as_ptr() as u64, 0)?;
                if fd < 0 {
                    return None;
                }
                let word = flags;
                let r = call(
                    Syscall::Ioctl.raw(),
                    a2(fd as u64, FS_IOC_SETFLAGS, &word as *const u32 as u64),
                );
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                r
            };
            let get_flags = || -> Option<u32> {
                let fd = call_open(path.as_ptr() as u64, 0)?;
                if fd < 0 {
                    return None;
                }
                let mut word = 0u32;
                let r = call(
                    Syscall::Ioctl.raw(),
                    a2(fd as u64, FS_IOC_GETFLAGS, &mut word as *mut u32 as u64),
                );
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                (r == Some(0)).then_some(word)
            };

            // Baseline: writable before the flag, or nothing below is a test.
            let writable_now = call_open(path.as_ptr() as u64, 0o1);
            match writable_now {
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a0(fd as u64));
                }
                _ => return Err("the file was not writable to begin with — test is vacuous"),
            }

            if set_flags(FS_IMMUTABLE_FL) != Some(0) {
                return Err("FS_IOC_SETFLAGS(FS_IMMUTABLE_FL) failed");
            }
            if get_flags() != Some(FS_IMMUTABLE_FL) {
                return Err("FS_IOC_GETFLAGS did not read the flag back");
            }

            // Opening for write is refused — `inode_permission` bars it, and
            // this is root.
            if call_open(path.as_ptr() as u64, 0o1) != Some(EPERM) {
                return Err("an immutable file allowed a write open");
            }
            // Reading is untouched.
            match call_open(path.as_ptr() as u64, 0) {
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a0(fd as u64));
                }
                _ => return Err("an immutable file refused a READ open"),
            }
            if call(Syscall::Truncate.raw(), a1(path.as_ptr() as u64, 0)) != Some(EPERM) {
                return Err("an immutable file allowed truncate");
            }
            if call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o600)) != Some(EPERM) {
                return Err("an immutable file allowed chmod");
            }
            if call(Syscall::Chown.raw(), a2(path.as_ptr() as u64, 1000, 1000)) != Some(EPERM) {
                return Err("an immutable file allowed chown");
            }
            if call_unlink(path.as_ptr() as u64) != Some(EPERM) {
                return Err("an immutable file allowed unlink");
            }
            if call_rename(path.as_ptr() as u64, moved.as_ptr() as u64) != Some(EPERM) {
                return Err("an immutable file allowed rename");
            }
            let name = b"user.k\0";
            let value = b"v";
            if call(
                Syscall::Setxattr.raw(),
                SyscallArgs {
                    arg0: path.as_ptr() as u64,
                    arg1: name.as_ptr() as u64,
                    arg2: value.as_ptr() as u64,
                    arg3: value.len() as u64,
                    arg4: 0,
                    ..Default::default()
                },
            ) != Some(EPERM)
            {
                return Err("an immutable file allowed setxattr");
            }
            // A NEW name for the inode is a change to it (`vfs_link`).
            //
            // Through `call_link`, not `Syscall::Link` directly: arm64
            // wires no legacy `link` (only the `*at` form), so the raw
            // number is `u32::MAX` there and the call would report "the
            // syscall misbehaved" rather than the errno under test.
            if call_link(path.as_ptr() as u64, other.as_ptr() as u64) != Some(EPERM) {
                return Err("an immutable file allowed a hard link");
            }

            // Lifting the flag restores everything — the file is protected,
            // not destroyed.
            if set_flags(0) != Some(0) {
                return Err("clearing FS_IMMUTABLE_FL failed");
            }
            match call_open(path.as_ptr() as u64, 0o1) {
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a0(fd as u64));
                    Ok(())
                }
                _ => Err("clearing the flag did not make the file writable again"),
            }
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_immutable_file_refuses_changes);

/// `chattr +a` — append-only lets the data grow and nothing else.
///
/// `may_open`:
///
/// ```text
/// if (IS_APPEND(inode)) {
///         if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
///                 return -EPERM;
///         if (flag & O_TRUNC)
///                 return -EPERM;
/// }
/// ```
///
/// This is the weaker of the two flags and the distinction is the point:
/// an append-only log must accept new records while refusing to have its
/// history rewritten, so an O_APPEND open succeeds where a plain one is
/// EPERM. Setting either flag needs CAP_LINUX_IMMUTABLE, which is the
/// other half tested here.
fn smoke_abi_fsx_append_only_allows_appends_only() -> TestResult {
    const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
    const FS_APPEND_FL: u32 = 0x0000_0020;
    const O_APPEND: u64 = 0o2000;
    const O_TRUNC: u64 = 0o1000;
    with_memfs("/abi-append", "abi-append", &[("log", b"start")], || {
        let path = b"/abi-append/log\0";
        let set_flags = |flags: u32| -> Option<i64> {
            let fd = call_open(path.as_ptr() as u64, 0)?;
            if fd < 0 {
                return None;
            }
            let word = flags;
            let r = call(
                Syscall::Ioctl.raw(),
                a2(fd as u64, FS_IOC_SETFLAGS, &word as *const u32 as u64),
            );
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            r
        };
        if set_flags(FS_APPEND_FL) != Some(0) {
            return Err("FS_IOC_SETFLAGS(FS_APPEND_FL) failed");
        }
        // A plain write open is refused; an appending one is not.
        if call_open(path.as_ptr() as u64, 0o1) != Some(EPERM) {
            return Err("an append-only file allowed a non-appending write open");
        }
        if call_open(path.as_ptr() as u64, 0o1 | O_TRUNC | O_APPEND) != Some(EPERM) {
            return Err("an append-only file allowed O_TRUNC");
        }
        let fd = match call_open(path.as_ptr() as u64, 0o1 | O_APPEND) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("an append-only file refused an O_APPEND open"),
        };
        let payload = b"more";
        let wrote = call(
            Syscall::Write.raw(),
            a2(fd, payload.as_ptr() as u64, payload.len() as u64),
        );
        let _ = call(Syscall::Close.raw(), a0(fd));
        if wrote != Some(payload.len() as i64) {
            return Err("an append-only file refused an appending write");
        }
        // Unlinking is still barred: the history cannot be dropped either.
        if call_unlink(path.as_ptr() as u64) != Some(EPERM) {
            return Err("an append-only file allowed unlink");
        }
        // A privileged caller CAN lift it — the file is protected, not
        // destroyed. Checked before the drop below, because dropping uid
        // also drops the capability and there is no way back.
        if set_flags(0) != Some(0) {
            return Err("a privileged caller could not clear FS_APPEND_FL");
        }
        if set_flags(FS_APPEND_FL) != Some(0) {
            return Err("re-setting FS_APPEND_FL failed");
        }
        // Setting or clearing either flag needs CAP_LINUX_IMMUTABLE
        // (`fileattr_set_prepare`), or the protection would be decorative:
        // anyone it applies to could simply remove it.
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            crate::handlers::__test_uidgid_reset();
            return Err("setresuid(1000) setup failed");
        }
        let cleared = set_flags(0);
        crate::handlers::__test_uidgid_reset();
        if cleared == Some(0) {
            return Err("an unprivileged caller cleared FS_APPEND_FL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_append_only_allows_appends_only);

fn smoke_abi_fsx_getxattr_pos() -> TestResult {
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("g", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("missing", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("l", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("l2", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("r", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("r2", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lx", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lx", b"hi")], || {
        let path = b"/abi/lx\0";
        // Empty name → ERANGE (`import_xattr_name`), not EINVAL.
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
        match call(Syscall::Lsetxattr.raw(), args) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("lsetxattr with an empty name must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_lsetxattr_neg);

fn smoke_abi_fsx_lgetxattr_pos() -> TestResult {
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lg", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lg-absent", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("ll", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("ll2", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lr", b"hi")], || {
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
    // xattr calls on a missing path are -ENOENT (`filename_lookup`),
    // so the named inode has to exist.
    with_memfs("/abi", "abi", &[("lr-absent", b"hi")], || {
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
        // put_old is resolved with LOOKUP_DIRECTORY too, so it must exist.
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, put_old.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            crate::handlers::__test_root_dir_reset();
            return Err("setup mkdir of put_old failed");
        }
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
/// move_mount(2): the source is `from_dfd` itself (an fsmount/open_tree fd);
/// without it an empty or NULL `from_path` is -ENOENT / -EFAULT.
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x0000_0004;

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
        // Empty fsname → `get_fs_type("")` finds nothing → ENODEV (Linux
        // 6.18); it is not an argument-shape error.
        let fsname = b"\0";
        if call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) != Some(ENODEV) {
            return Err("fsopen with an empty fsname must return -ENODEV");
        }
        // Unknown flag bits are -EINVAL, checked before the name is read.
        let tmpfs = b"tmpfs\0";
        match call(Syscall::Fsopen.raw(), a1(tmpfs.as_ptr() as u64, 2)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fsopen with an unknown flag must return -EINVAL"),
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
        // Parameters and CMD_RECONFIGURE are accepted only once the context
        // is in the reconfigure phase — after fsmount, which is how systemd
        // remounts its credentials fs read-only. Straight after CMD_CREATE
        // both are -EBUSY.
        if call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: 0,
                arg2: key.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(EBUSY)
        {
            return Err("fsconfig(SET_FLAG) awaiting fsmount must return -EBUSY");
        }
        if !matches!(call(Syscall::Fsmount.raw(), a2(fd, 0, 0)), Some(v) if v >= 0) {
            return Err("fsmount setup failed");
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
                arg4: MOVE_MOUNT_F_EMPTY_PATH,
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
            arg4: MOVE_MOUNT_F_EMPTY_PATH,
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
        // from_dfd 999 is not an open fd → EBADF. The target is resolved
        // first, so it names something that exists.
        let to = b"/\0";
        let args = SyscallArgs {
            arg0: 999,
            arg1: 0,
            arg2: 0,
            arg3: to.as_ptr() as u64,
            arg4: MOVE_MOUNT_F_EMPTY_PATH,
            ..Default::default()
        };
        if call(Syscall::MoveMount.raw(), args) != Some(EBADF) {
            return Err("move_mount from an unknown fd must return -EBADF");
        }
        // Unknown flag bits are -EINVAL before anything is resolved.
        let bad_flags = SyscallArgs { arg4: 0x80, ..args };
        if call(Syscall::MoveMount.raw(), bad_flags) != Some(EINVAL) {
            return Err("move_mount with an unknown flag must return -EINVAL");
        }
        // Without MOVE_MOUNT_F_EMPTY_PATH an empty source name is -ENOENT.
        let empty = b"\0";
        let no_empty_flag = SyscallArgs {
            arg1: empty.as_ptr() as u64,
            arg4: 0,
            ..args
        };
        match call(Syscall::MoveMount.raw(), no_empty_flag) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("move_mount of \"\" without F_EMPTY_PATH must return -ENOENT"),
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

// ─────────────────────────────────────────────────────────────────────
// ACL follow-ups: open(2) consults the ACL, and setxattr reports why
//
// The ACL implementation landed with these two deliberately unwired,
// because they live in files its author was fenced out of. Both are
// observable from userspace:
//
//   * `may_open` ends in `inode_permission(idmap, inode, MAY_OPEN|acc_mode)`
//     which reaches check_acl, so an ACL that access(2) honours must also
//     be honoured by the open that follows it. Otherwise `setfacl` appears
//     to work and the program still cannot open the file.
//   * setxattr collapsed every ACL rejection into -EIO, which points the
//     reader at the disk rather than at their ACL.
// ─────────────────────────────────────────────────────────────────────

/// A minimal well-formed ACCESS ACL granting `uid` exactly `perm`.
/// Layout: `__le32 a_version`, then `{__le16 tag, __le16 perm, __le32 id}`.
fn acl_blob(uid: u32, perm: u16) -> alloc::vec::Vec<u8> {
    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;
    const UNDEF: u32 = u32::MAX;
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&2u32.to_le_bytes()); // POSIX_ACL_XATTR_VERSION
    let mut ent = |tag: u16, p: u16, id: u32| {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&p.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    };
    // Order matters: posix_acl_valid requires USER_OBJ, USER*, GROUP_OBJ,
    // GROUP*, MASK, OTHER in that sequence, and the MASK must follow the
    // entries it limits (the forward-scan rule).
    // USER_OBJ 6 and OTHER 0 make `posix_acl_update_mode` derive a 06x0
    // mode, so the owner keeps access and "other" has none — the named-user
    // entry is then the only thing that can grant an unrelated uid.
    ent(ACL_USER_OBJ, 6, UNDEF);
    ent(ACL_USER, perm, uid);
    ent(ACL_GROUP_OBJ, 0, UNDEF);
    ent(ACL_MASK, perm, UNDEF);
    ent(ACL_OTHER, 0, UNDEF);
    v
}

fn smoke_abi_fsx_setxattr_malformed_acl_is_einval() -> TestResult {
    with_memfs("/aclx", "aclx", &[("f", b"data")], || {
        // `posix_acl_fix_xattr_common` rejects a ragged buffer with
        // -EINVAL. This used to report -EIO.
        let path = b"/aclx/f\0";
        let name = b"system.posix_acl_access\0";
        let ragged = [2u8, 0, 0]; // shorter than the 4-byte header
        match call(
            Syscall::Setxattr.raw(),
            a3(
                path.as_ptr() as u64,
                name.as_ptr() as u64,
                ragged.as_ptr() as u64,
                ragged.len() as u64,
            ),
        ) {
            Some(-22) => Ok(()),
            Some(-5) => Err("a malformed ACL still reports -EIO instead of -EINVAL"),
            _ => Err("setxattr of a malformed ACL should be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_setxattr_malformed_acl_is_einval
);

fn smoke_abi_fsx_setxattr_bad_acl_version_is_eopnotsupp() -> TestResult {
    with_memfs("/aclv", "aclv", &[("f", b"data")], || {
        // `if (header->a_version != cpu_to_le32(POSIX_ACL_XATTR_VERSION))
        //      return -EOPNOTSUPP;`
        //
        // This previously fell through to the generic xattr table, which
        // STORED the rejected bytes — a later read would hand back an ACL
        // the kernel had refused.
        let path = b"/aclv/f\0";
        let name = b"system.posix_acl_access\0";
        let v1 = 1u32.to_le_bytes();
        match call(
            Syscall::Setxattr.raw(),
            a3(
                path.as_ptr() as u64,
                name.as_ptr() as u64,
                v1.as_ptr() as u64,
                v1.len() as u64,
            ),
        ) {
            Some(-95) => {}
            Some(0) => return Err("a bad-version ACL was accepted and stored"),
            _ => return Err("setxattr of a bad-version ACL should be -EOPNOTSUPP"),
        }
        // And nothing was stored: the read must miss, not return the bytes.
        let mut out = [0u8; 64];
        match call(
            Syscall::Getxattr.raw(),
            a3(
                path.as_ptr() as u64,
                name.as_ptr() as u64,
                out.as_mut_ptr() as u64,
                out.len() as u64,
            ),
        ) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("the refused ACL was stored anyway and read back"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_setxattr_bad_acl_version_is_eopnotsupp
);

fn smoke_abi_fsx_open_honours_the_acl() -> TestResult {
    with_memfs("/aclo", "aclo", &[("f", b"data")], || {
        // The point of the follow-up: an ACL that access(2) honours must
        // also be honoured by the open(2) that follows it.
        //
        // The grant has to come from a NAMED-USER entry, and the caller
        // has to be neither the owner nor in the file's group. Two reasons,
        // both learned by getting this wrong:
        //
        //   * `acl_permission_check` short-circuits on an owner match
        //     BEFORE consulting the ACL, so an ACL_USER entry naming the
        //     owner's own uid is never reached — ACL_USER_OBJ governs.
        //   * `posix_acl_update_mode` rewrites the file mode from
        //     USER_OBJ / MASK / OTHER when the ACL is stored, so anything
        //     the owner or group triplet grants is ALSO granted by the mode
        //     bits alone. Only a named-user entry is invisible to the mode,
        //     which is what makes this a discriminator rather than a
        //     tautology.
        //
        // So: file is uid 0 / gid 0, mode ends up 0640 from the ACL, and
        // the caller becomes uid 1000 / gid 1000 — the "other" triplet,
        // which is 0. Mode bits alone refuse; the ACL_USER entry grants.
        let path = b"/aclo/f\0";
        let name = b"system.posix_acl_access\0";
        let blob = acl_blob(1000, 4);
        if call(
            Syscall::Setxattr.raw(),
            a3(
                path.as_ptr() as u64,
                name.as_ptr() as u64,
                blob.as_ptr() as u64,
                blob.len() as u64,
            ),
        ) != Some(0)
        {
            return Err("storing the ACL failed");
        }
        // Become an unrelated user. gid first, then uid — setuid away from
        // root clears the capability sets (cap_emulate_setxuid), so the
        // other order would leave setgid without CAP_SETGID.
        if call(Syscall::SetGid.raw(), a0(1000)) != Some(0) {
            return Err("setgid(1000) failed");
        }
        if call(Syscall::SetUid.raw(), a0(1000)) != Some(0) {
            return Err("setuid(1000) failed");
        }
        match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => Ok(()),
            Some(-13) => Err("open ignored the ACL and refused on mode bits alone"),
            _ => Err("open of an ACL-granted file should succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_open_honours_the_acl);

fn smoke_abi_fsx_open_still_refuses_without_an_acl() -> TestResult {
    with_memfs("/aclo2", "aclo2", &[("f", b"data")], || {
        // The control. Same identity change, same 0640-shaped mode, but no
        // named-user entry — so the "other" triplet decides and open is
        // refused. Without this, the test above would pass even if open
        // had simply stopped checking permissions at all.
        let path = b"/aclo2/f\0";
        if call(Syscall::Chmod.raw(), a1(path.as_ptr() as u64, 0o640)) != Some(0) {
            return Err("chmod setup failed");
        }
        if call(Syscall::SetGid.raw(), a0(1000)) != Some(0) {
            return Err("setgid(1000) failed");
        }
        if call(Syscall::SetUid.raw(), a0(1000)) != Some(0) {
            return Err("setuid(1000) failed");
        }
        match call_open(path.as_ptr() as u64, 0) {
            Some(-13) => Ok(()),
            Some(fd) if fd >= 0 => Err("open granted read on a 0640 file to an unrelated uid"),
            _ => Err("open without an ACL grant should be -EACCES"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_open_still_refuses_without_an_acl
);

// ══════════════════════════════════════════════════════════════════════════
// mount(2) requires its target to exist, and says so BEFORE anything else.
//
// `do_mount` (fs/namespace.c:4163):
//     ret = user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
//     if (ret) return ret;
//     return path_mount(dev_name, &path, type_page, flags, data_page);
//
// Both the MS_NOUSER -EINVAL and the `may_mount()` -EPERM live inside
// `path_mount`, downstream of that lookup, so a missing target outranks
// both. NARF used to register a mount at a path with no node and report
// success, which tells a caller using the probe-then-mkdir idiom (systemd,
// every container runtime) that its mount point already existed.
//
// Targets under MOUNT_TARGET_ABSENT_PREFIX are deliberately not created by
// the fixture, which is what lets these cases observe the -ENOENT.
// ══════════════════════════════════════════════════════════════════════════

fn smoke_abi_fsx_mount_missing_target_is_enoent() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let target = b"/absent-mount-target\0";
        let fstype = b"tmpfs\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(r) if r == ENOENT => Ok(()),
            _ => Err("mount at a nonexistent target must return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx_mount_missing_target_is_enoent);

/// ORDER PIN. The target lookup precedes `path_mount`, so a missing target
/// beats the MS_NOUSER -EINVAL that an in-kernel-only flag would otherwise
/// produce. Getting this backwards sends a caller off inspecting its flags
/// when the real problem is that it never created the mount point.
fn smoke_abi_fsx_mount_missing_target_beats_einval() -> TestResult {
    with_setup(|| {
        const MS_NOUSER: u64 = 1 << 31;
        let source = b"none\0";
        let target = b"/absent-mount-target-2\0";
        let fstype = b"tmpfs\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: MS_NOUSER,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(r) if r == ENOENT => Ok(()),
            Some(r) if r == EINVAL => {
                Err("MS_NOUSER -EINVAL won; the target lookup must run first")
            }
            _ => Err("mount with a bad flag AND a missing target did not return -ENOENT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx_mount_missing_target_beats_einval
);

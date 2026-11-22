//! A btrfs directory's default POSIX ACL reaches the inodes created in it.
//!
//! Linux: `btrfs_new_inode_prepare` runs `posix_acl_create(dir, &mode,
//! &default_acl, &acl)`, which reads the directory's `ACL_TYPE_DEFAULT`
//! through `btrfs_get_acl`, and `btrfs_init_inode_security` stores the
//! inherited access ACL — and, for a new directory, the copied default —
//! on the new inode (`fs/btrfs/inode.c`, `fs/btrfs/acl.c`). NARF runs the
//! same inheritance in the syscall layer (`inherit_acls_from_parent`): it
//! asks the parent through `DirOps::default_acl`, and `mkdir` stores the
//! copied default on the new directory through `DirOps::set_xattr`.
//!
//! journald depends on this. systemd-tmpfiles gives `/var/log/journal/<id>`
//! a default ACL with `group:wheel:r-x` and `group:adm:r-x`, and journald
//! sets no ACL of its own on a system journal: each `system.journal` it
//! creates on rotation is readable by those groups only through the
//! inherited entries. Without them every system journal created after boot
//! was `root:systemd-journal 0640` with no ACL, and `journalctl` run by a
//! wheel user silently stopped showing the kernel and every system service
//! from the first rotation on.

use super::*;
use narf_filesystem::{
    AclEntry, FsInstance, PosixAcl, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER_OBJ,
    XATTR_NAME_POSIX_ACL_DEFAULT as DEFAULT,
};

/// systemd-tmpfiles' `d:group::r-x,d:group:adm:r-x,d:group:wheel:r-x` on
/// `/var/log/journal/%m`, as `getfacl` reports it there: user::rwx group::r-x
/// group:adm:r-x group:wheel:r-x mask::r-x other::r-x.
fn journal_default_acl() -> PosixAcl {
    PosixAcl::from_entries(alloc::vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::with_id(ACL_GROUP, 4, 5),
        AclEntry::with_id(ACL_GROUP, 998, 5),
        AclEntry::tagged(ACL_MASK, 5),
        AclEntry::tagged(ACL_OTHER, 5),
    ])
}

/// The directory's default ACL, as `tmpfiles` stored it through `setxattr`
/// on the path, is what `DirOps::default_acl` hands the create path; a new
/// subdirectory keeps the copy `mkdir` stores through `DirOps::set_xattr`;
/// both survive a remount. A directory without a default ACL reports none,
/// so the umask applies there.
fn smoke_btrfs_directory_default_acl_reaches_new_inodes() -> TestResult {
    use narf_block::ram::RamBlockDevice;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    let journal = match poll_once(root.mkdir("journal")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("mkdir journal failed"),
    };
    if journal.default_acl().is_some() {
        return TestResult::Fail("a directory without a default ACL reported one");
    }

    // `setfacl -d` / tmpfiles: setxattr on the path reaches the directory's
    // FileOps (the syscall layer's `xattr_target` resolves it as a file).
    let acl = journal_default_acl();
    let blob = acl.to_xattr();
    let journal_file = match poll_once(root.lookup_async("journal")) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("journal lookup failed"),
    };
    if !matches!(
        poll_once(journal_file.set_xattr(DEFAULT, &blob, 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("setting the journal directory's default ACL failed");
    }

    // `open(O_CREAT)` in it: `posix_acl_create` reads the parent's default.
    if journal.default_acl().as_deref() != Some(&blob[..]) {
        return TestResult::Fail(
            "DirOps::default_acl did not hand the create path the directory's default ACL",
        );
    }
    // What journald's `open(system.journal, O_CREAT, 0640)` then gets: an
    // access ACL that keeps group:wheel, the mode unchanged by any umask.
    let mut mode = 0o640u16;
    let created = narf_filesystem::posix_acl_create(Some(&acl), false, false, &mut mode, 0o077);
    let wheel = |access: &PosixAcl| {
        access
            .entries
            .iter()
            .any(|e| e.tag == ACL_GROUP && e.id == 998)
    };
    let keeps_wheel = created
        .as_ref()
        .is_ok_and(|c| c.default_acl.is_none() && c.access_acl.as_ref().is_some_and(wheel));
    if mode != 0o640 || !keeps_wheel {
        return TestResult::Fail("a new file did not inherit group:wheel");
    }

    // `mkdir` in it: the new directory keeps the default so inheritance
    // continues below it (`sys_mkdir` stores it through DirOps::set_xattr).
    let machine = match poll_once(journal.mkdir("machine")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("mkdir journal/machine failed"),
    };
    if !matches!(
        poll_once(machine.set_xattr(DEFAULT, &blob, 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("a new btrfs directory refused the default ACL it inherits");
    }
    if machine.default_acl().as_deref() != Some(&blob[..]) {
        return TestResult::Fail("a new btrfs directory lost the default ACL it inherited");
    }

    // Commits are batched: sync before checking what a remount sees.
    let _ = poll_once(vol.sync_to_disk());
    let remount = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let journal = match poll_once(remount.root().lookup_dir_async("journal")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("journal lookup after remount failed"),
    };
    if journal.default_acl().as_deref() != Some(&blob[..]) {
        return TestResult::Fail("the directory's default ACL did not survive a remount");
    }
    let machine_file = match poll_once(journal.lookup_async("machine")) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("journal/machine lookup after remount failed"),
    };
    if poll_once(machine_file.get_xattr(DEFAULT)).and_then(Result::ok) != Some(blob) {
        return TestResult::Fail("the inherited default ACL did not survive a remount");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs/default-acl",
    smoke_btrfs_directory_default_acl_reaches_new_inodes
);

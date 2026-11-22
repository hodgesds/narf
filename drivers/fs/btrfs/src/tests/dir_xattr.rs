//! A btrfs directory's extended attributes, and its POSIX ACLs, through the
//! directory handle the VFS holds.
//!
//! Path resolution hands back a `DirOps` for a directory, and that is what
//! `may_create` / `may_delete` ask for the directory's access ACL
//! (`acl_of_dir`) and what an fd-based xattr call on a directory reaches.
//! Linux's btrfs serves directories and files with the same handlers
//! (`btrfs_xattr_handlers`, `btrfs_get_acl`, `btrfs_set_acl`), and an ACL
//! write is not a raw xattr write: `btrfs_set_acl` runs
//! `posix_acl_update_mode` for an access ACL — the mode's permission bits
//! become the ACL's, and an ACL the mode expresses exactly is not stored —
//! and `__btrfs_set_acl` refuses a default ACL on a non-directory, after the
//! VFS's `set_posix_acl` has (`acl ? -EACCES : 0`). Removing an ACL that is
//! not there is not an error (`btrfs_setxattr` deletes without
//! `XATTR_REPLACE`).

use super::*;
use narf_filesystem::{
    AclEntry, AclType, FsInstance, PosixAcl, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
    ACL_USER_OBJ, XATTR_NAME_POSIX_ACL_ACCESS as ACCESS, XATTR_NAME_POSIX_ACL_DEFAULT as DEFAULT,
};

/// user::rwx group::r-x group:<gid>:rwx mask::rwx other::---, as
/// `setfacl -m g:<gid>:rwx` leaves a 0750 inode: its mode becomes 0770.
fn shared_group_acl(gid: u32) -> PosixAcl {
    PosixAcl::from_entries(alloc::vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::with_id(ACL_GROUP, gid, 7),
        AclEntry::tagged(ACL_MASK, 7),
        AclEntry::tagged(ACL_OTHER, 0),
    ])
}

/// user::rwx group::r-x other::r-x — exactly mode 0755, so no ACL is kept.
fn minimal_acl() -> PosixAcl {
    PosixAcl::from_entries(alloc::vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::tagged(ACL_OTHER, 5),
    ])
}

fn smoke_btrfs_directory_xattrs_and_acls_follow_btrfs_set_acl() -> TestResult {
    use narf_block::ram::RamBlockDevice;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    let dir = match poll_once(root.mkdir("shared")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("mkdir shared failed"),
    };

    // An ordinary xattr round-trips through the directory handle.
    if !matches!(
        poll_once(dir.set_xattr("user.narf", b"dir", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("DirOps::set_xattr of user.narf failed");
    }
    if poll_once(dir.get_xattr("user.narf")).and_then(Result::ok) != Some(b"dir".to_vec()) {
        return TestResult::Fail("DirOps::get_xattr did not read the directory's xattr");
    }
    let names = poll_once(dir.list_xattr())
        .and_then(Result::ok)
        .unwrap_or_default();
    if !names.windows(10).any(|w| w == b"user.narf\0") {
        return TestResult::Fail("DirOps::list_xattr did not list the directory's xattr");
    }
    if !matches!(poll_once(dir.remove_xattr("user.narf")), Some(Ok(()))) {
        return TestResult::Fail("DirOps::remove_xattr of user.narf failed");
    }
    if !matches!(
        poll_once(dir.get_xattr("user.narf")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("a removed directory xattr is still readable");
    }
    if !matches!(
        poll_once(dir.remove_xattr("user.narf")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("removing an absent ordinary xattr must be ENODATA");
    }

    // An access ACL sets the mode (posix_acl_update_mode) and is what
    // may_create's acl_of_dir sees.
    let acl = shared_group_acl(998);
    let blob = acl.to_xattr();
    if !matches!(poll_once(dir.set_xattr(ACCESS, &blob, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting the directory's access ACL failed");
    }
    if dir.dir_mode() & 0o777 != 0o770 {
        return TestResult::Fail("an access ACL did not set the directory's mode to 0770");
    }
    match poll_once(narf_filesystem::acl_of_dir(dir.as_ref(), AclType::Access)) {
        Some(Ok(Some(seen))) if seen == acl => {}
        _ => return TestResult::Fail("acl_of_dir did not see the directory's access ACL"),
    }

    // An ACL the mode expresses exactly replaces the stored one with none.
    if !matches!(
        poll_once(dir.set_xattr(ACCESS, &minimal_acl().to_xattr(), 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("setting a mode-equivalent access ACL failed");
    }
    if dir.dir_mode() & 0o777 != 0o755
        || !matches!(
            poll_once(dir.get_xattr(ACCESS)),
            Some(Err(FsError::NotFound))
        )
    {
        return TestResult::Fail("a mode-equivalent access ACL must set 0755 and store nothing");
    }
    if !matches!(poll_once(dir.remove_xattr(ACCESS)), Some(Ok(()))) {
        return TestResult::Fail(
            "removing an absent ACL must succeed, as btrfs_set_acl(NULL) does",
        );
    }

    // An ACL that is not one (a named group before group::, no mask) is
    // EINVAL and changes nothing.
    let invalid = PosixAcl::from_entries(alloc::vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::with_id(ACL_GROUP, 998, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if !matches!(
        poll_once(dir.set_xattr(ACCESS, &invalid.to_xattr(), 0)),
        Some(Err(FsError::InvalidData))
    ) || dir.dir_mode() & 0o777 != 0o755
    {
        return TestResult::Fail("an invalid access ACL must be EINVAL and leave the mode");
    }

    // A file: the same mode rule; a default ACL is refused (EACCES).
    let file = match poll_once(dir.create("f")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("create shared/f failed"),
    };
    if !matches!(poll_once(file.set_xattr(ACCESS, &blob, 0)), Some(Ok(())))
        || file.stat().mode.perms & 0o777 != 0o770
    {
        return TestResult::Fail("an access ACL did not set the file's mode to 0770");
    }
    if !matches!(
        poll_once(file.set_xattr(DEFAULT, &blob, 0)),
        Some(Err(FsError::PermissionDenied))
    ) || !matches!(
        poll_once(file.get_xattr(DEFAULT)),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("a default ACL on a file must be EACCES and store nothing");
    }

    // The directory's ACL and mode are durable together.
    if !matches!(poll_once(dir.set_xattr(ACCESS, &blob, 0)), Some(Ok(()))) {
        return TestResult::Fail("re-setting the directory's access ACL failed");
    }
    let _ = poll_once(vol.sync_to_disk());
    let remount = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let dir = match poll_once(remount.root().lookup_dir_async("shared")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("shared lookup after remount failed"),
    };
    if dir.dir_mode() & 0o777 != 0o770
        || poll_once(dir.get_xattr(ACCESS)).and_then(Result::ok) != Some(blob)
    {
        return TestResult::Fail("the directory's access ACL and mode did not survive a remount");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs/dir-xattr",
    smoke_btrfs_directory_xattrs_and_acls_follow_btrfs_set_acl
);

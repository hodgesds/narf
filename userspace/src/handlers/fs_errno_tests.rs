//! The errnos a damaged or limit-bound filesystem reports, through each
//! syscall's mapper: Linux's EFSCORRUPTED (EUCLEAN), EFSBADCRC (EBADMSG),
//! EMLINK and ENAMETOOLONG, never the mapper's fallback.
use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::errno::{EBADMSG, EMLINK, ENAMETOOLONG, EUCLEAN};

fn smoke_fs_integrity_errnos_reach_userspace() -> TestResult {
    let general = [
        (FsError::TooManyLinks, EMLINK),
        (FsError::Corrupted, EUCLEAN),
        (FsError::BadChecksum, EBADMSG),
        (FsError::NameTooLong, ENAMETOOLONG),
    ];
    for (error, errno) in general {
        if super::copy_fs_errno(error) != errno {
            return TestResult::Fail("copy_fs_errno lost a filesystem errno");
        }
    }
    // unlink(2), rmdir(2) and rename(2) fall back to EPERM; a damaged
    // directory must not read as "operation not permitted".
    for (error, errno) in [
        (FsError::Corrupted, EUCLEAN),
        (FsError::BadChecksum, EBADMSG),
    ] {
        let want = (-errno) as u64;
        if super::unlink_errno(error) != want
            || super::rmdir_errno(error) != want
            || super::rename_errno(error) != want
        {
            return TestResult::Fail("a namespace mapper hid EUCLEAN/EBADMSG behind EPERM");
        }
        if crate::mount_api::mount_error_errno(error) != errno {
            return TestResult::Fail("mount(2) hid EUCLEAN/EBADMSG behind EINVAL");
        }
    }
    if super::rename_errno(FsError::TooManyLinks) != (-EMLINK) as u64 {
        return TestResult::Fail("ext4_rename's EMLINK must reach rename(2)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/fs-errno",
    smoke_fs_integrity_errnos_reach_userspace
);

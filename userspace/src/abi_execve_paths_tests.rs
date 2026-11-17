//! Exec pathname failures in the installed-root view used by distro boots.
#![cfg(feature = "kernel-test")]

use crate::abi_test_support::*;

fn rooted(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    with_memfs("/abi-exec-root", "exec-paths", &[("file", b"")], || {
        if !crate::handlers::install_root_dir(FAKE_TASK, "/abi-exec-root/") {
            return Err("installed-root fixture failed");
        }
        body()
    })
}

fn execve_empty_path_in_installed_root_is_enoent() -> TestResult {
    rooted(|| {
        let empty = b"\0";
        if call(Syscall::Execve.raw(), a2(empty.as_ptr() as u64, 0, 0)) != Some(ENOENT) {
            return Err("empty execve pathname became the installed root instead of ENOENT");
        }
        // AT_EMPTY_PATH belongs to execveat; its directory-anchor behavior
        // must remain distinct from execve's empty filename.
        for (flags, expected) in [(0, ENOENT), (0x1000, EACCES)] {
            if call(
                Syscall::Execveat.raw(),
                a4((-100i64) as u64, empty.as_ptr() as u64, 0, 0, flags),
            ) != Some(expected)
            {
                return Err("execveat empty-path semantics changed");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_empty_path_in_installed_root_is_enoent
);

fn execve_directory_in_installed_root_is_eacces() -> TestResult {
    rooted(|| {
        let dir = b"/dir\0";
        if call(Syscall::Mkdir.raw(), a1(dir.as_ptr() as u64, 0o755)) != Some(0) {
            return Err("directory fixture failed");
        }
        for path in [
            &b"/\0"[..],
            &b".\0"[..],
            &b"./\0"[..],
            &b"/dir\0"[..],
            &b"/dir/\0"[..],
            &b"/dir/.\0"[..],
            &b"/dir/..\0"[..],
        ] {
            let result = call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0));
            if result != Some(EACCES) {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "exec directory {path:?}: {result:?}");
                return Err("executing a directory reported an I/O or executable-format error");
            }
        }
        if call(
            Syscall::Execveat.raw(),
            a4((-100i64) as u64, dir.as_ptr() as u64, 0, 0, 0),
        ) != Some(EACCES)
        {
            return Err("execveat did not share directory rejection");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_directory_in_installed_root_is_eacces
);

fn execve_empty_file_in_installed_root_is_enoexec() -> TestResult {
    rooted(|| {
        let path = b"/file\0";
        if call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) != Some(ENOEXEC) {
            return Err("execve /file did not return ENOEXEC");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_empty_file_in_installed_root_is_enoexec
);

fn execve_missing_path_in_installed_root_is_enoent() -> TestResult {
    rooted(|| {
        let path = b"/missing\0";
        if call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) != Some(ENOENT) {
            return Err("execve /missing did not return ENOENT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_missing_path_in_installed_root_is_enoent
);

fn execve_file_trailing_slash_in_installed_root_is_enotdir() -> TestResult {
    rooted(|| {
        let path = b"/file/\0";
        if call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) != Some(ENOTDIR) {
            return Err("execve /file/ did not return ENOTDIR");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_file_trailing_slash_in_installed_root_is_enotdir
);

fn execve_missing_under_file_in_installed_root_is_enotdir() -> TestResult {
    rooted(|| {
        let path = b"/file/missing\0";
        if call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) != Some(ENOTDIR) {
            return Err("execve /file/missing did not return ENOTDIR");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_missing_under_file_in_installed_root_is_enotdir
);

fn execve_self_symlink_in_installed_root_is_eloop() -> TestResult {
    rooted(|| {
        let loop_name = b"/loop\0";
        if call(
            Syscall::Symlinkat.raw(),
            a2(
                loop_name.as_ptr() as u64,
                (-100i64) as u64,
                loop_name.as_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("symlink-loop fixture failed");
        }
        if call(Syscall::Execve.raw(), a2(loop_name.as_ptr() as u64, 0, 0)) != Some(ELOOP) {
            return Err("execve /loop did not return ELOOP");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/exec_path",
    execve_self_symlink_in_installed_root_is_eloop
);

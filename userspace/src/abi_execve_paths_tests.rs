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

fn execve_path_errors_remain_distinct() -> TestResult {
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
        for (path, expected) in [
            (&b"/file\0"[..], ENOEXEC),
            (&b"/missing\0"[..], ENOENT),
            (&b"/file/\0"[..], ENOTDIR),
            (&b"/file/missing\0"[..], ENOTDIR),
            (&loop_name[..], ELOOP),
        ] {
            if call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) != Some(expected) {
                return Err("exec lookup lost its specific Linux errno");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/exec_path", execve_path_errors_remain_distinct);

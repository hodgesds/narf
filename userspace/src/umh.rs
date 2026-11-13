//! Usermode helper — Linux `kernel/umh.c::call_usermodehelper(path, argv,
//! envp, UMH_WAIT_EXEC)`.
//!
//! Linux starts the helper from a kernel worker as a child of `kthreadd`
//! (`CLONE_PARENT`), with full root credentials, `kthreadd`'s filesystem
//! context (`init_fs`: the system root) and the initial namespaces, and
//! `UMH_WAIT_EXEC` returns once `kernel_execve` has succeeded or failed.
//! NARF mirrors that:
//!
//! - the program is resolved and loaded under PID 1's root (the installed
//!   distro root a `systemd_pid1` boot runs in; the global root otherwise),
//!   in the initial mount namespace, with root credentials;
//! - the process has no parent, so it is reaped by the kernel when it exits,
//!   as `kthreadd`'s children are;
//! - the call returns `Ok` once the image is loaded and the task published,
//!   `Err(errno)` if it could not be: `ENOENT` for a missing program,
//!   `ENOEXEC` for one that is not a loadable executable, `EAGAIN` with no
//!   free pid.
//!
//! The only user is `narf_power`'s orderly power-off (`run_cmd`), installed
//! by [`crate::handlers::wait_init`].

use alloc::string::String;

use crate::process::{load_user_process_from_path, resolve_exec_file};

const ENOENT: i32 = 2;
const EAGAIN: i32 = 11;
const ENOEXEC: i32 = 8;

/// PID 1's filesystem root (`None` = the global root): the root a helper
/// runs in, as Linux's runs in `init_fs`.
fn init_root() -> Option<String> {
    let init_task = crate::handlers::pid_to_task_raw(1)?;
    crate::handlers::root_dir_of(init_task).filter(|r| r != "/")
}

/// `path` as the kernel resolves it for a task whose root is `root`.
fn rooted_path(root: Option<&str>, path: &str) -> String {
    // `kernel_execve` of a relative path resolves against the helper's cwd,
    // which is the root.
    let path = path.trim_start_matches('/');
    match root {
        Some(r) => alloc::format!("{}/{}", r.trim_end_matches('/'), path),
        None => alloc::format!("/{path}"),
    }
}

/// Resolve and load `argv[0]` under `root` without publishing a task: the
/// part of the helper that can fail. The caller owns the returned process
/// (and its pid).
pub(crate) fn load_helper(
    argv: &[&str],
    envp: &[&str],
    root: Option<&str>,
) -> Result<crate::UserProcess, i32> {
    let program = argv.first().ok_or(ENOENT)?;
    let path = rooted_path(root, program);
    if resolve_exec_file(&path).is_none() {
        return Err(ENOENT);
    }
    let pid = crate::alloc_pid();
    if pid == crate::ProcessId::KERNEL {
        return Err(EAGAIN);
    }
    // SAFETY: called from task context after boot: the loader's identity
    // mapping and frame allocator are live, as for every execve.
    match unsafe { load_user_process_from_path(&path, argv, envp, &[], root, pid) } {
        Ok(p) => Ok(p),
        Err(_) => {
            crate::release_pid(pid);
            Err(ENOEXEC)
        }
    }
}

/// `call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC)`: start the
/// helper and return once it runs. The [`narf_power::orderly::UsermodeHelper`]
/// installed into the power crate.
pub fn call_usermodehelper_exec(argv: &[&str], envp: &[&str]) -> Result<(), i32> {
    use core::fmt::Write as _;
    let root = init_root();
    let process = match load_helper(argv, envp, root.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "umh: could not start {}: errno {e}",
                argv.first().copied().unwrap_or("")
            );
            return Err(e);
        }
    };
    let pid = process.pid;
    let pending = crate::user_task::prepare_user_process_initial(
        process,
        narf_scheduler::TaskSpec::user_task(),
    );
    let tid = pending.task_id();
    if let Some(r) = root.as_deref() {
        if !crate::handlers::install_root_dir(tid.raw(), r) {
            drop(pending);
            crate::release_pid(pid);
            return Err(ENOENT);
        }
    }
    crate::handlers::register_pid_task_mapping(pid.raw(), tid.raw());
    #[cfg(feature = "cgroup")]
    narf_filesystem::cgroupfs::attach_to_root(pid.raw());
    crate::handlers::set_proc_argv(tid.raw(), argv);
    let comm = argv[0].rsplit('/').next().unwrap_or(argv[0]);
    crate::handlers::set_proc_comm(tid.raw(), comm);
    pending.spawn();
    let _ = writeln!(
        narf_console::Writer,
        "umh: started {} pid={}",
        argv[0],
        pid.raw()
    );
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use crate::abi_test_support::with_memfs;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A minimal static executable: `exit_group(0)`.
    fn exit_elf() -> alloc::vec::Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        const CODE: &[u8] = &[
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231
            0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
        ];
        #[cfg(target_arch = "x86_64")]
        const MACHINE: u16 = 62;
        #[cfg(target_arch = "aarch64")]
        const CODE: &[u8] = &[
            0xa8, 0x0b, 0x80, 0xd2, // mov x8, #94
            0x00, 0x00, 0x80, 0xd2, // mov x0, #0
            0x01, 0x00, 0x00, 0xd4, // svc #0
        ];
        #[cfg(target_arch = "aarch64")]
        const MACHINE: u16 = 183;
        const VA: u64 = 0x40_0000;
        let mut b = alloc::vec![0u8; 0x1000 + CODE.len()];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&MACHINE.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&(VA + 0x1000).to_le_bytes()); // e_entry
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let ph = 64usize;
        let len = b.len() as u64;
        b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        b[ph + 0x10..ph + 0x18].copy_from_slice(&VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&len.to_le_bytes()); // p_filesz
        b[ph + 0x28..ph + 0x30].copy_from_slice(&len.to_le_bytes()); // p_memsz
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        b[0x1000..].copy_from_slice(CODE);
        b
    }

    /// The helper resolves its program under PID 1's root, as Linux's runs
    /// in `init_fs`: `/sbin/poweroff` in a root at `/umh-root` is
    /// `/umh-root/sbin/poweroff`. A missing program is `ENOENT` and a file
    /// that is not an executable `ENOEXEC` — the failures that send a forced
    /// orderly power-off to its emergency fallback.
    fn smoke_umh_resolves_under_init_root() -> TestResult {
        let elf = exit_elf();
        with_memfs(
            "/umh-root",
            "umh-root",
            &[("poweroff", &elf), ("notelf", b"#!nothing here\n")],
            || {
                let envp = narf_power::orderly::HELPER_ENVP;
                let loaded = super::load_helper(&["/poweroff"], &envp, Some("/umh-root"));
                let ok = match loaded {
                    Ok(p) => {
                        let pid = p.pid;
                        drop(p);
                        crate::release_pid(pid);
                        true
                    }
                    Err(_) => false,
                };
                if !ok {
                    return Err("an executable under the init root did not load");
                }
                // The same name outside the root does not exist.
                if super::load_helper(&["/poweroff"], &envp, None).err() != Some(super::ENOENT) {
                    return Err("the helper resolved outside the init root");
                }
                if super::load_helper(&["/missing"], &envp, Some("/umh-root")).err()
                    != Some(super::ENOENT)
                {
                    return Err("a missing helper must be ENOENT");
                }
                if super::load_helper(&["/notelf"], &envp, Some("/umh-root")).err()
                    != Some(super::ENOEXEC)
                {
                    return Err("a non-executable helper must be ENOEXEC");
                }
                if super::load_helper(&[], &envp, Some("/umh-root")).err() != Some(super::ENOENT) {
                    return Err("an empty argv must be ENOENT");
                }
                Ok(())
            },
        )
    }
    kernel_test_in!("userspace/umh", smoke_umh_resolves_under_init_root);

    /// `wait_init` installs this helper into the power crate: without it the
    /// orderly power-off cannot run the poweroff command and a power-button
    /// press with no logind would do nothing.
    fn smoke_umh_installed_by_wait_init() -> TestResult {
        crate::handlers::wait_init();
        let installed = narf_power::orderly::__swap_usermode_helper_for_test(None);
        if let Some(h) = installed {
            narf_power::orderly::install_usermode_helper(h);
        }
        let expected: narf_power::orderly::UsermodeHelper = super::call_usermodehelper_exec;
        if installed.map(|h| h as usize) != Some(expected as usize) {
            return TestResult::Fail("wait_init did not install the usermode helper");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace/umh", smoke_umh_installed_by_wait_init);
}

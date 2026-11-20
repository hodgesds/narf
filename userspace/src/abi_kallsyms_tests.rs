//! `/proc/kallsyms` and `kernel.kptr_restrict` through the real syscall path,
//! with real credentials.
//!
//! The filesystem-level cases (`filesystem/src/procfs/kallsyms_tests.rs`)
//! drive the opener's privilege through the `caller_capable` hook; these
//! drop and regain CAP_SYSLOG on the calling task itself, so they also prove
//! that `open(2)` asks about the task that is opening, and that `read(2)`
//! does not ask again.
//!
//! Linux refs: `kernel/kallsyms.c::kallsyms_open` (`file->f_cred`),
//! `kernel/ksyms_common.c::kallsyms_show_value`,
//! `kernel/printk/sysctl.c` (`kptr_restrict`, `proc_dointvec_minmax_sysadmin`).

use alloc::vec::Vec;

use crate::abi_test_support::*;

const KALLSYMS: &[u8] = b"/proc/kallsyms\0";
const KPTR_RESTRICT: &[u8] = b"/proc/sys/kernel/kptr_restrict\0";

const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYSLOG: u64 = 1 << 34;
const ALL_CAPS: u64 = u64::MAX;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;

fn set_caps(caps: u64) {
    crate::handlers::__test_set_caps(FAKE_TASK, caps, caps);
}

fn open(path: &[u8], flags: u64) -> Result<i64, &'static str> {
    match call_open(path.as_ptr() as u64, flags) {
        Some(fd) if fd >= 0 => Ok(fd),
        _ => Err("open failed"),
    }
}

fn close(fd: i64) {
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
}

/// `read(2)` the first 16 KiB of `fd`.
fn read_head(fd: i64) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while out.len() < 16 * 1024 {
        let n = call(
            Syscall::Read.raw(),
            a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        )
        .ok_or("read failed")?;
        if n < 0 {
            return Err("read returned an error");
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    Ok(out)
}

/// The address column of every complete line.
fn addresses(body: &[u8]) -> Vec<u64> {
    let text = core::str::from_utf8(body).unwrap_or("");
    let complete = &text[..text.rfind('\n').map_or(0, |i| i + 1)];
    complete
        .lines()
        .filter_map(|l| u64::from_str_radix(l.get(..16)?, 16).ok())
        .collect()
}

/// `write(2)` `value` into `kernel.kptr_restrict`; the raw return.
fn write_kptr_restrict(value: &[u8]) -> Result<i64, &'static str> {
    let fd = open(KPTR_RESTRICT, O_WRONLY)?;
    let r = call(
        Syscall::Write.raw(),
        a2(fd as u64, value.as_ptr() as u64, value.len() as u64),
    )
    .ok_or("write did not return");
    close(fd);
    r
}

/// Puts the boot policy back even when a case fails part-way.
struct RestorePolicy;
impl Drop for RestorePolicy {
    fn drop(&mut self) {
        set_caps(ALL_CAPS);
        let _ = write_kptr_restrict(b"2\n");
    }
}

/// The opener's credentials decide, once, at open.
///
/// With `kptr_restrict = 1`: a descriptor opened holding CAP_SYSLOG shows
/// addresses even when read after the task dropped it, and one opened
/// without CAP_SYSLOG shows zeros even when read after the task regained it.
fn smoke_abi_kallsyms_show_value_follows_the_opener() -> TestResult {
    with_setup(|| {
        let _restore = RestorePolicy;
        if write_kptr_restrict(b"1\n")? != 2 {
            return Err("CAP_SYS_ADMIN write of kptr_restrict=1 failed");
        }

        let privileged_fd = open(KALLSYMS, O_RDONLY)?;
        set_caps(ALL_CAPS & !CAP_SYSLOG);
        let unprivileged_fd = open(KALLSYMS, O_RDONLY)?;

        // Read the privileged descriptor while unprivileged...
        let a = addresses(&read_head(privileged_fd)?);
        set_caps(ALL_CAPS);
        // ...and the unprivileged one while privileged.
        let b = addresses(&read_head(unprivileged_fd)?);
        close(privileged_fd);
        close(unprivileged_fd);

        if a.is_empty() || b.is_empty() {
            return Err("/proc/kallsyms read back no lines");
        }
        if a.contains(&0) {
            return Err("dropping CAP_SYSLOG after open hid addresses from a privileged fd");
        }
        if b.iter().any(|&v| v != 0) {
            return Err("regaining CAP_SYSLOG after open exposed addresses on an unprivileged fd");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/kallsyms",
    smoke_abi_kallsyms_show_value_follows_the_opener
);

/// The boot default hides every address from every reader, CAP_SYSLOG or
/// not, and only CAP_SYS_ADMIN can change that.
fn smoke_abi_kallsyms_default_hides_and_sysctl_is_sysadmin() -> TestResult {
    with_setup(|| {
        let _restore = RestorePolicy;
        // Default (2): zeros even for a fully privileged opener.
        let fd = open(KALLSYMS, O_RDONLY)?;
        let v = addresses(&read_head(fd)?);
        close(fd);
        if v.is_empty() || v.iter().any(|&a| a != 0) {
            return Err("kptr_restrict=2 showed an address to a privileged reader");
        }
        // A root-uid task without CAP_SYS_ADMIN cannot loosen it: the file's
        // owner write bit admits the open, the capability check refuses the
        // write.
        set_caps(ALL_CAPS & !CAP_SYS_ADMIN);
        if write_kptr_restrict(b"0\n")? != EPERM {
            return Err("kptr_restrict write without CAP_SYS_ADMIN was not EPERM");
        }
        set_caps(ALL_CAPS);
        let fd = open(KALLSYMS, O_RDONLY)?;
        let v = addresses(&read_head(fd)?);
        close(fd);
        if v.iter().any(|&a| a != 0) {
            return Err("a refused kptr_restrict write still changed the policy");
        }
        if write_kptr_restrict(b"3\n")? != EINVAL {
            return Err("kptr_restrict=3 was not EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/kallsyms",
    smoke_abi_kallsyms_default_hides_and_sysctl_is_sysadmin
);

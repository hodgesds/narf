//! Linux syscall ABI conformance — inode identity `(st_dev, st_ino)`.
//!
//! On Linux every file has an inode on some superblock, and the pair names
//! it: nonzero, the same for every stat/fstat of the same file, and
//! different for different files. These drive the real `newfstatat` /
//! `openat` + `fstat` handlers against procfs, sysfs and a mount root.
//! Positive cases pin "same file ⇒ same pair"; negative cases pin
//! "different file ⇒ different pair", which a constant (or all-zero)
//! identity would pass vacuously on the positive side alone.

use crate::abi_test_support::*;

const AT_FDCWD: u64 = (-100i64) as u64;

/// `(st_dev, st_ino)` of `path` via `newfstatat(AT_FDCWD, path, 0)`.
fn stat_id(path: &[u8]) -> Result<(u64, u64), &'static str> {
    let mut sb = [0u8; 144];
    match call(
        Syscall::Newfstatat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, sb.as_mut_ptr() as u64, 0),
    ) {
        Some(0) => Ok((
            u64::from_ne_bytes(sb[0..8].try_into().unwrap()),
            u64::from_ne_bytes(sb[8..16].try_into().unwrap()),
        )),
        _ => Err("newfstatat failed"),
    }
}

/// `(st_dev, st_ino)` of `fstat(open(path, O_RDONLY))`.
fn fstat_id(path: &[u8]) -> Result<(u64, u64), &'static str> {
    let fd = match call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
    ) {
        Some(fd) if fd >= 0 => fd as u64,
        _ => return Err("openat failed"),
    };
    let mut sb = [0u8; 144];
    let rc = call(Syscall::Fstat.raw(), a1(fd, sb.as_mut_ptr() as u64));
    let _ = call(Syscall::Close.raw(), a0(fd));
    if rc != Some(0) {
        return Err("fstat failed");
    }
    Ok((
        u64::from_ne_bytes(sb[0..8].try_into().unwrap()),
        u64::from_ne_bytes(sb[8..16].try_into().unwrap()),
    ))
}

fn nonzero(id: (u64, u64), what: &'static str) -> Result<(), &'static str> {
    if id.0 == 0 || id.1 == 0 {
        return Err(what);
    }
    Ok(())
}

// ── procfs ────────────────────────────────────────────────────────────

/// Two stats of one procfs file are the same inode, on a real procfs
/// superblock; the open fd agrees with the path.
fn smoke_abi_inode_proc_file_stable() -> TestResult {
    with_setup(|| {
        let path = b"/proc/meminfo\0";
        let a = stat_id(path)?;
        nonzero(a, "/proc/meminfo: st_dev or st_ino is 0")?;
        if stat_id(path)? != a {
            return Err("/proc/meminfo: two stats report different inodes");
        }
        if fstat_id(path)? != a {
            return Err("/proc/meminfo: fstat of an open fd differs from stat");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_inode_proc_file_stable);

/// Different procfs files are different inodes — at the top level and
/// under a pid directory — and share the one procfs `st_dev`.
fn smoke_abi_inode_proc_files_distinct() -> TestResult {
    with_setup(|| {
        let meminfo = stat_id(b"/proc/meminfo\0")?;
        let cpuinfo = stat_id(b"/proc/cpuinfo\0")?;
        if meminfo.1 == cpuinfo.1 {
            return Err("/proc/meminfo and /proc/cpuinfo share an st_ino");
        }
        if meminfo.0 != cpuinfo.0 {
            return Err("two procfs files report different st_dev");
        }
        let stat = stat_id(b"/proc/self/stat\0")?;
        let status = stat_id(b"/proc/self/status\0")?;
        nonzero(stat, "/proc/self/stat: st_dev or st_ino is 0")?;
        if stat.1 == status.1 {
            return Err("/proc/self/stat and /proc/self/status share an st_ino");
        }
        let root = stat_id(b"/\0")?;
        if root.0 == meminfo.0 {
            return Err("procfs shares its st_dev with the root filesystem");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_inode_proc_files_distinct);

/// `/proc/self` resolves to the inode of `/proc/<pid>` (Linux follows the
/// link into the one per-process directory), for the directory and a file
/// in it; the open directory fd agrees.
fn smoke_abi_inode_proc_self_is_pid_dir() -> TestResult {
    with_setup(|| {
        let pid = match call(Syscall::GetPid.raw(), a0(0)) {
            Some(p) if p > 0 => p,
            _ => return Err("getpid failed"),
        };
        let mut dir = alloc::format!("/proc/{}", pid).into_bytes();
        let mut status = dir.clone();
        status.extend_from_slice(b"/status\0");
        dir.push(0);
        let self_dir = stat_id(b"/proc/self\0")?;
        nonzero(self_dir, "/proc/self: st_dev or st_ino is 0")?;
        if stat_id(&dir)? != self_dir {
            return Err("/proc/self and /proc/<pid> report different inodes");
        }
        if fstat_id(b"/proc/self\0")? != self_dir {
            return Err("fstat(open(/proc/self)) differs from stat(/proc/self)");
        }
        if stat_id(&status)? != stat_id(b"/proc/self/status\0")? {
            return Err("/proc/self/status and /proc/<pid>/status differ");
        }
        // And the per-process directory is not its parent.
        if stat_id(b"/proc\0")? == self_dir {
            return Err("/proc/<pid> reports the inode of /proc");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_inode_proc_self_is_pid_dir);

// ── sysfs ─────────────────────────────────────────────────────────────

/// A sysfs directory is one stable inode (path and open fd agree); two
/// directories differ.
fn smoke_abi_inode_sysfs_dirs() -> TestResult {
    // Self-contained: other tests may leave /sys unmounted or the kobject
    // tree pruned, so create the two directories and mount a private sysfs
    // instance (sysfs is one tree, so any mount shows the same kobjects).
    let root = narf_filesystem::sysfs::sysfs_root();
    let _ = narf_filesystem::sysfs::get_or_create_child(&root, "kernel");
    let _ = narf_filesystem::sysfs::get_or_create_child(&root, "class");
    setup();
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, "/iidsys", narf_filesystem::SysFs::new()) {
        Ok(h) => h,
        Err(_) => {
            teardown();
            return TestResult::Fail("sysfs mount failed");
        }
    };
    let outcome = crate::handlers::with_kernel_buffers(|| {
        let kernel = stat_id(b"/iidsys/kernel\0")?;
        nonzero(kernel, "/sys/kernel: st_dev or st_ino is 0")?;
        if stat_id(b"/iidsys/kernel\0")? != kernel {
            return Err("/sys/kernel: two stats report different inodes");
        }
        if fstat_id(b"/iidsys/kernel\0")? != kernel {
            return Err("/sys/kernel: fstat of an open fd differs from stat");
        }
        let class = stat_id(b"/iidsys/class\0")?;
        if class.1 == kernel.1 || class.0 != kernel.0 {
            return Err("/sys/class and /sys/kernel: same st_ino or different st_dev");
        }
        Ok(())
    });
    let _ = registry().unmount(&handle, "/iidsys");
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
kernel_test_in!("syscall_abi", smoke_abi_inode_sysfs_dirs);

// ── mount roots ───────────────────────────────────────────────────────

/// `stat` of a mount point and `fstat` of the directory opened there both
/// describe the mounted filesystem's root — Linux crosses into the mount
/// for both. The mount's files are different inodes on the same device.
fn smoke_abi_inode_mount_root_stat_matches_fstat() -> TestResult {
    with_memfs("/iid", "iid", &[("f", b"x")], || {
        let root = stat_id(b"/iid\0")?;
        nonzero(root, "/iid: st_dev or st_ino is 0")?;
        if fstat_id(b"/iid\0")? != root {
            return Err("fstat(open(mount root)) differs from stat(mount root)");
        }
        let file = stat_id(b"/iid/f\0")?;
        if file.1 == root.1 || file.0 != root.0 {
            return Err("a file in the mount shares the root's st_ino or not its st_dev");
        }
        if fstat_id(b"/iid/f\0")? != file {
            return Err("fstat of a file in the mount differs from stat");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_inode_mount_root_stat_matches_fstat);

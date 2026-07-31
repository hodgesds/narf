//! `/proc` arch-divergence policy stubs.
//!
//! These keys must exist so standard tools don't crash on open/read, but
//! they return fixed stub values because the corresponding Linux subsystem
//! has no NARF equivalent.  Each entry documents the canonical Linux
//! semantics and what to do when the subsystem is eventually added.
//!
//! Stubs in this file:
//!
//! | path                               | value     | reason |
//! |------------------------------------|-----------|--------|
//! | /proc/cgroups                      | hdr/live  | controller list when enabled |
//! | /proc/keys                         | ""        | no keyring subsystem |
//! | /proc/key-users                    | ""        | no keyring subsystem |
//! | /proc/sys/kernel/ns_last_pid       | "0\n"     | no PID namespaces in this build |
//! | /proc/sys/kernel/keys/maxkeys      | "200\n"   | no keyring subsystem |
//! | /proc/sys/user/max_user_namespaces | "0\n"     | no user namespaces in this build |
//! | /proc/sys/user/max_pid_namespaces  | "0\n"     | no PID namespaces in this build |
//! | /proc/sys/user/max_net_namespaces  | "0\n"     | no network namespaces in this build |
//! | /proc/sys/user/max_mnt_namespaces  | "0\n"     | no mount namespaces in this build |
//! | /proc/sys/user/max_ipc_namespaces  | "0\n"     | no IPC namespaces in this build |
//! | /proc/sys/user/max_uts_namespaces  | "0\n"     | no UTS namespaces in this build |
//! | /proc/sys/user/max_cgroup_namespaces | "0\n"   | no cgroup namespaces in this build |
//!
//! NOTE: `/proc/<pid>/cgroup`, `/proc/<pid>/personality`, and
//! `/proc/<pid>/wchan` are per-task stubs that live in `pid_ext.rs`
//! because they are served through the per-pid `DirOps` path.
//!
//! NOTE: `/proc/sys/kernel/modprobe` is implemented in `sys_kernel.rs`
//! and is intentionally NOT duplicated here.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::sys::{register_sysctl, SysctlEntry};
use super::{register_proc, ProcFile};

// ── /proc/cgroups ────────────────────────────────────────────────
//
// Linux: this file lists every cgroup subsystem (cpu, memory, …) with
// its hierarchy ID, number of cgroups, and enabled flag.
// NARF has no cgroup hierarchy. We emit the header line only so parsers
// that check for the file's presence (systemd, Docker, runc) don't see
// ENOENT.  When a cgroupfs is added, replace this with a renderer that
// walks the real subsystem table.

#[derive(Debug)]
struct CgroupsFile;

impl ProcFile for CgroupsFile {
    fn read(&self) -> Vec<u8> {
        // Header only — no subsystem entries.
        // Linux ref: kernel/cgroup/cgroup.c::proc_cgroupstats_show.
        // With the cgroup feature this routes through cgroupfs (which
        // lists available controllers — none in the base feature, so
        // the output is identical until a controller sub-feature lands).
        #[cfg(feature = "cgroup")]
        {
            crate::cgroupfs::proc_cgroups()
        }
        #[cfg(not(feature = "cgroup"))]
        {
            b"#subsys_name\thierarchy\tnum_cgroups\tenabled\n".to_vec()
        }
    }
}

// ── /proc/keys ──────────────────────────────────────────────────
//
// Linux: lists every key held by the calling task's keyring, one per
// line. NARF has no keyring subsystem (security/keys/).  Return empty
// so tools that cat this file get a clean result rather than ENOENT.
// When the keyring subsystem lands, replace with a real renderer.

#[derive(Debug)]
struct KeysFile;

impl ProcFile for KeysFile {
    fn read(&self) -> Vec<u8> {
        // No keyring subsystem in NARF. Return empty (not ENOENT).
        // Linux ref: security/keys/proc.c::proc_keys_show.
        Vec::new()
    }
}

// ── /proc/key-users ─────────────────────────────────────────────
//
// Linux: lists per-uid keyring quota (nkeys/nikeys/qnkeys/qnbytes).
// NARF has no keyring subsystem. Return empty.
// When the keyring subsystem lands, replace with a real renderer.

#[derive(Debug)]
struct KeyUsersFile;

impl ProcFile for KeyUsersFile {
    fn read(&self) -> Vec<u8> {
        // No keyring subsystem in NARF. Return empty (not ENOENT).
        // Linux ref: security/keys/proc.c::proc_key_users_show.
        Vec::new()
    }
}

// ── /proc/sys/kernel/ns_last_pid ────────────────────────────────
//
// Linux: last PID allocated in the current PID namespace. Used by
// tools that tune PID recycling (e.g. sysbox-runc).  NARF has a flat
// pid space with no namespace layer today.  "0\n" is a safe sentinel.
// When PID namespaces land, surface the real last-allocated PID from
// the scheduler.

#[cfg(not(feature = "container"))]
fn read_ns_last_pid() -> String {
    // No PID namespaces in NARF; 0 is the sentinel for "not yet
    // allocated in any namespace".  Linux ref: kernel/pid.c::
    // proc_sys_last_pid (sysctl handler).
    String::from("0\n")
}

// ── /proc/sys/kernel/keys/maxkeys ───────────────────────────────
//
// Linux: per-uid limit on the number of keys that can be held in a
// keyring (default 200).  NARF has no keyring subsystem; expose the
// Linux default so tools that probe this sysctl don't get ENOENT.
// When the keyring subsystem lands, back this with a real atomic.

fn read_maxkeys() -> String {
    // Linux default is 200. NARF has no keyring subsystem; we expose
    // the default so probes don't get ENOENT.
    // Linux ref: security/keys/sysctl.c::key_quota_maxkeys.
    String::from("200\n")
}

// ── /proc/sys/user/* ────────────────────────────────────────────
//
// Linux: per-user limits on namespace counts. These are meaningful
// only when the corresponding namespace type exists in the kernel.
// NARF has no namespace layer (no user_ns, pid_ns, net_ns, mnt_ns,
// ipc_ns, uts_ns, cgroup_ns).  All limits are 0 — the correct value
// for a kernel that does not support the namespace type.
//
// When a namespace type is added, replace the corresponding fn with a
// real atomic-backed read/write handler and raise the limit.
//
// Linux ref: kernel/ucount.c::create_user_ns_sysctl_table.

#[cfg(not(feature = "container"))]
fn read_zero() -> String {
    String::from("0\n")
}

// ── Registration ─────────────────────────────────────────────────

/// Register every arch-divergence stub. Called once from boot init;
/// idempotent via `register_proc` / `register_sysctl` semantics.
pub fn register_all() {
    // /proc top-level files.
    register_proc("cgroups", Arc::new(CgroupsFile));
    register_proc("keys", Arc::new(KeysFile));
    register_proc("key-users", Arc::new(KeyUsersFile));

    // Do not publish a zero namespace limit in a container-enabled build:
    // zero means "disabled" to Linux userspace, while those namespaces are
    // actually usable. Until the namespace layer exposes authoritative
    // limits/high-water marks, absence is the honest older-kernel shape.
    #[cfg(not(feature = "container"))]
    {
        register_sysctl(SysctlEntry {
            path: "kernel/ns_last_pid",
            read: read_ns_last_pid,
            write: None,
            perms: 0o444,
        });
    }

    // /proc/sys/kernel/keys/maxkeys — no keyring subsystem.
    register_sysctl(SysctlEntry {
        path: "kernel/keys/maxkeys",
        read: read_maxkeys,
        write: None,
        perms: 0o444,
    });

    #[cfg(not(feature = "container"))]
    {
        register_sysctl(SysctlEntry {
            path: "user/max_user_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_pid_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_net_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_mnt_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_ipc_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_uts_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
        register_sysctl(SysctlEntry {
            path: "user/max_cgroup_namespaces",
            read: read_zero,
            write: None,
            perms: 0o444,
        });
    }
}

// ── Tests ─────────────────────────────────────────────────────────

use super::{lookup_registry, ProcNodeSnapshot};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_cgroups_header_only() -> TestResult {
    register_all();
    let snap = lookup_registry(&["cgroups"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let b = f.read();
            b.starts_with(b"#subsys_name") && !b[13..].contains(&b'\n'.wrapping_add(1))
                || b == b"#subsys_name\thierarchy\tnum_cgroups\tenabled\n"
        }
        _ => false,
    };
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/cgroups missing header")
    }
}
kernel_test_in!("filesystem/procfs/stubs", smoke_cgroups_header_only);

#[cfg(not(feature = "container"))]
fn smoke_sys_user_max_user_namespaces_zero() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "user", "max_user_namespaces"]);
    let ok = matches!(snap, Some(ProcNodeSnapshot::File(ref f)) if f.read() == b"0\n");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("max_user_namespaces did not return '0\\n'")
    }
}
#[cfg(not(feature = "container"))]
kernel_test_in!(
    "filesystem/procfs/stubs",
    smoke_sys_user_max_user_namespaces_zero
);

fn smoke_proc_keys_empty() -> TestResult {
    register_all();
    let snap = lookup_registry(&["keys"]);
    let ok = matches!(snap, Some(ProcNodeSnapshot::File(ref f)) if f.read().is_empty());
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/keys did not return empty body")
    }
}
kernel_test_in!("filesystem/procfs/stubs", smoke_proc_keys_empty);

fn smoke_sys_kernel_ns_last_pid_zero() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "kernel", "ns_last_pid"]);
    let ok = matches!(snap, Some(ProcNodeSnapshot::File(ref f)) if f.read() == b"0\n");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("ns_last_pid did not return '0\\n'")
    }
}
kernel_test_in!("filesystem/procfs/stubs", smoke_sys_kernel_ns_last_pid_zero);

fn smoke_sys_kernel_keys_maxkeys_200() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "kernel", "keys", "maxkeys"]);
    let ok = matches!(snap, Some(ProcNodeSnapshot::File(ref f)) if f.read() == b"200\n");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("maxkeys did not return '200\\n'")
    }
}
kernel_test_in!("filesystem/procfs/stubs", smoke_sys_kernel_keys_maxkeys_200);

fn smoke_proc_key_users_empty() -> TestResult {
    register_all();
    let snap = lookup_registry(&["key-users"]);
    let ok = matches!(snap, Some(ProcNodeSnapshot::File(ref f)) if f.read().is_empty());
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/key-users did not return empty body")
    }
}
kernel_test_in!("filesystem/procfs/stubs", smoke_proc_key_users_empty);

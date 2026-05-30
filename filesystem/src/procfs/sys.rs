//! `/proc/sys/*` sysctl framework.
//!
//! Sysctls are key-value tunables exposed under `/proc/sys/<path>`.
//! The framework sits on top of `procfs::register_proc`: each key
//! maps to one `ProcFile` registered at `"sys/<path>"`.
//!
//! ## Design
//!
//! `SysctlEntry` holds a read closure and an optional write closure
//! rather than a raw value cell so subsystems can back a key with any
//! live state (an `AtomicUsize`, a `Mutex<String>`, etc.) without
//! the framework needing to know the storage type.
//!
//! Linux ref: `kernel/sysctl.c` `ctl_table` array + `proc_dointvec` /
//! `proc_dostring` handlers; `fs/proc/proc_sysctl.c` registration.
//!
//! ## Permissions
//!
//! `perms` is a 9-bit Unix mode stored in the `SysctlEntry`. Read-only
//! keys use 0o444; writable keys use 0o644 by default. The framework
//! consults `writable` (i.e. `write_fn.is_some()`) when returning the
//! stat mode — no separate `perms` field is needed at the VFS layer
//! because `Mode::FILE_RO` / `Mode::FILE_RW` are sufficient for
//! Stage-3 consumers. The `perms` field on `SysctlEntry` is preserved
//! for future Stage-4 permission checks.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{register_proc, ProcFile};
use crate::FsError;

// ── Public entry descriptor ─────────────────────────────────────

/// One sysctl key descriptor. Pass to `register_sysctl`.
///
/// `path` is relative to `/proc/sys/`, e.g. `"kernel/hostname"`.
/// `read`  is called on every open.
/// `write` is `None` for read-only keys; for writable keys it
///         receives the trimmed string value from the write syscall
///         and returns `Ok(())` or an `FsError`.
/// `perms` is the 9-bit Unix permission word (0o444 r/o, 0o644 r/w).
pub struct SysctlEntry {
    pub path: &'static str,
    pub read: fn() -> String,
    pub write: Option<fn(&str) -> Result<(), FsError>>,
    pub perms: u16,
}

impl core::fmt::Debug for SysctlEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysctlEntry")
            .field("path", &self.path)
            .field("writable", &self.write.is_some())
            .field("perms", &self.perms)
            .finish()
    }
}

/// Register one sysctl key. The file appears at
/// `/proc/sys/<entry.path>`. Intermediate directories are created
/// automatically by the underlying `register_proc` machinery.
///
/// Idempotent: a second call at the same path replaces the first.
///
/// Linux ref: `register_sysctl_table` / `register_sysctl_paths`
/// in `kernel/sysctl.c`.
pub fn register_sysctl(entry: SysctlEntry) {
    let path = alloc::format!("sys/{}", entry.path.trim_matches('/'));
    register_proc(&path, Arc::new(SysctlProcFile {
        read_fn: entry.read,
        write_fn: entry.write,
    }));
}

// ── ProcFile adapter ─────────────────────────────────────────────

/// `ProcFile` adapter for a sysctl entry. Dispatches `read`/`write`
/// through the closures supplied to `register_sysctl`.
struct SysctlProcFile {
    read_fn: fn() -> String,
    write_fn: Option<fn(&str) -> Result<(), FsError>>,
}

impl core::fmt::Debug for SysctlProcFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysctlProcFile")
            .field("writable", &self.write_fn.is_some())
            .finish()
    }
}

impl ProcFile for SysctlProcFile {
    fn read(&self) -> Vec<u8> {
        (self.read_fn)().into_bytes()
    }

    fn writable(&self) -> bool {
        self.write_fn.is_some()
    }

    fn write(&self, buf: &[u8]) -> Result<usize, FsError> {
        let handler = match self.write_fn {
            Some(f) => f,
            None => return Err(FsError::ReadOnly),
        };
        // Convert the byte slice to UTF-8, stripping a trailing newline
        // if present (Linux userspace writes "value\n").
        let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
        let trimmed = s.trim_end_matches('\n').trim();
        handler(trimmed)?;
        Ok(buf.len())
    }
}

// ── Tests ────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::{lookup_registry, unregister_proc, ProcNodeSnapshot};

/// Register a read-only key and verify read returns the value.
fn smoke_sysctl_register_readonly_read() -> TestResult {
    static CALLS: IrqSafeSpinLock<u32> = IrqSafeSpinLock::new(0);
    fn read_fn() -> String {
        *CALLS.lock() += 1;
        String::from("hello\n")
    }
    let path = "sys/test/smoke_ro";
    register_sysctl(SysctlEntry {
        path: "test/smoke_ro",
        read: read_fn,
        write: None,
        perms: 0o444,
    });
    let snap = lookup_registry(&["sys", "test", "smoke_ro"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let bytes = f.read();
            bytes == b"hello\n"
        }
        _ => false,
    };
    unregister_proc(path);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("sysctl read-only key did not return expected value")
    }
}
kernel_test_in!("filesystem/procfs/sys", smoke_sysctl_register_readonly_read);

/// Register a writable key, write "42" → handler called with "42".
fn smoke_sysctl_writable_write_calls_handler() -> TestResult {
    static GOT: IrqSafeSpinLock<Option<String>> = IrqSafeSpinLock::new(None);
    fn read_fn() -> String {
        String::from("0\n")
    }
    fn write_fn(v: &str) -> Result<(), FsError> {
        *GOT.lock() = Some(v.to_string());
        Ok(())
    }
    let path = "sys/test/smoke_rw";
    register_sysctl(SysctlEntry {
        path: "test/smoke_rw",
        read: read_fn,
        write: Some(write_fn),
        perms: 0o644,
    });
    let snap = lookup_registry(&["sys", "test", "smoke_rw"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let result = f.write(b"42\n");
            result.is_ok() && GOT.lock().as_deref() == Some("42")
        }
        _ => false,
    };
    unregister_proc(path);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("sysctl writable write did not call handler with trimmed value")
    }
}
kernel_test_in!("filesystem/procfs/sys", smoke_sysctl_writable_write_calls_handler);

/// Writing to a read-only key returns FsError::ReadOnly.
fn smoke_sysctl_readonly_write_returns_error() -> TestResult {
    fn read_fn() -> String {
        String::from("42\n")
    }
    let path = "sys/test/smoke_ro_write";
    register_sysctl(SysctlEntry {
        path: "test/smoke_ro_write",
        read: read_fn,
        write: None,
        perms: 0o444,
    });
    let snap = lookup_registry(&["sys", "test", "smoke_ro_write"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            matches!(f.write(b"99\n"), Err(FsError::ReadOnly))
        }
        _ => false,
    };
    unregister_proc(path);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("read-only sysctl write did not return ReadOnly")
    }
}
kernel_test_in!("filesystem/procfs/sys", smoke_sysctl_readonly_write_returns_error);

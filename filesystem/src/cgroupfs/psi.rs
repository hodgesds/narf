//! Pressure Stall Information (PSI).
//!
//! Unlike the resource controllers, the `*.pressure` files are core v2
//! files present in every non-root cgroup (and `/proc/pressure/*`
//! system-wide) when PSI is enabled — they are not gated behind
//! `cgroup.subtree_control`. This module renders them; the core wires
//! the per-cgroup files (see `core_files_for` in `mod.rs`).
//!
//! SCAFFOLD: reports zero pressure in the exact v2 wire format. Real
//! stall-time accounting (tasks blocked on cpu/memory/io) is fed by
//! counters the scheduler/allocator/block layer update; that data
//! source lands in the PSI implementation pass.
//!
//! Linux ref: `kernel/sched/psi.c`,
//! `Documentation/accounting/psi.rst`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// PSI resource axis.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Cpu,
    Memory,
    Io,
}

impl Resource {
    /// The cgroup interface filename for this axis.
    pub fn file_name(self) -> &'static str {
        match self {
            Resource::Cpu => "cpu.pressure",
            Resource::Memory => "memory.pressure",
            Resource::Io => "io.pressure",
        }
    }
}

/// Render a pressure file's content for a cgroup axis.
///
/// `cpu` exposes only the `some` line; `memory`/`io` expose both
/// `some` and `full`.
pub fn render(resource: Resource) -> String {
    let some = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    let full = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    match resource {
        Resource::Cpu => {
            let mut s = String::from(some);
            // Modern kernels also expose cpu `full` (always 0 at the
            // system level for cpu, meaningful per-cgroup).
            s.push_str(full);
            s
        }
        Resource::Memory | Resource::Io => {
            let mut s = String::from(some);
            s.push_str(full);
            s
        }
    }
}

/// `/proc/pressure/<cpu|memory|io>` system-wide content.
pub fn proc_pressure(resource: Resource) -> alloc::vec::Vec<u8> {
    render(resource).into_bytes()
}

/// The per-cgroup pressure interface filenames (present in every
/// non-root cgroup when PSI is enabled).
pub fn file_names() -> &'static [&'static str] {
    &["cpu.pressure", "memory.pressure", "io.pressure"]
}

/// Resolve a pressure filename to a `FileOps`, if it is one.
///
/// Takes the owning `Cgroup`, not just its inode: a `*.pressure` file is
/// chownable like any other cgroup attribute file, and its owner has to
/// live somewhere that outlives this handle. It shares the cgroup's
/// `file_owners` map, keyed by this file's own inode.
pub fn pressure_file(name: &str, cg: &Arc<super::Cgroup>) -> Option<Arc<dyn FileOps>> {
    let (resource, stable_name) = match name {
        "cpu.pressure" => (Resource::Cpu, "cpu.pressure"),
        "memory.pressure" => (Resource::Memory, "memory.pressure"),
        "io.pressure" => (Resource::Io, "io.pressure"),
        _ => return None,
    };
    Some(Arc::new(PsiFile {
        resource,
        ino: super::cgroup_attr_ino(cg.ino, stable_name),
        cg: Arc::clone(cg),
    }))
}

/// A `*.pressure` interface file. Writable in Linux (poll triggers);
/// here read-only until trigger support lands.
#[derive(Debug)]
struct PsiFile {
    resource: Resource,
    ino: u64,
    /// Owning cgroup, for the shared `file_owners` map.
    cg: Arc<super::Cgroup>,
}

impl FileOps for PsiFile {
    // A `*.pressure` file must accept a chown like any other cgroup
    // attribute file. Inheriting the `Unsupported` FileOps default is what
    // left "Failed to adjust ownership of '.../memory.pressure', ignoring:
    // Operation not supported" in every boot — harmless where systemd says
    // "ignoring", fatal where it does not: `cg_set_access()` walks a
    // delegated subtree, so one rejecting file aborts delegation and
    // `systemd --user` exits 219/EXIT_CGROUP.
    fn owners(&self) -> (u32, u32) {
        self.cg
            .file_owners
            .lock()
            .get(&self.ino)
            .copied()
            .unwrap_or((0, 0))
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        self.cg.file_owners.lock().insert(self.ino, (uid, gid));
        Box::pin(async { Ok(()) })
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = render(self.resource);
        Box::pin(async move {
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let slice = &bytes[start..];
            let n = slice.len().min(buf.len());
            buf[..n].copy_from_slice(&slice[..n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // PSI pressure-trigger writes (poll) are not yet supported.
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    // chmod, for the same reason as `set_owners` above: systemd adjusts a
    // delegated subtree with `fchmod_and_chown()`, which chmods FIRST and
    // reports the failure as "Failed to adjust ownership of
    // '.../memory.pressure': Operation not supported". Leaving `set_perms`
    // at its `Unsupported` default is what kept that message in every boot
    // even after the ownership fix — the chown was never reached.
    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.cg.file_modes.lock().insert(self.ino, perms & 0o7777);
        Box::pin(async { Ok(()) })
    }

    fn stat(&self) -> Stat {
        let perms = self.cg.file_modes.lock().get(&self.ino).copied();
        match perms {
            Some(perms) => Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::File,
                    perms,
                },
                mtime_cycles: 0,
            },
            None => Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            },
        }
    }
}

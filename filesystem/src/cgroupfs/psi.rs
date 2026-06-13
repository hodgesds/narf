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

use crate::{FileOps, FsError, FsFuture, Mode, Stat};

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
pub fn pressure_file(name: &str) -> Option<Arc<dyn FileOps>> {
    let resource = match name {
        "cpu.pressure" => Resource::Cpu,
        "memory.pressure" => Resource::Memory,
        "io.pressure" => Resource::Io,
        _ => return None,
    };
    Some(Arc::new(PsiFile { resource }))
}

/// A `*.pressure` interface file. Writable in Linux (poll triggers);
/// here read-only until trigger support lands.
#[derive(Debug)]
struct PsiFile {
    resource: Resource,
}

impl FileOps for PsiFile {
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

    fn stat(&self) -> Stat {
        Stat {
            size: render(self.resource).len() as u64,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

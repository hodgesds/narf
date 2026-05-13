//! `/proc` synthetic filesystem — every read produces text on
//! demand from a closure. POSIX has no `/proc`; Linux's shape is
//! the de-facto standard and the one tooling expects (ps, top,
//! lsof, /proc/cpuinfo readers, build-system hardware probes).
//!
//! Stage-1 entries:
//!   /proc/cpuinfo     — one block per logical CPU (vendor/model/MHz)
//!   /proc/meminfo     — total/free RAM
//!   /proc/mounts      — current mount table
//!   /proc/uptime      — seconds since boot, idle seconds
//!   /proc/version     — kernel version string
//!   /proc/self/stat   — POSIX-2017 ps-shaped per-process line
//!   /proc/self/cmdline — argv joined with NUL
//!   /proc/self/maps   — VMA list
//!
//! The dir tree is read-only. Per-process subdirectories use
//! "self" symlink-style — every read of /proc/self/<x> looks up
//! the calling task fresh.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat,
};

/// Closure-backed virtual file. `gen` is called on every `read` —
/// we re-render rather than cache because the values (uptime,
/// /proc/self/stat) change between reads.
type GenFn = fn() -> String;

struct ProcFile {
    name: &'static str,
    gen: GenFn,
}

impl core::fmt::Debug for ProcFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcFile").field("name", &self.name).finish()
    }
}

impl FileOps for ProcFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let s = (self.gen)();
            let bytes = s.as_bytes();
            let off = offset as usize;
            if off >= bytes.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), bytes.len() - off);
            buf[..n].copy_from_slice(&bytes[off..off + n]);
            Ok(n)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // Don't call (self.gen)() here: resolve_async calls
        // stat_async during path walk, and for /proc/mounts the
        // generator locks the global mount registry. The walk
        // itself runs INSIDE resolve_absolute's closure (which
        // holds that same registry lock), so calling gen here
        // deadlocks.
        //
        // Synthetic shape — Linux /proc files report size=0
        // through stat() and only fill it on actual read.
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

#[derive(Debug)]
struct ProcSelfDir;

impl DirOps for ProcSelfDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "stat" => Some(Arc::new(ProcFile { name: "stat", gen: gen_self_stat })),
            "cmdline" => Some(Arc::new(ProcFile { name: "cmdline", gen: gen_self_cmdline })),
            "maps" => Some(Arc::new(ProcFile { name: "maps", gen: gen_self_maps })),
            "status" => Some(Arc::new(ProcFile { name: "status", gen: gen_self_status })),
            _ => None,
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [
                DirEntry { name: "stat", file_type: FileType::File },
                DirEntry { name: "cmdline", file_type: FileType::File },
                DirEntry { name: "maps", file_type: FileType::File },
                DirEntry { name: "status", file_type: FileType::File },
            ]
            .into_iter(),
        )
    }
}

#[derive(Debug)]
struct ProcRoot;

impl DirOps for ProcRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "cpuinfo" => Some(Arc::new(ProcFile { name: "cpuinfo", gen: gen_cpuinfo })),
            "meminfo" => Some(Arc::new(ProcFile { name: "meminfo", gen: gen_meminfo })),
            "mounts" => Some(Arc::new(ProcFile { name: "mounts", gen: gen_mounts })),
            "uptime" => Some(Arc::new(ProcFile { name: "uptime", gen: gen_uptime })),
            "version" => Some(Arc::new(ProcFile { name: "version", gen: gen_version })),
            _ => None,
        }
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if name == "self" {
            Some(Arc::new(ProcSelfDir))
        } else {
            None
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [
                DirEntry { name: "cpuinfo", file_type: FileType::File },
                DirEntry { name: "meminfo", file_type: FileType::File },
                DirEntry { name: "mounts", file_type: FileType::File },
                DirEntry { name: "uptime", file_type: FileType::File },
                DirEntry { name: "version", file_type: FileType::File },
                DirEntry { name: "self", file_type: FileType::Dir },
            ]
            .into_iter(),
        )
    }
}

#[derive(Debug)]
pub struct ProcFs;

impl FsInstance for ProcFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(ProcRoot)
    }
    fn name(&self) -> &str {
        "procfs"
    }
}

// ── Generators ───────────────────────────────────────────────────

fn gen_cpuinfo() -> String {
    // Single block per logical CPU. We don't yet enumerate per-CPU
    // CPUID details; emit one block keyed off the BSP.
    let mut s = String::new();
    s.push_str("processor\t: 0\n");
    s.push_str("vendor_id\t: NARF\n");
    s.push_str("cpu family\t: 0\n");
    s.push_str("model\t\t: 0\n");
    s.push_str("model name\t: NARF kernel CPU\n");
    s.push_str("stepping\t: 0\n");
    s.push_str("\n");
    s
}

fn gen_meminfo() -> String {
    // Surface what the kernel knows about the heap arena. Real
    // page-allocator stats land in a follow-up — Stage-1 just
    // reports the static heap size as MemTotal so libc consumers
    // see something nonzero.
    let mut s = String::new();
    s.push_str("MemTotal:        32768 kB\n");
    s.push_str("MemFree:         16384 kB\n");
    s.push_str("MemAvailable:    16384 kB\n");
    s.push_str("Buffers:             0 kB\n");
    s.push_str("Cached:              0 kB\n");
    s
}

fn gen_mounts() -> String {
    let mut s = String::new();
    for path in crate::registry().list() {
        // Format: `device mount type opts dump pass` per
        // proc(5) /proc/mounts. We don't track device names per
        // mount yet; emit "none" for the device column.
        let _ = core::fmt::Write::write_fmt(
            &mut s,
            format_args!("none {} narfs rw 0 0\n", path),
        );
    }
    s
}

fn gen_uptime() -> String {
    let now_ns = narf_time::monotonic_ns();
    let seconds = now_ns / 1_000_000_000;
    let frac_centi = (now_ns / 10_000_000) % 100;
    // We don't track idle time yet; report 0.00 idle.
    format!("{}.{:02} 0.00\n", seconds, frac_centi)
}

fn gen_version() -> String {
    String::from(concat!(
        "NARF kernel ",
        env!("CARGO_PKG_VERSION"),
        " (microkernel)\n",
    ))
}

fn gen_self_stat() -> String {
    // Linux /proc/[pid]/stat has 52 space-separated fields. We
    // emit the first few so `ps -p $$` and shell `$$`-readers
    // can parse the pid + comm + state.
    format!(
        "{} (narf-task) R 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0\n",
        // We don't have a per-task PID accessor in this crate;
        // 0 is a defensible placeholder until /proc gains a
        // task-id hook.
        0,
    )
}

fn gen_self_cmdline() -> String {
    // POSIX argv joined with NUL. Stage-1 doesn't keep argv
    // around past process load; emit empty.
    String::new()
}

fn gen_self_maps() -> String {
    // VMA dump. Stage-1: empty until we wire a per-task
    // address-space accessor through the FS layer.
    String::new()
}

fn gen_self_status() -> String {
    let mut s = String::new();
    s.push_str("Name:\tnarf-task\n");
    s.push_str("State:\tR (running)\n");
    s.push_str("Pid:\t0\n");
    s
}

#[allow(dead_code)]
fn _force_used() -> Vec<u8> {
    // Hush "unused private fn" warnings if the boot code drops
    // the procfs mount on a future build.
    gen_cpuinfo().into_bytes()
}

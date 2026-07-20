//! `/proc/pressure/{cpu,memory,io}` — Linux Pressure Stall Information
//! (PSI).
//!
//! Linux exposes a per-resource *pressure* view under `/proc/pressure`.
//! Each file reports the share of wall-clock time that tasks were
//! stalled waiting for that resource, as running averages over 10 s,
//! 60 s and 300 s windows, plus a `total` stall counter in
//! microseconds:
//!
//! ```text
//! some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//! full avg10=0.00 avg60=0.00 avg300=0.00 total=0
//! ```
//!
//! `cpu` has only the `some` line (a CPU is never "fully" stalled —
//! there is always a runnable task the moment one exists); `memory`
//! and `io` carry both `some` and `full`.
//!
//! NARF has no real pressure accounting, so every window and the
//! `total` read back as zero — which is exactly what an idle Linux box
//! reports. We deliberately do NOT fabricate an accounting subsystem;
//! all-zeros is a correct, unloaded-system answer.
//!
//! **Why this exists at all:** systemd's memory-pressure event source
//! opens `/proc/pressure/memory`, `write(2)`s a trigger threshold like
//! `some 150000 1000000\n`, then adds the fd to `epoll` waiting for
//! `EPOLLPRI`. On real Linux the fd becomes `EPOLLPRI`-ready when the
//! averaged pressure crosses the threshold. If the file is *absent*
//! (the pre-PSI NARF state) systemd logs
//! `Failed to establish memory pressure event source, ignoring: Bad
//! file descriptor` and disables the feature. So the fix is not to
//! model pressure — it is to make the fd *valid, writable, and
//! pollable-but-quiescent*:
//!
//!   * `read`  → the static all-zeros text above.
//!   * `write` → accept the trigger and return the byte count (never
//!     `-EINVAL`); we don't act on it because pressure never rises.
//!   * `poll`  → advertise `POLLOUT` only (writable), never `POLLIN`
//!     or `POLLPRI`, so an `EPOLLPRI` waiter parks forever on an idle
//!     system — the correct "threshold never crossed" behaviour.
//!
//! Linux ref: `kernel/sched/psi.c` (`psi_show`, `psi_trigger_create`)
//! and `Documentation/accounting/psi.rst`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::slice_read;
use crate::{DirEntry, DirOps, FileOps, FileType, FsFuture, Mode, Stat, POLL_OUT};

/// Which PSI resource a `/proc/pressure/*` node reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Resource {
    Cpu,
    Memory,
    Io,
}

impl Resource {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "cpu" => Some(Resource::Cpu),
            "memory" => Some(Resource::Memory),
            "io" => Some(Resource::Io),
            _ => None,
        }
    }
}

/// Render the exact bytes a pressure file returns. All windows and the
/// stall total read back zero (idle system). `cpu` emits only the
/// `some` line; `memory`/`io` emit `some` then `full`.
///
/// The trailing newline on each line matches Linux's `seq_printf`
/// output — tools (and systemd) parse line-by-line and expect it.
fn render(res: Resource) -> String {
    const SOME: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    const FULL: &str = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    match res {
        Resource::Cpu => String::from(SOME),
        Resource::Memory | Resource::Io => {
            let mut s = String::with_capacity(SOME.len() + FULL.len());
            s.push_str(SOME);
            s.push_str(FULL);
            s
        }
    }
}

/// One `/proc/pressure/<res>` file. Read-writable-and-pollable but
/// semantically inert on NARF (see module docs).
#[derive(Debug)]
struct ProcPressureFile {
    res: Resource,
}

impl FileOps for ProcPressureFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let res = self.res;
        Box::pin(async move {
            let s = render(res);
            slice_read(s.as_bytes(), offset, buf)
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Accept-and-ignore. systemd writes a trigger like
        // `some 150000 1000000\n` to register a threshold; on a real
        // kernel that arms a notifier. NARF has no pressure to cross,
        // so we validate nothing and simply consume the write — the
        // critical contract is "do NOT return -EINVAL / -EBADF", which
        // is what made systemd disable the event source. Returning the
        // full byte count is the standard "wrote everything" reply.
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            // Read-write: systemd (and the kernel) open these O_RDWR to
            // install a trigger. FILE_RW advertises 0o666.
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        // Writable (so a trigger install never blocks) but never
        // readable and never EPOLLPRI: an idle system's pressure never
        // crosses any threshold, so an `epoll` waiter on EPOLLPRI must
        // park quiescently. Returning POLL_OUT only — deliberately
        // withholding POLL_IN and POLL_PRI — is exactly that.
        POLL_OUT
    }
}

/// The `/proc/pressure` directory itself. Static (no feature gate, no
/// registry dependency) so it is always present in a boot build — it
/// is wired directly into `ProcRoot`, the same guaranteed-present path
/// `/proc/meminfo` uses.
#[derive(Debug)]
pub struct ProcPressureDir;

impl ProcPressureDir {
    /// `FileOps` for a named child, or `None` if the name is not one of
    /// the three PSI resources.
    fn child(name: &str) -> Option<Arc<dyn FileOps>> {
        Resource::from_name(name).map(|res| Arc::new(ProcPressureFile { res }) as Arc<dyn FileOps>)
    }
}

impl DirOps for ProcPressureDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        Self::child(name)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        let entries: Vec<DirEntry> = alloc::vec![
            DirEntry {
                name: "cpu",
                file_type: FileType::File,
            },
            DirEntry {
                name: "memory",
                file_type: FileType::File,
            },
            DirEntry {
                name: "io",
                file_type: FileType::File,
            },
        ];
        Box::new(entries.into_iter())
    }
}

// ── Tests ────────────────────────────────────────────────────────────
//
// These run in the in-kernel test suite (`kernel_test_in!`), the same
// runner every other procfs test uses — host `#[test]` binaries can't
// link this crate (it pulls in narf-memory's NUMA weak symbols). The
// exact-byte assertions lock the ABI systemd parses.

use crate::procfs::{poll_once, ProcRoot};
use crate::{POLL_IN, POLL_PRI};
use narf_kernel_test::{kernel_test_in, TestResult};

/// `/proc/pressure/cpu` is exactly the single `some` line.
fn smoke_pressure_cpu_exact_bytes() -> TestResult {
    if render(Resource::Cpu) == "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" {
        TestResult::Pass
    } else {
        TestResult::Fail("cpu pressure content mismatch")
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_cpu_exact_bytes);

/// `/proc/pressure/memory` is `some` then `full`; `io` matches.
fn smoke_pressure_memory_io_exact_bytes() -> TestResult {
    let expect = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
                  full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    if render(Resource::Memory) == expect && render(Resource::Io) == expect {
        TestResult::Pass
    } else {
        TestResult::Fail("memory/io pressure content mismatch")
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_memory_io_exact_bytes);

/// `/proc/pressure` resolves through the root as a directory and its
/// three children resolve to files.
fn smoke_pressure_dir_resolves_via_root() -> TestResult {
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);
    let dir = match root.lookup_dir("pressure") {
        Some(d) => d,
        None => return TestResult::Fail("pressure dir lookup_dir returned None"),
    };
    for name in ["cpu", "memory", "io"] {
        if dir.lookup(name).is_none() {
            return TestResult::Fail("pressure child missing");
        }
    }
    if dir.lookup("bogus").is_some() {
        return TestResult::Fail("pressure accepted an unknown child");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/procfs", smoke_pressure_dir_resolves_via_root);

/// `iter()` lists exactly cpu, memory, io.
fn smoke_pressure_iter_lists_three() -> TestResult {
    let dir = ProcPressureDir;
    let names: Vec<&str> = dir.iter().map(|e| e.name).collect();
    if names == alloc::vec!["cpu", "memory", "io"] {
        TestResult::Pass
    } else {
        TestResult::Fail("pressure iter did not list cpu/memory/io")
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_iter_lists_three);

/// read() returns the rendered bytes through the FileOps surface.
fn smoke_pressure_read_through_fileops() -> TestResult {
    let f = ProcPressureFile {
        res: Resource::Memory,
    };
    let mut buf = [0u8; 256];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if buf[..n] == *render(Resource::Memory).as_bytes() => TestResult::Pass,
        _ => TestResult::Fail("pressure read did not return rendered bytes"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_read_through_fileops);

/// write() accepts systemd's trigger and returns the byte count (never
/// -EINVAL) — the crux of the systemd fix.
fn smoke_pressure_write_accepts_trigger() -> TestResult {
    let f = ProcPressureFile {
        res: Resource::Memory,
    };
    let trigger = b"some 150000 1000000\n";
    match poll_once(f.write(0, trigger)) {
        Some(Ok(n)) if n == trigger.len() => TestResult::Pass,
        _ => TestResult::Fail("pressure write did not accept the trigger"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_write_accepts_trigger);

/// poll() is writable but never readable / never EPOLLPRI on an idle
/// system — so systemd's EPOLLPRI waiter parks quiescently.
fn smoke_pressure_poll_out_only() -> TestResult {
    let f = ProcPressureFile { res: Resource::Cpu };
    let r = f.poll_readiness();
    if r & POLL_OUT == POLL_OUT && r & POLL_IN == 0 && r & POLL_PRI == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("pressure poll must be POLL_OUT only")
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_poll_out_only);

/// stat() reports a read-write file so O_RDWR opens succeed.
fn smoke_pressure_stat_is_rw() -> TestResult {
    let f = ProcPressureFile { res: Resource::Io };
    if f.stat().mode == Mode::FILE_RW {
        TestResult::Pass
    } else {
        TestResult::Fail("pressure stat mode is not FILE_RW")
    }
}
kernel_test_in!("filesystem/procfs", smoke_pressure_stat_is_rw);

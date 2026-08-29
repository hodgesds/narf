//! Minimal debugfs — runtime kernel-debug knobs under `/sys/kernel/debug`.
//!
//! Linux exposes scheduler tunables at `/sys/kernel/debug/sched/` (`features`,
//! `latency_ns`, …). NARF mirrors that layout with a small synthetic tree
//! driven by a KNOB TABLE rather than hardcoded files, so the surface is
//! registration-shaped: today the core executor contributes the entries below;
//! a future seam can let the *active* pluggable `Scheduler` / `StealStrategy`
//! contribute its own knobs (appearing/disappearing on `install_*`).
//!
//! `sched/` entries:
//! - `wake_placement` (rw) — a CORE executor feature flag (à la Linux
//!   `SCHED_FEAT(WAKE_AFFINE)`): whether the waker consults the loaded steal
//!   strategy's `select_wake_cpu` to push a woken task onto an idle sibling.
//!   Off by default (helps producer-consumer IPC, can thrash contended locks).
//! - `policy` (ro) — the installed [`Scheduler`] name. The `wake_placement`
//!   flag's EFFECT depends on the loaded strategy (a strategy whose
//!   `select_wake_cpu` returns `None` makes the flag a no-op), so an operator
//!   needs to see what is active.
//! - `steal_strategy` (ro) — the installed `StealStrategy` name.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// One observable/tunable exposed under `sched/`. `read` renders the current
/// value (freshly, from live kernel state); `write` is `None` for read-only
/// knobs (the file is then mode 0444 and writes fail EPERM).
#[derive(Debug)]
struct SchedKnob {
    name: &'static str,
    read: fn() -> String,
    write: Option<fn(&[u8])>,
}

/// The core executor's `sched/` knob table. Read-only reflectors surface the
/// active pluggable policy/strategy; `wake_placement` is a core feature flag.
static SCHED_KNOBS: &[SchedKnob] = &[
    SchedKnob {
        name: "wake_placement",
        read: || {
            if narf_scheduler::wake_placement_enabled() {
                String::from("1\n")
            } else {
                String::from("0\n")
            }
        },
        write: Some(|buf| {
            // Toggle on the first non-whitespace byte, `echo 1 > …` style.
            if let Some(&b) = buf.iter().find(|b| !b.is_ascii_whitespace()) {
                match b {
                    b'1' | b'y' | b'Y' | b't' | b'T' => narf_scheduler::enable_wake_placement(),
                    b'0' | b'n' | b'N' | b'f' | b'F' => narf_scheduler::disable_wake_placement(),
                    _ => {}
                }
            }
        }),
    },
    SchedKnob {
        name: "policy",
        read: || {
            let name = narf_scheduler::current_scheduler_name().unwrap_or("(none)");
            let mut s = String::from(name);
            s.push('\n');
            s
        },
        write: None,
    },
    SchedKnob {
        name: "steal_strategy",
        read: || {
            let name = narf_scheduler::current_steal_strategy_name().unwrap_or("(none)");
            let mut s = String::from(name);
            s.push('\n');
            s
        },
        write: None,
    },
];

/// The debugfs instance mounted at `/sys/kernel/debug` (`mount -t debugfs`).
#[derive(Debug, Default)]
pub struct DebugFs;

impl DebugFs {
    /// Construct a fresh debugfs. The tree is stateless (every knob reads/writes
    /// live kernel state), so instances are interchangeable.
    pub fn new() -> Self {
        DebugFs
    }
}

impl crate::FsInstance for DebugFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(DebugRoot)
    }
    fn name(&self) -> &str {
        "debugfs"
    }
}

/// `/sys/kernel/debug` — one subdir today: `sched/`.
#[derive(Debug)]
struct DebugRoot;

impl DirOps for DebugRoot {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        (name == "sched").then(|| Arc::new(SchedDir) as Arc<dyn DirOps>)
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(
            [DirEntry {
                name: "sched",
                file_type: FileType::Dir,
            }]
            .into_iter(),
        )
    }
}

/// `/sys/kernel/debug/sched` — enumerates [`SCHED_KNOBS`].
#[derive(Debug)]
struct SchedDir;

impl DirOps for SchedDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        SCHED_KNOBS
            .iter()
            .find(|k| k.name == name)
            .map(|k| Arc::new(KnobFile { knob: k }) as Arc<dyn FileOps>)
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(SCHED_KNOBS.iter().map(|k| DirEntry {
            name: k.name,
            file_type: FileType::File,
        }))
    }
}

/// A file backed by one [`SchedKnob`]: read renders the live value, write
/// (when the knob is writable) applies it.
#[derive(Debug)]
struct KnobFile {
    knob: &'static SchedKnob,
}

impl FileOps for KnobFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let value = (self.knob.read)();
        let bytes = value.as_bytes();
        let start = (offset as usize).min(bytes.len());
        let n = core::cmp::min(buf.len(), bytes.len() - start);
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Box::pin(async move { Ok(n) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let result = match self.knob.write {
            // Consume the whole write regardless of content, so a `> file`
            // redirect completes; unknown values are a lenient no-op.
            Some(apply) => {
                apply(buf);
                Ok(buf.len())
            }
            None => Err(FsError::PermissionDenied),
        };
        Box::pin(async move { result })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 2,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                // Writable knobs 0644; read-only reflectors 0444.
                perms: if self.knob.write.is_some() {
                    0o644
                } else {
                    0o444
                },
            },
            mtime_cycles: 0,
        }
    }
}

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
//! - `wake_next` (rw) — a CORE executor feature flag (à la Linux
//!   `SCHED_FEAT(NEXT_BUDDY)`): whether a just-woken task is dispatched ahead
//!   of the tasks already queued in front of it (its home CPU's "next buddy").
//!   Off by default (favors latency over strict-FIFO fairness).
//! - `wake_preempt` (rw) — a CORE executor feature flag (à la Linux
//!   `wakeup_preempt`/`resched_curr`): whether a wake asks the running task to
//!   cede at its next syscall exit so the wakee runs promptly instead of after a
//!   fair quantum. Off by default. Collapses producer/consumer handoff latency
//!   (stress-ng `--futex`) at some cost to batching.
//! - `policy` (ro) — the installed [`Scheduler`] name. Wake-time CPU placement
//!   is the policy's `select_task_rq` (a policy that returns `None` does no
//!   placement), so an operator needs to see what is active.
//! - `steal_strategy` (ro) — the installed `StealStrategy` name.
//!
//! Drivers add their own top-level directories with [`register_dir`]
//! (Linux `debugfs_create_dir(name, NULL)`, as DRM creates `dri/`). Their
//! inodes take numbers from [`alloc_ino`] and the superblock identity of
//! [`attrs`], as Linux's `debugfs_get_inode` numbers every entry from
//! `get_next_ino()` on the one superblock.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

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
/// active pluggable policy/strategy; `wake_next` / `wake_preempt` are core
/// feature flags.
static SCHED_KNOBS: &[SchedKnob] = &[
    SchedKnob {
        name: "wake_next",
        read: || {
            if narf_scheduler::wake_next_enabled() {
                String::from("1\n")
            } else {
                String::from("0\n")
            }
        },
        write: Some(|buf| {
            if let Some(&b) = buf.iter().find(|b| !b.is_ascii_whitespace()) {
                match b {
                    b'1' | b'y' | b'Y' | b't' | b'T' => narf_scheduler::enable_wake_next(),
                    b'0' | b'n' | b'N' | b'f' | b'F' => narf_scheduler::disable_wake_next(),
                    _ => {}
                }
            }
        }),
    },
    SchedKnob {
        name: "wake_preempt",
        read: || {
            if narf_scheduler::wake_preempt_enabled() {
                String::from("1\n")
            } else {
                String::from("0\n")
            }
        },
        write: Some(|buf| {
            if let Some(&b) = buf.iter().find(|b| !b.is_ascii_whitespace()) {
                match b {
                    b'1' | b'y' | b'Y' | b't' | b'T' => narf_scheduler::enable_wake_preempt(),
                    b'0' | b'n' | b'N' | b'f' | b'F' => narf_scheduler::disable_wake_preempt(),
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
        name: "quantum_unit",
        read: || {
            // The unit the installed policy schedules the slice in (Linux is
            // always ns; NARF makes it first-class). See `QuantumUnit`.
            let base = match narf_scheduler::current_scheduler_quantum_unit() {
                narf_scheduler::QuantumUnit::Nanos => "nanos\n",
                narf_scheduler::QuantumUnit::Cycles => "cycles\n",
                narf_scheduler::QuantumUnit::Instructions => "instructions\n",
            };
            String::from(base)
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

// Inode identity. Linux debugfs is one superblock (`get_tree_single`) whose
// root is `simple_fill_super`'s inode 1 (fs/libfs.c) and whose entries take
// `get_next_ino()` numbers when created (`debugfs_get_inode`,
// fs/debugfs/inode.c). NARF's tree is fixed, so the numbers are assigned by
// position in creation order: root 1, `sched/` 2, knob `i` 3 + i.
const DEBUGFS_ROOT_INO: u64 = 1;
const DEBUGFS_SCHED_INO: u64 = 2;
static DEBUGFS_DEV: crate::inode_id::LazyAnonDev = crate::inode_id::LazyAnonDev::new();

fn debugfs_attrs() -> crate::InodeAttrs {
    crate::InodeAttrs {
        dev: DEBUGFS_DEV.get(),
        ..Default::default()
    }
}

/// The superblock identity every debugfs inode carries, for a registered
/// directory's entries.
pub fn attrs() -> crate::InodeAttrs {
    debugfs_attrs()
}

/// The first inode number [`alloc_ino`] hands out: past the fixed tree.
const DYNAMIC_INO_BASE: u64 = 1 << 20;
static NEXT_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(DYNAMIC_INO_BASE);

/// `get_next_ino()` for an entry of a registered directory: unique on this
/// superblock, never one of the fixed tree's numbers.
pub fn alloc_ino() -> u64 {
    alloc_ino_range(1)
}

/// `count` consecutive [`alloc_ino`] numbers, for a directory whose
/// entries are made on lookup and need stable numbers; the first.
pub fn alloc_ino_range(count: u64) -> u64 {
    NEXT_INO.fetch_add(count.max(1), core::sync::atomic::Ordering::Relaxed)
}

/// Driver directories at the root, in registration order.
static DIRS: IrqSafeSpinLock<Vec<(&'static str, Arc<dyn DirOps>)>> =
    IrqSafeSpinLock::new(Vec::new());

/// `debugfs_create_dir(name, NULL)`: `dir` appears as
/// `/sys/kernel/debug/<name>` in every debugfs mount. A name already
/// present (or `sched`) is `AlreadyExists`.
pub fn register_dir(name: &'static str, dir: Arc<dyn DirOps>) -> Result<(), FsError> {
    let mut dirs = DIRS.lock();
    if name == "sched" || dirs.iter().any(|(taken, _)| *taken == name) {
        return Err(FsError::AlreadyExists);
    }
    dirs.push((name, dir));
    Ok(())
}

/// `debugfs_remove` of a registered directory; nothing if it is absent.
pub fn unregister_dir(name: &str) {
    DIRS.lock().retain(|(taken, _)| *taken != name);
}

/// `/sys/kernel/debug` — `sched/`, then the registered directories.
#[derive(Debug)]
struct DebugRoot;

impl DirOps for DebugRoot {
    fn ino(&self) -> u64 {
        DEBUGFS_ROOT_INO
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        debugfs_attrs()
    }
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if name == "sched" {
            return Some(Arc::new(SchedDir) as Arc<dyn DirOps>);
        }
        DIRS.lock()
            .iter()
            .find(|(taken, _)| *taken == name)
            .map(|(_, dir)| dir.clone())
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        let mut entries = alloc::vec![DirEntry {
            name: "sched".into(),
            file_type: FileType::Dir,
        }];
        entries.extend(DIRS.lock().iter().map(|(name, _)| DirEntry {
            name: (*name).into(),
            file_type: FileType::Dir,
        }));
        Box::new(entries.into_iter())
    }
}

/// `/sys/kernel/debug/sched` — enumerates [`SCHED_KNOBS`].
#[derive(Debug)]
struct SchedDir;

impl DirOps for SchedDir {
    fn ino(&self) -> u64 {
        DEBUGFS_SCHED_INO
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        debugfs_attrs()
    }
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        SCHED_KNOBS
            .iter()
            .find(|k| k.name == name)
            .map(|k| Arc::new(KnobFile { knob: k }) as Arc<dyn FileOps>)
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(SCHED_KNOBS.iter().map(|k| DirEntry {
            name: k.name.into(),
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
    fn ino(&self) -> u64 {
        let index = SCHED_KNOBS
            .iter()
            .position(|k| core::ptr::eq(k, self.knob))
            .unwrap_or(0);
        DEBUGFS_SCHED_INO + 1 + index as u64
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        debugfs_attrs()
    }
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

//! Batch 24 — Landlock path-based access control with real enforcement.
//!
//! Landlock lets an unprivileged task irreversibly drop its own filesystem
//! access down to an allow-list of `path_beneath` rules. NARF implements
//! the create → add_rule → restrict_self flow AND enforces it at
//! `open(2)`:
//!
//!  - `landlock_create_ruleset(attr, size, flags)` builds a ruleset
//!    declaring which FS access rights it `handles`, returning a ruleset
//!    fd. With `LANDLOCK_CREATE_RULESET_VERSION` it instead reports the
//!    supported ABI version.
//!  - `landlock_add_rule(fd, PATH_BENEATH, attr, 0)` adds a rule allowing
//!    a set of rights beneath `parent_fd`'s path. The path is recovered
//!    from the fd → path table (see `mqueue::fd_path`).
//!  - `landlock_restrict_self(fd, 0)` stacks the ruleset onto the calling
//!    task's active set (irreversible).
//!
//! Enforcement (`landlock_check_open`, called from `sys_open`): for each
//! stacked ruleset, the requested rights that the ruleset *handles* must
//! all be granted by some rule whose path is an ancestor of (or equal to)
//! the opened path. A handled right with no covering rule ⇒ the open is
//! denied with EACCES. Rights a ruleset doesn't handle are always allowed.
//!
//! Restriction is per-task, so it dies with the process; a global
//! `LANDLOCK_ANY` flag keeps the open hot-path free when nothing is
//! restricted.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::handlers::{copy_from_user_vec, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno (negated-long convention) ─────────────────────────────────
const EINVAL: i64 = 22;
const EBADF: i64 = 9;
const EMFILE: i64 = 24;
const EFAULT: i64 = 14;
const EACCES: i64 = 13;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

// ── Landlock FS access-right bits (ABI v1) ──────────────────────────
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
/// ABI version we report; v1 covers the file/dir access rights we enforce.
const LANDLOCK_ABI_VERSION: u64 = 1;

// create_ruleset flags.
const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1 << 0;
// rule types.
const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;

#[derive(Clone)]
struct PathRule {
    path: String,
    allowed: u64,
}

#[derive(Clone)]
struct Ruleset {
    handled: u64,
    rules: Vec<PathRule>,
}

/// Rulesets under construction, keyed by their fd's opaque id.
static RULESETS: IrqSafeSpinLock<Option<BTreeMap<u64, Ruleset>>> = IrqSafeSpinLock::new(None);
static RULESET_NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Applied (restrict_self) rulesets, stacked per task.
static TASK_RULESETS: IrqSafeSpinLock<Option<BTreeMap<u64, Vec<Ruleset>>>> =
    IrqSafeSpinLock::new(None);
/// Set once any task is restricted, so sys_open skips the check otherwise.
static LANDLOCK_ANY: AtomicBool = AtomicBool::new(false);

fn with_rulesets<R>(f: impl FnOnce(&mut BTreeMap<u64, Ruleset>) -> R) -> R {
    let mut g = RULESETS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}
fn with_task_rulesets<R>(f: impl FnOnce(&mut BTreeMap<u64, Vec<Ruleset>>) -> R) -> R {
    let mut g = TASK_RULESETS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_landlock_reset() {
    *RULESETS.lock() = Some(BTreeMap::new());
    *TASK_RULESETS.lock() = Some(BTreeMap::new());
    RULESET_NEXT_ID.store(1, Ordering::Relaxed);
    LANDLOCK_ANY.store(false, Ordering::Relaxed);
}

fn ruleset_id_of(task: u64, fd_no: u32) -> Option<u64> {
    crate::fd::with_table(task, |t| {
        t.get(fd_no).and_then(|e| e.ops.landlock_ruleset())
    })
    .flatten()
}

/// True if `target` is `base` or lies beneath it (`base/...`).
fn path_beneath(base: &str, target: &str) -> bool {
    if base == "/" {
        return true;
    }
    target == base
        || (target.len() > base.len()
            && target.starts_with(base)
            && target.as_bytes()[base.len()] == b'/')
}

/// fd-backed ruleset handle.
struct RulesetFile {
    id: u64,
}

impl narf_filesystem::FileOps for RulesetFile {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::InvalidData) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::InvalidData) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn landlock_ruleset(&self) -> Option<u64> {
        Some(self.id)
    }
}

/// `landlock_create_ruleset(attr, size, flags)`.
pub fn sys_landlock_create_ruleset(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let attr = a.arg0;
    let size = a.arg1 as usize;
    let flags = a.arg2;

    // Version query: ignore attr/size, report the supported ABI version.
    if flags & LANDLOCK_CREATE_RULESET_VERSION != 0 {
        ctx.set_return(SyscallReturn::ok(LANDLOCK_ABI_VERSION));
        return;
    }
    // The ruleset attr's first u64 is handled_access_fs (v1). Require at
    // least that much.
    if attr == 0 || size < 8 {
        ctx.set_return(err(EINVAL));
        return;
    }
    // SAFETY: range-validated by copy_from_user_vec.
    let bytes = match unsafe { copy_from_user_vec(attr, 8) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(err(EFAULT));
            return;
        }
    };
    let handled = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let id = RULESET_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_rulesets(|m| {
        m.insert(
            id,
            Ruleset {
                handled,
                rules: Vec::new(),
            },
        )
    });
    let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(RulesetFile { id });
    match crate::fd::install(
        current_task_id(),
        crate::fd::FdEntry {
            ops: file,
            offset: 0,
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        },
    ) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => {
            // `security/landlock/syscalls.c` publishes the ruleset with
            // `anon_inode_getfd`, whose descriptor comes from
            // `get_unused_fd_flags`: a full table is -EMFILE.
            ctx.set_return(err(EMFILE));
        }
    }
}

/// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`.
pub fn sys_landlock_add_rule(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match ruleset_id_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    if a.arg1 != LANDLOCK_RULE_PATH_BENEATH {
        // Only path_beneath rules are supported (no net_port).
        ctx.set_return(err(EINVAL));
        return;
    }
    // struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
    // (packed → 12 bytes).
    // SAFETY: copy_from_user_vec range-validates [arg2, arg2+12).
    let bytes = match unsafe { copy_from_user_vec(a.arg2, 12) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(err(EFAULT));
            return;
        }
    };
    let allowed = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let parent_fd = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    // Resolve the parent fd back to its path via the fd → path table.
    let path = match crate::mqueue::fd_path(task, parent_fd as u32) {
        Some(p) => p,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let r = with_rulesets(|m| {
        m.get_mut(&id).map(|rs| {
            rs.rules.push(PathRule { path, allowed });
        })
    });
    match r {
        Some(()) => ctx.set_return(SyscallReturn::ok(0)),
        None => ctx.set_return(err(EINVAL)),
    }
}

/// `landlock_restrict_self(ruleset_fd, flags)`.
pub fn sys_landlock_restrict_self(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match ruleset_id_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let ruleset = with_rulesets(|m| m.get(&id).cloned());
    let ruleset = match ruleset {
        Some(r) => r,
        None => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    with_task_rulesets(|m| m.entry(task).or_default().push(ruleset));
    LANDLOCK_ANY.store(true, Ordering::Relaxed);
    ctx.set_return(SyscallReturn::ok(0));
}

/// Enforcement hook for `sys_open`. Returns `Ok(())` if the open is
/// permitted, or `Err(SyscallReturn)` carrying EACCES if a stacked
/// ruleset handles a requested right that no rule grants for `abs_path`.
pub(crate) fn landlock_check_open(
    task: u64,
    abs_path: &str,
    want_read: bool,
    want_write: bool,
) -> Result<(), SyscallReturn> {
    if !LANDLOCK_ANY.load(Ordering::Relaxed) {
        return Ok(());
    }
    let mut requested = 0u64;
    if want_read {
        requested |= LANDLOCK_ACCESS_FS_READ_FILE;
    }
    if want_write {
        requested |= LANDLOCK_ACCESS_FS_WRITE_FILE;
    }
    if requested == 0 {
        return Ok(());
    }
    with_task_rulesets(|m| {
        let rulesets = match m.get(&task) {
            Some(r) => r,
            None => return Ok(()),
        };
        for rs in rulesets {
            // Only the rights this ruleset handles are subject to it.
            let enforced = requested & rs.handled;
            if enforced == 0 {
                continue;
            }
            let mut granted = 0u64;
            for rule in &rs.rules {
                if path_beneath(&rule.path, abs_path) {
                    granted |= rule.allowed;
                }
            }
            if enforced & !granted != 0 {
                return Err(err(EACCES));
            }
        }
        Ok(())
    })
}

// Re-export the execute bit for callers that may grow exec checks; keeps
// the constant from being dead while documenting the full v1 set.
#[allow(dead_code)]
const _ALL_V1_RIGHTS: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE;

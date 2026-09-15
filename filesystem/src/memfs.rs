//! `MemFs` — an in-memory read/write filesystem with hierarchy.
//!
//! Stage-4 surface for exercising the mutable [`DirOps`] paths
//! (`unlink`, `create`, `mkdir`, `rmdir`, `rename`, `symlink`).
//! Designed for the `/tmp` mount in the validate harness — small
//! files, nested directories, no persistence. Concurrency: a single
//! `IrqSafeSpinLock` per directory keeps mutations atomic, while successful
//! subdirectory reads use generation-validated per-CPU weak entries instead
//! of serializing on that writer lock.
//!
//! Layout: each directory owns a `BTreeMap<String, Entry>` of refcounted
//! files, directories, links, FIFOs, and special nodes. `MemFile` carries a
//! sparse page map behind an IRQ-safe lock, so concurrent readers/writers see
//! a consistent logical length and contents without sparse truncates allocating
//! physical storage. `MemSymlink` stores its target as an immutable `String`
//! and exposes the bytes via `FileOps::read`; writes return
//! `ReadOnly`. `unlink` removes the entry from the parent map but
//! keeps the file's `Arc` alive for any outstanding fd holders —
//! the bytes go away when the last fd drops, matching POSIX
//! semantics. `rmdir` rejects non-empty directories (POSIX
//! EEXIST→`Busy`).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::posix_acl::{
    AclType, PosixAcl, XATTR_NAME_POSIX_ACL_ACCESS, XATTR_NAME_POSIX_ACL_DEFAULT,
};
use crate::{
    DirEntry, DirOps, FileOps, FileType, FsDqBlk, FsDqInfo, FsError, FsFuture, FsInstance, FsStat,
    InodeAttrs, Mode, QuotaKind, Stat, IIF_BGRACE, IIF_FLAGS, IIF_IGRACE, QIF_ALL, QIF_BLIMITS,
    QIF_BTIME, QIF_ILIMITS, QIF_INODES, QIF_ITIME, QIF_SPACE,
};

const PAGE_SIZE: u64 = 4096;
const SECTORS_PER_PAGE: u64 = PAGE_SIZE / 512;

/// Linux `mm/shmem.c::BOGO_INODE_SIZE` — the notional bytes one tmpfs inode
/// costs. tmpfs does not budget inodes as a count: it budgets `free_ispace`
/// bytes, of which an inode takes 1024 and an extended attribute takes
/// `simple_xattr_space()`. `nr_inodes=N` is the count form of an
/// `N * BOGO_INODE_SIZE` byte budget.
const BOGO_INODE_SIZE: u64 = 1024;

/// Linux `SHMEM_QUOTA_MAX_SPC_LIMIT` / `SHMEM_QUOTA_MAX_INO_LIMIT`
/// (`include/linux/shmem_fs.h`) — both are 2^63-1.
const SHMEM_QUOTA_MAX_LIMIT: u64 = i64::MAX as u64;

/// Linux tmpfs mount configuration.
///
/// Limits use 4-KiB pages/inodes. `None` is Linux's explicit unlimited value
/// (`size=0`, `nr_blocks=0`, or `nr_inodes=0`). The ordinary default is half
/// of allocator-managed RAM, matching `shmem_default_max_blocks()` and
/// `shmem_default_max_inodes()` in Linux `mm/shmem.c`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmpFsOptions {
    pub max_blocks: Option<u64>,
    pub max_inodes: Option<u64>,
    pub root_mode: u16,
    pub root_uid: u32,
    pub root_gid: u32,
    pub noswap: bool,
    pub inode64: bool,
    /// `usrquota` — enable per-user disk-quota accounting + enforcement.
    pub usrquota: bool,
    /// `grpquota` — enable per-group disk-quota accounting + enforcement.
    pub grpquota: bool,
    /// `{usr,grp}quota_{block,inode}_hardlimit=` — the hard limit every id
    /// starts with on this mount, before `setquota` overrides it. Block
    /// limits are BYTES (Linux `memparse`), inode limits are counts; 0 is
    /// Linux's "no default limit". Mirrors `struct shmem_quota_limits`.
    pub quota_limits: QuotaDefaults,
}

/// Linux `struct shmem_quota_limits` — the per-mount default hard limits
/// handed to every newly seen quota id (`mm/shmem_quota.c::shmem_acquire_dquot`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QuotaDefaults {
    pub usrquota_bhardlimit: u64,
    pub usrquota_ihardlimit: u64,
    pub grpquota_bhardlimit: u64,
    pub grpquota_ihardlimit: u64,
}

impl TmpFsOptions {
    pub fn defaults(total_pages: u64, uid: u32, gid: u32) -> Self {
        let half = total_pages / 2;
        Self {
            max_blocks: (half != 0).then_some(half),
            max_inodes: (half != 0).then_some(half),
            root_mode: 0o1777,
            root_uid: uid,
            root_gid: gid,
            // NARF has no swap-backed shmem path. All tmpfs mounts therefore
            // have Linux's noswap behavior even when the option is omitted.
            noswap: true,
            inode64: true,
            usrquota: false,
            grpquota: false,
            quota_limits: QuotaDefaults::default(),
        }
    }

    /// Parse Linux's tmpfs mount options against an explicit RAM-page total.
    /// The explicit total keeps unit/kernel tests deterministic; mounted
    /// instances use NARF's live frame total through [`TmpFs::from_options`].
    pub fn parse(options: &str, total_pages: u64, uid: u32, gid: u32) -> Result<Self, FsError> {
        let mut parsed = Self::defaults(total_pages, uid, gid);
        apply_tmpfs_options(&mut parsed, options, total_pages)?;
        Ok(parsed)
    }
}

/// Linux ramfs accepts `mode=` and historically ignores every other mount
/// option. It has no block or inode limits and cannot be resized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamFsOptions {
    pub root_mode: u16,
    pub root_uid: u32,
    pub root_gid: u32,
}

impl RamFsOptions {
    pub fn parse(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        let mut parsed = Self {
            root_mode: 0o755,
            root_uid: uid,
            root_gid: gid,
        };
        for raw in options.split(',').filter(|part| !part.is_empty()) {
            let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
            if key == "mode" {
                parsed.root_mode = parse_octal_mode(value)?;
            }
            // Linux ramfs intentionally ignores unknown parameters for
            // compatibility with its historical tmpfs-fallback role.
        }
        Ok(parsed)
    }
}

/// Linux `fsparam_u32oct` + `shmem_parse_one`'s `Opt_mode`:
/// `kstrtouint(value, 8, ...)` then `result.uint_32 & 07777`. An
/// out-of-range mode is MASKED, not rejected — `mode=17777` mounts with
/// 07777 — so the only failure here is a value that is not octal or does
/// not fit a `u32`.
fn parse_octal_mode(value: &str) -> Result<u16, FsError> {
    // `kstrtouint` takes plain digits: no sign, no `0o`/`0x` prefix (base
    // is fixed at 8 by the parameter spec), and rejects an empty string.
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FsError::InvalidData);
    }
    let raw = u32::from_str_radix(value, 8).map_err(|_| FsError::InvalidData)?;
    Ok((raw & 0o7777) as u16)
}

/// Linux `memparse` (`lib/cmdline.c`): `simple_strtoull(ptr, &end, 0)`
/// followed by at most ONE `K`/`M`/`G`/`T`/`P`/`E` suffix in either case.
/// Base 0 is C's `strtoull` convention — `0x`/`0X` hex, a leading `0`
/// octal, decimal otherwise.
///
/// Returns the value AND the unconsumed remainder, because every shmem
/// caller ends with Linux's `if (*rest) goto bad_value` — and `size=`
/// additionally consumes a trailing `%`. Note what Linux does NOT do: it
/// never rejects a two-character suffix such as `kB` (the `B` is left in
/// `rest`, so the caller's `*rest` test fails the mount), and it does not
/// check the shifts for overflow. NARF keeps the first behaviour exactly
/// and diverges on the second by returning EINVAL rather than wrapping to
/// a nonsense limit.
fn memparse(value: &str) -> Result<(u64, &str), FsError> {
    let (digits, radix) = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (hex, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    // `simple_strtoull` stops at the first non-digit and returns what it
    // has; with NO digits at all it returns 0 and consumes nothing. The
    // callers' `*rest` test then rejects the whole value, so treat an
    // empty digit run the same way rather than parsing "" as 0.
    if end == 0 {
        return Err(FsError::InvalidData);
    }
    let base = u64::from_str_radix(&digits[..end], radix).map_err(|_| FsError::InvalidData)?;
    let rest = &digits[end..];
    let power = match rest.as_bytes().first() {
        Some(b'k') | Some(b'K') => 1,
        Some(b'm') | Some(b'M') => 2,
        Some(b'g') | Some(b'G') => 3,
        Some(b't') | Some(b'T') => 4,
        Some(b'p') | Some(b'P') => 5,
        Some(b'e') | Some(b'E') => 6,
        _ => 0,
    };
    let mut scaled = base;
    for _ in 0..power {
        scaled = scaled.checked_mul(1024).ok_or(FsError::InvalidData)?;
    }
    Ok((scaled, if power == 0 { rest } else { &rest[1..] }))
}

/// `memparse` for an option that must consume its whole value — Linux's
/// `size = memparse(...); if (*rest) goto bad_value;`.
fn memparse_exact(value: &str) -> Result<u64, FsError> {
    let (parsed, rest) = memparse(value)?;
    rest.is_empty()
        .then_some(parsed)
        .ok_or(FsError::InvalidData)
}

/// Linux `Opt_size`: a byte count (optionally a percentage of RAM) rounded
/// UP to whole pages. The percentage arm reproduces `shmem_parse_one`'s
/// arithmetic exactly — `size <<= PAGE_SHIFT; size *= totalram_pages();
/// do_div(size, 100)` — including its truncation, so `size=1%` of a
/// one-page machine is Linux's 1 block and not the 0 a
/// `percent * pages / 100` shortcut would give. Linux applies no ceiling
/// to the percentage: `size=200%` is a legal (over-committed) tmpfs.
fn parse_size_blocks(value: &str, total_pages: u64) -> Result<u64, FsError> {
    let (parsed, rest) = memparse(value)?;
    let bytes = match rest.strip_prefix('%') {
        Some(after) => {
            if !after.is_empty() {
                return Err(FsError::InvalidData);
            }
            let scaled = (parsed as u128)
                .saturating_mul(PAGE_SIZE as u128)
                .saturating_mul(total_pages as u128)
                / 100;
            u64::try_from(scaled).map_err(|_| FsError::InvalidData)?
        }
        None => {
            if !rest.is_empty() {
                return Err(FsError::InvalidData);
            }
            parsed
        }
    };
    Ok(bytes.div_ceil(PAGE_SIZE))
}

/// Linux `Opt_{usr,grp}quota_{block,inode}_hardlimit`: a `memparse` value
/// that must consume the whole string, must be nonzero, and must not
/// exceed `SHMEM_QUOTA_MAX_{SPC,INO}_LIMIT`.
fn parse_quota_hardlimit(value: &str) -> Result<u64, FsError> {
    let parsed = memparse_exact(value)?;
    if parsed == 0 || parsed > SHMEM_QUOTA_MAX_LIMIT {
        return Err(FsError::InvalidData);
    }
    Ok(parsed)
}

fn apply_tmpfs_options(
    parsed: &mut TmpFsOptions,
    options: &str,
    total_pages: u64,
) -> Result<(), FsError> {
    for raw in options.split(',').filter(|part| !part.is_empty()) {
        let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
        match key {
            "size" => {
                let blocks = parse_size_blocks(value, total_pages)?;
                parsed.max_blocks = (blocks != 0).then_some(blocks);
            }
            "nr_blocks" => {
                let blocks = memparse_exact(value)?;
                // `if (*rest || ctx->blocks > LONG_MAX) goto bad_value;`
                if blocks > i64::MAX as u64 {
                    return Err(FsError::InvalidData);
                }
                parsed.max_blocks = (blocks != 0).then_some(blocks);
            }
            "nr_inodes" => {
                let inodes = memparse_exact(value)?;
                // `if (*rest || ctx->inodes > ULONG_MAX / BOGO_INODE_SIZE)`
                // — the count is later multiplied by BOGO_INODE_SIZE to get
                // the inode-space budget, so it must not overflow that.
                if inodes > u64::MAX / BOGO_INODE_SIZE {
                    return Err(FsError::InvalidData);
                }
                parsed.max_inodes = (inodes != 0).then_some(inodes);
            }
            "mode" => parsed.root_mode = parse_octal_mode(value)?,
            "uid" => {
                parsed.root_uid = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
            }
            "gid" => {
                parsed.root_gid = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
            }
            "noswap" if value.is_empty() => parsed.noswap = true,
            "inode64" if value.is_empty() => parsed.inode64 = true,
            "inode32" if value.is_empty() => parsed.inode64 = false,
            // Disk-quota mount options. Bare `quota` turns on BOTH kinds —
            // `Opt_quota` sets `QTYPE_MASK_USR | QTYPE_MASK_GRP` — it is not
            // a synonym for `usrquota`.
            "quota" if value.is_empty() => {
                parsed.usrquota = true;
                parsed.grpquota = true;
            }
            "usrquota" if value.is_empty() => parsed.usrquota = true,
            "grpquota" if value.is_empty() => parsed.grpquota = true,
            "usrquota_block_hardlimit" => {
                parsed.quota_limits.usrquota_bhardlimit = parse_quota_hardlimit(value)?;
            }
            "grpquota_block_hardlimit" => {
                parsed.quota_limits.grpquota_bhardlimit = parse_quota_hardlimit(value)?;
            }
            "usrquota_inode_hardlimit" => {
                parsed.quota_limits.usrquota_ihardlimit = parse_quota_hardlimit(value)?;
            }
            "grpquota_inode_hardlimit" => {
                parsed.quota_limits.grpquota_ihardlimit = parse_quota_hardlimit(value)?;
            }
            // NARF advertises THP as disabled. Accepting another policy would
            // make the mount option lie about allocation behavior — which is
            // also what Linux does without CONFIG_TRANSPARENT_HUGEPAGE
            // (`goto unsupported_parameter`, i.e. -EINVAL).
            "huge" if value == "never" => {}
            // Heap allocation follows the caller/default policy. These two
            // spellings therefore describe existing behavior; node-list
            // policies require page-backed tmpfs and are rejected.
            "mpol" if value == "default" || value == "local" => {}
            // `casefold`, `casefold=utf8-<v>` and `strict_encoding` need
            // CONFIG_UNICODE; without it `shmem_parse_opt_casefold` reports
            // -EINVAL, which is what falling through to the reject arm does.
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MemFsKind {
    Generic,
    Tmpfs,
    Ramfs,
}

/// Default quota grace period — 7 days, matching Linux `MAX_DQ_TIME`.
const DEFAULT_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

/// Wall-clock seconds, for quota soft-limit grace deadlines.
fn quota_now_secs() -> u64 {
    narf_time::now_wall().secs.max(0) as u64
}

/// Per-id disk-quota accounting + limits.
///
/// Usage is counted in 4-KiB pages (the fs block), but the LIMITS are bytes,
/// as in Linux: `dquot->dq_dqb.dqb_bhardlimit` holds a byte count and
/// `fs/quota/dquot.c::check_bdq` compares it against `dqb_curspace`, also
/// bytes. Keeping bytes here is what lets a sub-page mount-option limit
/// (`usrquota_block_hardlimit=1K`) deny the first page the way Linux does
/// instead of rounding into "one page allowed" or "unlimited".
/// `*_hard`/`*_soft` of 0 means "unlimited" (Linux convention).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct Dquot {
    blocks_used: u64,
    space_hard: u64,
    space_soft: u64,
    inodes_used: u64,
    inodes_hard: u64,
    inodes_soft: u64,
    /// Grace deadlines (wall-clock seconds); 0 = not over the soft limit.
    btime: u64,
    itime: u64,
}

/// Bytes charged for `blocks` whole tmpfs pages — Linux's
/// `__dquot_alloc_space(inode, nr << inode->i_blkbits, ...)`.
fn blocks_to_space(blocks: u64) -> u64 {
    blocks.saturating_mul(PAGE_SIZE)
}

/// Evaluate charging `add` blocks against `dq` WITHOUT mutating: returns the
/// new used count + new grace deadline, or `QuotaExceeded` if it must be
/// denied (over hard, or over soft with the grace period expired).
fn eval_blocks(dq: &Dquot, add: u64, grace: u64, now: u64) -> Result<(u64, u64), FsError> {
    let new = dq.blocks_used.saturating_add(add);
    let space = blocks_to_space(new);
    if dq.space_hard != 0 && space > dq.space_hard {
        return Err(FsError::QuotaExceeded);
    }
    let mut btime = dq.btime;
    if dq.space_soft != 0 && space > dq.space_soft {
        if btime == 0 {
            btime = now.saturating_add(grace); // just crossed — start the clock
        } else if now >= btime {
            return Err(FsError::QuotaExceeded); // grace expired
        }
    } else {
        btime = 0; // back under the soft limit
    }
    Ok((new, btime))
}

/// Inode analogue of [`eval_blocks`].
fn eval_inodes(dq: &Dquot, add: u64, grace: u64, now: u64) -> Result<(u64, u64), FsError> {
    let new = dq.inodes_used.saturating_add(add);
    if dq.inodes_hard != 0 && new > dq.inodes_hard {
        return Err(FsError::QuotaExceeded);
    }
    let mut itime = dq.itime;
    if dq.inodes_soft != 0 && new > dq.inodes_soft {
        if itime == 0 {
            itime = now.saturating_add(grace);
        } else if now >= itime {
            return Err(FsError::QuotaExceeded);
        }
    } else {
        itime = 0;
    }
    Ok((new, itime))
}

/// One quota kind's (user or group) table + grace periods.
#[derive(Debug)]
struct QuotaTable {
    on: bool,
    grace_blocks: u64,
    grace_inodes: u64,
    /// Mount-option default hard limits (`{usr,grp}quota_block_hardlimit=`
    /// in bytes, `..._inode_hardlimit=` as a count). Linux stamps these onto
    /// every id the first time it is seen
    /// (`mm/shmem_quota.c::shmem_acquire_dquot`), so an id with no explicit
    /// `setquota` still inherits the mount-wide ceiling.
    default_space_hard: u64,
    default_inodes_hard: u64,
    ids: BTreeMap<u32, Dquot>,
}

impl QuotaTable {
    fn new() -> Self {
        Self {
            on: false,
            grace_blocks: DEFAULT_GRACE_SECS,
            grace_inodes: DEFAULT_GRACE_SECS,
            default_space_hard: 0,
            default_inodes_hard: 0,
            ids: BTreeMap::new(),
        }
    }

    /// The limits an id starts life with: Linux's freshly acquired dquot,
    /// pre-loaded from the superblock's mount-option hard limits.
    fn fresh(&self) -> Dquot {
        Dquot {
            space_hard: self.default_space_hard,
            inodes_hard: self.default_inodes_hard,
            ..Dquot::default()
        }
    }

    /// The stored quota for `id`, or the mount's starting limits if this is
    /// the first time the id has been charged.
    fn dquot(&self, id: u32) -> Dquot {
        self.ids.get(&id).copied().unwrap_or_else(|| self.fresh())
    }

    /// Evaluate charging (`blocks`,`inodes`) to `id` without mutating: returns
    /// `(new_blocks, new_btime, new_inodes, new_itime)` or `QuotaExceeded`.
    fn eval(
        &self,
        id: u32,
        blocks: u64,
        inodes: u64,
        now: u64,
    ) -> Result<(u64, u64, u64, u64), FsError> {
        let dq = self.dquot(id);
        let (bu, bt) = eval_blocks(&dq, blocks, self.grace_blocks, now)?;
        let (iu, it) = eval_inodes(&dq, inodes, self.grace_inodes, now)?;
        Ok((bu, bt, iu, it))
    }

    /// Apply an evaluated charge to `id`.
    fn commit(&mut self, id: u32, bu: u64, bt: u64, iu: u64, it: u64) {
        let fresh = self.fresh();
        let dq = self.ids.entry(id).or_insert(fresh);
        dq.blocks_used = bu;
        dq.btime = bt;
        dq.inodes_used = iu;
        dq.itime = it;
    }

    /// Uncharge (`blocks`,`inodes`) from `id`, clearing grace once back under
    /// the soft limit.
    fn uncharge(&mut self, id: u32, blocks: u64, inodes: u64) {
        if let Some(dq) = self.ids.get_mut(&id) {
            dq.blocks_used = dq.blocks_used.saturating_sub(blocks);
            dq.inodes_used = dq.inodes_used.saturating_sub(inodes);
            if dq.space_soft == 0 || blocks_to_space(dq.blocks_used) <= dq.space_soft {
                dq.btime = 0;
            }
            if dq.inodes_soft == 0 || dq.inodes_used <= dq.inodes_soft {
                dq.itime = 0;
            }
        }
    }
}

/// The per-id quota tables — the only superblock state that needs a lock.
///
/// Capacity counters deliberately live OUTSIDE this, as atomics on
/// [`MemSuper`]. Linux keeps `used_blocks` in a `percpu_counter` and reaches
/// for `sbinfo->stat_lock` only for the inode-space bookkeeping and remount
/// (`shmem_inode_acct_blocks` uses `percpu_counter_limited_add`), precisely
/// so a mount-wide lock is not in the path of every page a writer dirties.
/// A single spinlock covering the counters made every concurrent writer on
/// one tmpfs serialise against every other, which is the wrong shape for
/// `/tmp` under parallel builds.
#[derive(Debug)]
struct QuotaState {
    usr: QuotaTable,
    grp: QuotaTable,
}

impl QuotaState {
    /// Charge `blocks`/`inodes` to the file owner (`uid`,`gid`) against every
    /// active quota, all-or-nothing: if any per-id limit would be exceeded,
    /// nothing is mutated and `QuotaExceeded` is returned.
    fn charge_owner(
        &mut self,
        uid: u32,
        gid: u32,
        blocks: u64,
        inodes: u64,
    ) -> Result<(), FsError> {
        if blocks == 0 && inodes == 0 {
            return Ok(());
        }
        let now = quota_now_secs();
        // Evaluate USR + GRP first so a failure mutates nothing.
        let usr_eval = self
            .usr
            .on
            .then(|| self.usr.eval(uid, blocks, inodes, now))
            .transpose()?;
        let grp_eval = self
            .grp
            .on
            .then(|| self.grp.eval(gid, blocks, inodes, now))
            .transpose()?;
        if let Some((bu, bt, iu, it)) = usr_eval {
            self.usr.commit(uid, bu, bt, iu, it);
        }
        if let Some((bu, bt, iu, it)) = grp_eval {
            self.grp.commit(gid, bu, bt, iu, it);
        }
        Ok(())
    }

    /// Uncharge `blocks`/`inodes` from (`uid`,`gid`) — the inverse of
    /// [`Self::charge_owner`], clearing grace deadlines once back under soft.
    fn uncharge_owner(&mut self, uid: u32, gid: u32, blocks: u64, inodes: u64) {
        if self.usr.on {
            self.usr.uncharge(uid, blocks, inodes);
        }
        if self.grp.on {
            self.grp.uncharge(gid, blocks, inodes);
        }
    }

    /// Move a file's (`blocks`,`inodes`) charge from its old owner to a new one
    /// (chown), enforcing the NEW owner's quota all-or-nothing: on `QuotaExceeded`
    /// nothing changes and the caller must keep the old owner.
    fn transfer_owner(
        &mut self,
        old_uid: u32,
        old_gid: u32,
        new_uid: u32,
        new_gid: u32,
        blocks: u64,
        inodes: u64,
    ) -> Result<(), FsError> {
        let now = quota_now_secs();
        // Evaluate the new owner's incoming charge (each kind only if the id
        // actually changes) before mutating anything.
        let usr_eval = (self.usr.on && old_uid != new_uid)
            .then(|| self.usr.eval(new_uid, blocks, inodes, now))
            .transpose()?;
        let grp_eval = (self.grp.on && old_gid != new_gid)
            .then(|| self.grp.eval(new_gid, blocks, inodes, now))
            .transpose()?;
        if let Some((bu, bt, iu, it)) = usr_eval {
            self.usr.uncharge(old_uid, blocks, inodes);
            self.usr.commit(new_uid, bu, bt, iu, it);
        }
        if let Some((bu, bt, iu, it)) = grp_eval {
            self.grp.uncharge(old_gid, blocks, inodes);
            self.grp.commit(new_gid, bu, bt, iu, it);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct MemSuper {
    kind: MemFsKind,
    /// This superblock's anonymous device number — Linux's
    /// `get_anon_bdev` result, reported as every inode's `st_dev`.
    dev: u64,
    /// Mount-wide block limit in 4-KiB pages. **0 is unlimited**, which is
    /// Linux's own encoding for `sbinfo->max_blocks` — keeping the same
    /// sentinel lets this be a plain atomic instead of a locked `Option`.
    max_blocks: AtomicU64,
    /// Blocks in use. Atomic, not lock-protected: this is the counter every
    /// page of every write touches, and Linux keeps its equivalent in a
    /// `percpu_counter` for exactly that reason.
    used_blocks: AtomicU64,
    /// `nr_inodes=` as a count; 0 is unlimited.
    max_inodes: AtomicU64,
    /// Inode space in USE, in bytes — the complement of Linux's
    /// `free_ispace`. An inode costs [`BOGO_INODE_SIZE`] and an extended
    /// attribute costs `simple_xattr_space()`, so xattrs eat into the same
    /// budget `nr_inodes=` sets and show up in `statfs`'s `f_ffree`,
    /// exactly as on Linux.
    used_ispace: AtomicU64,
    /// True while either quota kind is on. Read before taking [`Self::quotas`]
    /// so the overwhelmingly common quota-free mount never takes the lock at
    /// all on an allocation.
    quota_active: core::sync::atomic::AtomicBool,
    quotas: IrqSafeSpinLock<QuotaState>,
    /// True for a superblock minted by [`new_anon_file`] — an inode that
    /// belongs to no MOUNTED filesystem.
    ///
    /// It exists because NARF lets `O_TMPFILE` succeed on a directory whose
    /// filesystem has no native `tmpfile()`, by minting a standalone inode and
    /// materialising it later with `link_node`. Linux has no equivalent: its
    /// O_TMPFILE inode is created BY the target filesystem, so it can never be
    /// a stranger to the directory it lands in.
    ///
    /// Which means the cross-filesystem check has to tell "unowned" apart from
    /// "owned by someone else". Filing an unowned inode is an adoption, not a
    /// link across a boundary; there is no second filesystem for it to cross
    /// from. Refusing it would break every O_TMPFILE on a backend without
    /// native support.
    anonymous: core::sync::atomic::AtomicBool,
}

impl MemSuper {
    fn new(kind: MemFsKind, max_blocks: Option<u64>, max_inodes: Option<u64>) -> Arc<Self> {
        Self::with_quota(
            kind,
            max_blocks,
            max_inodes,
            false,
            false,
            QuotaDefaults::default(),
        )
    }

    /// A superblock for a standalone inode that belongs to no mount.
    /// Set before the `Arc` is shared, and never cleared.
    fn new_anonymous() -> Arc<Self> {
        let sb = Self::new(MemFsKind::Generic, None, None);
        sb.anonymous
            .store(true, core::sync::atomic::Ordering::Release);
        sb
    }

    /// Whether this superblock backs a standalone inode with no mount.
    fn is_anonymous(&self) -> bool {
        self.anonymous.load(core::sync::atomic::Ordering::Acquire)
    }

    fn with_quota(
        kind: MemFsKind,
        max_blocks: Option<u64>,
        max_inodes: Option<u64>,
        usrquota: bool,
        grpquota: bool,
        limits: QuotaDefaults,
    ) -> Arc<Self> {
        let mut usr = QuotaTable::new();
        usr.on = usrquota;
        usr.default_space_hard = limits.usrquota_bhardlimit;
        usr.default_inodes_hard = limits.usrquota_ihardlimit;
        let mut grp = QuotaTable::new();
        grp.on = grpquota;
        grp.default_space_hard = limits.grpquota_bhardlimit;
        grp.default_inodes_hard = limits.grpquota_ihardlimit;
        Arc::new(Self {
            anonymous: core::sync::atomic::AtomicBool::new(false),
            kind,
            dev: alloc_anon_dev(),
            max_blocks: AtomicU64::new(max_blocks.unwrap_or(0)),
            used_blocks: AtomicU64::new(0),
            max_inodes: AtomicU64::new(max_inodes.unwrap_or(0)),
            used_ispace: AtomicU64::new(0),
            quota_active: core::sync::atomic::AtomicBool::new(usrquota || grpquota),
            quotas: IrqSafeSpinLock::new(QuotaState { usr, grp }),
        })
    }

    /// Inode-space budget in bytes; 0 when the mount is unlimited.
    fn max_ispace(&self) -> u64 {
        self.max_inodes
            .load(Ordering::Relaxed)
            .saturating_mul(BOGO_INODE_SIZE)
    }

    /// Recompute `quota_active` after a `quotactl` turned a kind on or off.
    fn refresh_quota_active(&self, state: &QuotaState) {
        self.quota_active
            .store(state.usr.on || state.grp.on, Ordering::Release);
    }

    /// The mount's default quota hard limits, as parsed from its mount
    /// options. Used by remount validation and `show_options`.
    fn quota_defaults(&self) -> QuotaDefaults {
        let state = self.quotas.lock();
        QuotaDefaults {
            usrquota_bhardlimit: state.usr.default_space_hard,
            usrquota_ihardlimit: state.usr.default_inodes_hard,
            grpquota_bhardlimit: state.grp.default_space_hard,
            grpquota_ihardlimit: state.grp.default_inodes_hard,
        }
    }

    /// Bounded add against a mount-wide ceiling — Linux's
    /// `percpu_counter_limited_add`. A `limit` of 0 is unlimited, in which
    /// case the counter still moves (so `statfs` and remount see real usage)
    /// but nothing can fail.
    fn limited_add(counter: &AtomicU64, limit: u64, amount: u64) -> Result<(), FsError> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let new = used.checked_add(amount)?;
                (limit == 0 || new <= limit).then_some(new)
            })
            .map(|_| ())
            .map_err(|_| FsError::NoSpace)
    }

    /// Reserve `blocks` for the file owned by (`uid`,`gid`).
    ///
    /// `mm/shmem.c::shmem_inode_acct_blocks` fixes the order, and with it
    /// which error wins when both limits bite: the mount-wide limit is
    /// taken first (ENOSPC), the per-owner quota second (EDQUOT), and a
    /// quota failure rolls the block counter back
    /// (`percpu_counter_sub(&sbinfo->used_blocks, pages)`).
    fn reserve_blocks(&self, uid: u32, gid: u32, blocks: u64) -> Result<(), FsError> {
        if blocks == 0 {
            return Ok(());
        }
        Self::limited_add(
            &self.used_blocks,
            self.max_blocks.load(Ordering::Relaxed),
            blocks,
        )?;
        if self.quota_active.load(Ordering::Acquire) {
            let mut quotas = self.quotas.lock();
            if let Err(error) = quotas.charge_owner(uid, gid, blocks, 0) {
                drop(quotas);
                self.used_blocks.fetch_sub(blocks, Ordering::AcqRel);
                return Err(error);
            }
        }
        Ok(())
    }

    fn release_blocks(&self, uid: u32, gid: u32, blocks: u64) {
        if blocks == 0 {
            return;
        }
        let _ = self
            .used_blocks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(blocks))
            });
        if self.quota_active.load(Ordering::Acquire) {
            self.quotas.lock().uncharge_owner(uid, gid, blocks, 0);
        }
    }

    /// Charge `bytes` of inode space — the budget `nr_inodes=` sets, which
    /// extended attributes share with inodes themselves
    /// (`shmem_xattr_handler_set`).
    fn reserve_ispace(&self, bytes: u64) -> Result<(), FsError> {
        Self::limited_add(&self.used_ispace, self.max_ispace(), bytes)
    }

    fn release_ispace(&self, bytes: u64) {
        let _ = self
            .used_ispace
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes))
            });
    }

    /// `shmem_reserve_inode` then `dquot_alloc_inode`: ENOSPC when the
    /// mount's inode space is exhausted, EDQUOT when the owner's is.
    fn reserve_inode(self: &Arc<Self>, uid: u32, gid: u32) -> Result<InodeLease, FsError> {
        self.reserve_ispace(BOGO_INODE_SIZE)?;
        if self.quota_active.load(Ordering::Acquire) {
            let mut quotas = self.quotas.lock();
            if let Err(error) = quotas.charge_owner(uid, gid, 0, 1) {
                drop(quotas);
                self.release_ispace(BOGO_INODE_SIZE);
                return Err(error);
            }
        }
        Ok(InodeLease {
            superblock: Arc::clone(self),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            xattr_space: AtomicU64::new(0),
        })
    }

    fn statfs(&self) -> FsStat {
        let max_blocks = self.max_blocks.load(Ordering::Relaxed);
        let used_blocks = self.used_blocks.load(Ordering::Relaxed);
        let blocks_free = max_blocks.saturating_sub(used_blocks);
        // `shmem_statfs` leaves `f_blocks`/`f_bfree` at 0 on an unlimited
        // mount — that zero IS how userspace spells "no limit here".
        let (blocks, blocks_free) = if max_blocks == 0 {
            (0, 0)
        } else {
            (max_blocks, blocks_free)
        };
        // `f_files = max_inodes`, `f_ffree = free_ispace / BOGO_INODE_SIZE`.
        let max_inodes = self.max_inodes.load(Ordering::Relaxed);
        let files_free = self
            .max_ispace()
            .saturating_sub(self.used_ispace.load(Ordering::Relaxed))
            / BOGO_INODE_SIZE;
        let (files, files_free) = if max_inodes == 0 {
            (0, 0)
        } else {
            (max_inodes, files_free)
        };
        FsStat {
            blocks,
            blocks_free,
            blocks_available: blocks_free,
            files,
            files_free,
            block_size: PAGE_SIZE as u32,
            name_len: 255,
            fragment_size: PAGE_SIZE as u32,
        }
    }

    fn reconfigure_tmpfs(&self, options: &str, total_pages: u64) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut requested_blocks = None;
        let mut requested_inodes = None;
        let mut seen_quota = false;
        let limits = self.quota_defaults();
        for raw in options.split(',').filter(|part| !part.is_empty()) {
            let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
            match key {
                "size" => {
                    requested_blocks = Some(parse_size_blocks(value, total_pages)?);
                }
                "nr_blocks" => {
                    let blocks = memparse_exact(value)?;
                    if blocks > i64::MAX as u64 {
                        return Err(FsError::InvalidData);
                    }
                    requested_blocks = Some(blocks);
                }
                "nr_inodes" => {
                    let inodes = memparse_exact(value)?;
                    if inodes > u64::MAX / BOGO_INODE_SIZE {
                        return Err(FsError::InvalidData);
                    }
                    requested_inodes = Some(inodes);
                }
                // Linux ignores root metadata on remount. The remaining
                // accepted initial-only policies are validated here too.
                "mode" => {
                    let _ = parse_octal_mode(value)?;
                }
                "uid" | "gid" => {
                    let _ = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
                }
                // "noswap" doesn't use fsparam_flag_no: there is no `swap`
                // spelling to turn it back off. NARF has no swap path at
                // all, so every mount is already noswap and this can never
                // be the "Cannot disable swap on remount" case.
                "noswap" | "inode64" | "inode32" if value.is_empty() => {}
                // `SHMEM_SEEN_QUOTA` on remount is only legal while quota is
                // already loaded — "Cannot enable quota on remount". The
                // request is then a no-op: `shmem_reconfigure` never applies
                // `quota_types`.
                "quota" | "usrquota" | "grpquota" if value.is_empty() => seen_quota = true,
                // "Cannot change global quota limit on remount" — a repeat of
                // the SAME limit is accepted, a different one is not.
                "usrquota_block_hardlimit" => {
                    if parse_quota_hardlimit(value)? != limits.usrquota_bhardlimit {
                        return Err(FsError::InvalidData);
                    }
                }
                "grpquota_block_hardlimit" => {
                    if parse_quota_hardlimit(value)? != limits.grpquota_bhardlimit {
                        return Err(FsError::InvalidData);
                    }
                }
                "usrquota_inode_hardlimit" => {
                    if parse_quota_hardlimit(value)? != limits.usrquota_ihardlimit {
                        return Err(FsError::InvalidData);
                    }
                }
                "grpquota_inode_hardlimit" => {
                    if parse_quota_hardlimit(value)? != limits.grpquota_ihardlimit {
                        return Err(FsError::InvalidData);
                    }
                }
                "huge" if value == "never" => {}
                "mpol" if value == "default" || value == "local" => {}
                _ => return Err(FsError::InvalidData),
            }
        }
        // `shmem_reconfigure` takes `sbinfo->stat_lock` for the whole
        // validate-then-apply sequence. Remount is rare and must not
        // interleave with another remount, so the quota lock serves as that
        // lock here even when no quota is on; the capacity counters it
        // guards are atomics read under it.
        let quotas = self.quotas.lock();
        if seen_quota && !(quotas.usr.on || quotas.grp.on) {
            return Err(FsError::InvalidData);
        }
        // Linux only validates a NONZERO request; `size=0` / `nr_inodes=0`
        // lift the limit unconditionally.
        if let Some(blocks) = requested_blocks {
            if blocks != 0 {
                if self.max_blocks.load(Ordering::Relaxed) == 0 {
                    return Err(FsError::InvalidData); // "Cannot retroactively limit size"
                }
                if self.used_blocks.load(Ordering::Relaxed) > blocks {
                    return Err(FsError::InvalidData); // "Too small a size for current use"
                }
            }
            self.max_blocks.store(blocks, Ordering::Relaxed);
        }
        if let Some(inodes) = requested_inodes {
            if inodes != 0 {
                if self.max_inodes.load(Ordering::Relaxed) == 0 {
                    return Err(FsError::InvalidData);
                }
                if inodes.saturating_mul(BOGO_INODE_SIZE) < self.used_ispace.load(Ordering::Relaxed)
                {
                    return Err(FsError::InvalidData); // "Too few inodes for current use"
                }
            }
            self.max_inodes.store(inodes, Ordering::Relaxed);
        }
        drop(quotas);
        Ok(())
    }

    // ── quotactl backing (only meaningful on a tmpfs mount) ─────────

    fn quota_table_mut(state: &mut QuotaState, kind: QuotaKind) -> &mut QuotaTable {
        match kind {
            QuotaKind::User => &mut state.usr,
            QuotaKind::Group => &mut state.grp,
        }
    }

    fn quota_on(&self, kind: QuotaKind) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        Self::quota_table_mut(&mut state, kind).on = true;
        self.refresh_quota_active(&state);
        Ok(())
    }

    fn quota_off(&self, kind: QuotaKind) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        Self::quota_table_mut(&mut state, kind).on = false;
        self.refresh_quota_active(&state);
        Ok(())
    }

    fn quota_get(&self, kind: QuotaKind, id: u32) -> Result<FsDqBlk, FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        let table = Self::quota_table_mut(&mut state, kind);
        if !table.on {
            return Err(FsError::Unsupported);
        }
        Ok(dq_to_fsdqblk(&table.dquot(id)))
    }

    fn quota_get_next(&self, kind: QuotaKind, id: u32) -> Result<(u32, FsDqBlk), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        let table = Self::quota_table_mut(&mut state, kind);
        if !table.on {
            return Err(FsError::Unsupported);
        }
        match table.ids.range(id..).next() {
            Some((&nid, dq)) => Ok((nid, dq_to_fsdqblk(dq))),
            None => Err(FsError::NotFound),
        }
    }

    fn quota_set(&self, kind: QuotaKind, id: u32, blk: &FsDqBlk) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let now = quota_now_secs();
        let mut state = self.quotas.lock();
        let table = Self::quota_table_mut(&mut state, kind);
        if !table.on {
            return Err(FsError::Unsupported);
        }
        let (grace_b, grace_i) = (table.grace_blocks, table.grace_inodes);
        let fresh = table.fresh();
        let dq = table.ids.entry(id).or_insert(fresh);
        if blk.valid & QIF_BLIMITS != 0 {
            // `FsDqBlk` speaks fs blocks; the stored limit is bytes.
            dq.space_hard = blocks_to_space(blk.blocks_hard);
            dq.space_soft = blocks_to_space(blk.blocks_soft);
        }
        if blk.valid & QIF_ILIMITS != 0 {
            dq.inodes_hard = blk.inodes_hard;
            dq.inodes_soft = blk.inodes_soft;
        }
        if blk.valid & QIF_SPACE != 0 {
            dq.blocks_used = blk.blocks_used;
        }
        if blk.valid & QIF_INODES != 0 {
            dq.inodes_used = blk.inodes_used;
        }
        if blk.valid & QIF_BTIME != 0 {
            dq.btime = blk.btime;
        }
        if blk.valid & QIF_ITIME != 0 {
            dq.itime = blk.itime;
        }
        // Re-arm or clear the soft-limit grace clock against the new
        // limits/usage, unless the caller set the deadline explicitly.
        if blk.valid & QIF_BTIME == 0 {
            dq.btime = if dq.space_soft != 0 && blocks_to_space(dq.blocks_used) > dq.space_soft {
                now.saturating_add(grace_b)
            } else {
                0
            };
        }
        if blk.valid & QIF_ITIME == 0 {
            dq.itime = if dq.inodes_soft != 0 && dq.inodes_used > dq.inodes_soft {
                now.saturating_add(grace_i)
            } else {
                0
            };
        }
        Ok(())
    }

    fn quota_get_info(&self, kind: QuotaKind) -> Result<FsDqInfo, FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        let table = Self::quota_table_mut(&mut state, kind);
        if !table.on {
            return Err(FsError::Unsupported);
        }
        Ok(FsDqInfo {
            bgrace: table.grace_blocks,
            igrace: table.grace_inodes,
            flags: 0,
            valid: 0,
        })
    }

    fn quota_set_info(&self, kind: QuotaKind, info: &FsDqInfo) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut state = self.quotas.lock();
        let table = Self::quota_table_mut(&mut state, kind);
        if !table.on {
            return Err(FsError::Unsupported);
        }
        if info.valid & IIF_BGRACE != 0 {
            table.grace_blocks = info.bgrace;
        }
        if info.valid & IIF_IGRACE != 0 {
            table.grace_inodes = info.igrace;
        }
        // IIF_FLAGS carries per-type feature flags NARF has no use for yet;
        // accept and ignore so `setquota -t` succeeds.
        let _ = IIF_FLAGS;
        Ok(())
    }
}

/// Snapshot a [`Dquot`] into the VFS-facing [`FsDqBlk`] (usage + limits, all
/// fields valid).
fn dq_to_fsdqblk(dq: &Dquot) -> FsDqBlk {
    FsDqBlk {
        // Stored in bytes (Linux `dqb_bhardlimit`), reported in fs blocks.
        blocks_hard: dq.space_hard / PAGE_SIZE,
        blocks_soft: dq.space_soft / PAGE_SIZE,
        blocks_used: dq.blocks_used,
        inodes_hard: dq.inodes_hard,
        inodes_soft: dq.inodes_soft,
        inodes_used: dq.inodes_used,
        btime: dq.btime,
        itime: dq.itime,
        valid: QIF_ALL,
    }
}

#[derive(Debug)]
struct InodeLease {
    superblock: Arc<MemSuper>,
    /// Owner the inode is currently charged to for quota; updated by
    /// `set_owners` (chown transfers the inode + block charge to the new owner).
    uid: AtomicU32,
    gid: AtomicU32,
    /// Inode space this node's extended attributes hold, in bytes. Tracked
    /// on the lease rather than the node so every node type releases it on
    /// the same path the inode charge is released on — `simple_xattrs_free`
    /// runs from `shmem_evict_inode` for files, directories, symlinks and
    /// special nodes alike.
    xattr_space: AtomicU64,
}

impl InodeLease {
    /// Transfer this node's quota charge — its inode plus `blocks` data blocks —
    /// from its current owner to (`new_uid`,`new_gid`) on chown, enforcing the
    /// new owner's quota. On `QuotaExceeded` nothing changes. Updates the lease's
    /// tracked owner so `Drop` later uncharges the right id.
    fn rechown(&self, new_uid: u32, new_gid: u32, blocks: u64) -> Result<(), FsError> {
        let old_uid = self.uid.load(Ordering::Relaxed);
        let old_gid = self.gid.load(Ordering::Relaxed);
        if self.superblock.quota_active.load(Ordering::Acquire) {
            self.superblock
                .quotas
                .lock()
                .transfer_owner(old_uid, old_gid, new_uid, new_gid, blocks, 1)?;
        }
        self.uid.store(new_uid, Ordering::Relaxed);
        self.gid.store(new_gid, Ordering::Relaxed);
        Ok(())
    }
}

impl InodeLease {
    /// Charge an extended attribute's inode space to this inode.
    fn charge_xattr(&self, bytes: u64) -> Result<(), FsError> {
        self.superblock.reserve_ispace(bytes)?;
        self.xattr_space.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Give back the inode space of an attribute that was replaced or
    /// removed.
    fn uncharge_xattr(&self, bytes: u64) {
        self.superblock.release_ispace(bytes);
        let _ = self
            .xattr_space
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(bytes))
            });
    }
}

impl Drop for InodeLease {
    fn drop(&mut self) {
        // `shmem_free_inode(sb, freed_ispace)` returns BOGO_INODE_SIZE plus
        // whatever `simple_xattrs_free` gave back, in one step.
        let held = self.xattr_space.load(Ordering::Relaxed);
        self.superblock.release_ispace(held + BOGO_INODE_SIZE);
        if self.superblock.quota_active.load(Ordering::Acquire) {
            self.superblock.quotas.lock().uncharge_owner(
                self.uid.load(Ordering::Relaxed),
                self.gid.load(Ordering::Relaxed),
                0,
                1,
            );
        }
    }
}

/// Anonymous device numbers, Linux `fs/super.c::get_anon_bdev`.
///
/// Every superblock without a block device still needs a distinct `st_dev`,
/// because that is what makes two files on different mounts different files:
/// `rename` across them is EXDEV, `find -xdev` prunes at the boundary, `du
/// -x` stops, and systemd's mount-point probe compares a directory's
/// `st_dev` with its parent's. NARF reported 0 for every mount, so every
/// tmpfs looked like the same filesystem as every other — and as the root.
static NEXT_ANON_MINOR: AtomicU64 = AtomicU64::new(1);

/// Linux `new_encode_dev` for major 0: the low 8 bits of the minor stay
/// put and the rest moves above the 12-bit major field.
fn alloc_anon_dev() -> u64 {
    let minor = NEXT_ANON_MINOR.fetch_add(1, Ordering::Relaxed);
    (minor & 0xff) | ((minor & !0xff) << 12)
}

/// Wall-clock nanoseconds since the epoch, the unit every inode timestamp
/// is stored in.
fn wall_now_ns() -> u64 {
    let w = narf_time::now_wall();
    (w.secs.max(0) as u64).saturating_mul(1_000_000_000) + w.nanos as u64
}

/// Linux `RELATIME_DISCARD_SECS`-equivalent: relatime refreshes an atime
/// that is more than a day stale even when nothing else changed
/// (`fs/inode.c::relatime_need_update`).
const RELATIME_STALE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// An inode's three timestamps, in wall-clock nanoseconds.
///
/// Kept as three atomics rather than a lock: a node exists for every file
/// the suite and a booted userspace create, and the per-node heap margin
/// here is tight (see the note on `MemFile`'s DAC atomics). Relaxed
/// ordering is right — these are independent metadata, not a
/// synchronisation point.
#[derive(Debug)]
struct Times {
    atime_ns: AtomicU64,
    mtime_ns: AtomicU64,
    ctime_ns: AtomicU64,
}

impl Times {
    /// A freshly created inode: `shmem_get_inode` stamps
    /// `simple_inode_init_ts`, so all three start at "now".
    fn now() -> Self {
        let now = wall_now_ns();
        Self {
            atime_ns: AtomicU64::new(now),
            mtime_ns: AtomicU64::new(now),
            ctime_ns: AtomicU64::new(now),
        }
    }

    /// A data change — `file_update_time` moves mtime AND ctime.
    fn touch_mtime(&self) {
        let now = wall_now_ns();
        self.mtime_ns.store(now, Ordering::Relaxed);
        self.ctime_ns.store(now, Ordering::Relaxed);
    }

    /// A metadata change — chmod, chown, link, rename, setxattr. Linux
    /// moves ONLY ctime here, which is exactly what makes ctime worth
    /// reporting separately: `chmod` must not make a file look rebuilt to
    /// `make`.
    fn touch_ctime(&self) {
        self.ctime_ns.store(wall_now_ns(), Ordering::Relaxed);
    }

    /// `fs/inode.c::touch_atime` under the default `relatime` mount
    /// policy, whose rule is `relatime_need_update`:
    ///
    /// ```text
    /// if (inode_get_atime <= inode_get_mtime) return 1;
    /// if (inode_get_atime <= inode_get_ctime) return 1;
    /// if ((long)(now.tv_sec - atime.tv_sec) >= 24*60*60) return 1;
    /// return 0;
    /// ```
    ///
    /// i.e. atime is refreshed only when it is older than the last change
    /// or a day stale — which is why a read loop over a warm file does not
    /// keep dirtying its inode.
    fn touch_atime(&self) {
        let atime = self.atime_ns.load(Ordering::Relaxed);
        let now = wall_now_ns();
        let needs_update = atime <= self.mtime_ns.load(Ordering::Relaxed)
            || atime <= self.ctime_ns.load(Ordering::Relaxed)
            || now.saturating_sub(atime) >= RELATIME_STALE_NS;
        if needs_update {
            self.atime_ns.store(now, Ordering::Relaxed);
        }
    }

    fn atime(&self) -> u64 {
        self.atime_ns.load(Ordering::Relaxed)
    }

    fn mtime(&self) -> u64 {
        self.mtime_ns.load(Ordering::Relaxed)
    }

    fn ctime(&self) -> u64 {
        self.ctime_ns.load(Ordering::Relaxed)
    }
}

/// Linux `fs/xattr.c::simple_xattr_space` — the deterministic inode-space
/// charge for one extended attribute. The 40 is upstream's fixed stand-in
/// for `sizeof(struct simple_xattr)`, chosen so the number does not move
/// with the allocator or the word size.
fn simple_xattr_space(name: &str, size: usize) -> u64 {
    40 + size as u64 + name.len() as u64
}

/// An inode's extended attributes, with Linux's inode-space accounting.
///
/// tmpfs keeps xattrs in RAM like everything else, so they are budgeted
/// against the same `nr_inodes=` inode space an inode itself costs
/// (`shmem_xattr_handler_set`): setting one on a full mount returns ENOSPC,
/// and `statfs`'s `f_ffree` falls as attributes accumulate.
///
/// Every tmpfs inode type has one. `shmem_xattr_handlers` hangs off the
/// SUPERBLOCK, and `shmem_{inode,dir,special,symlink}_inode_operations` all
/// carry `.listxattr`, so directories, symlinks, sockets, FIFOs and device
/// nodes take attributes exactly as regular files do.
///
/// The map is boxed behind an `Option` and stays `None` until the first
/// attribute is set. That matters at MemFs's scale: a node exists for every
/// file the kernel-test suite and a booted userspace create, the vast
/// majority never carry an xattr, and the per-node heap margin here is
/// already tight enough that three extra spinlocks once tipped it (see the
/// atomics note on `MemFile`). An empty store is one pointer.
/// The attribute map itself. Boxed so an inode with no attributes — the
/// overwhelming majority — costs one pointer rather than a `BTreeMap`.
type XattrMap = Box<BTreeMap<String, Vec<u8>>>;

#[derive(Debug)]
struct Xattrs {
    entries: IrqSafeSpinLock<Option<XattrMap>>,
}

impl Xattrs {
    const fn new() -> Self {
        Self {
            entries: IrqSafeSpinLock::new(None),
        }
    }

    /// The half of `fs/xattr.c::xattr_permission` that needs the inode.
    ///
    /// `user.*` is refused on anything that is not a regular file or a
    /// directory, and the answer is asymmetric:
    ///
    /// ```text
    /// if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
    ///         return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
    /// ```
    ///
    /// A set or a remove is a write, so both get EPERM; a get is already
    /// ENODATA here because the attribute cannot have been stored.
    ///
    /// Name length, the `trusted.*` capability, and resolving the prefix to
    /// a handler at all are VFS decisions that do not need the inode, so
    /// they live in the syscall layer where Linux keeps them
    /// (`import_xattr_name`, `xattr_resolve_name`) — reaching this with an
    /// unknown prefix is possible only from an in-kernel caller, and
    /// `Unsupported` is the EOPNOTSUPP that produces.
    fn check_name(name: &str, allow_user: bool) -> Result<(), FsError> {
        if name.starts_with("user.") {
            return if allow_user {
                Ok(())
            } else {
                Err(FsError::OperationNotPermitted)
            };
        }
        if name.starts_with("trusted.") || name.starts_with("security.") {
            return Ok(());
        }
        Err(FsError::Unsupported)
    }

    fn set(
        &self,
        lease: &InodeLease,
        name: &str,
        value: &[u8],
        flags: u32,
        allow_user: bool,
    ) -> Result<(), FsError> {
        Self::check_name(name, allow_user)?;
        const XATTR_CREATE: u32 = 1;
        const XATTR_REPLACE: u32 = 2;
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
            return Err(FsError::InvalidData);
        }
        // Reserve BEFORE mutating, and give back only the space the
        // replaced value held — the order `shmem_xattr_handler_set` uses,
        // so a failed set leaves the budget exactly as it found it.
        let charge = simple_xattr_space(name, value.len());
        lease.charge_xattr(charge)?;
        let mut guard = self.entries.lock();
        let attrs = guard.get_or_insert_with(|| Box::new(BTreeMap::new()));
        let previous = attrs.get(name).map(|old| old.len());
        // `simple_xattr_set` tests the flag BITS, and tests CREATE first:
        // passing both is not EINVAL, it is EEXIST when the attribute is
        // there and ENODATA when it is not.
        let refusal = if previous.is_some() {
            (flags & XATTR_CREATE != 0).then_some(FsError::Busy)
        } else {
            (flags & XATTR_REPLACE != 0).then_some(FsError::NotFound)
        };
        if let Some(error) = refusal {
            drop(guard);
            lease.uncharge_xattr(charge);
            return Err(error);
        }
        attrs.insert(name.to_string(), value.to_vec());
        drop(guard);
        if let Some(old_len) = previous {
            lease.uncharge_xattr(simple_xattr_space(name, old_len));
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, FsError> {
        self.raw_get(name).ok_or(FsError::NotFound)
    }

    fn list(&self) -> Vec<u8> {
        let guard = self.entries.lock();
        let mut list = Vec::new();
        if let Some(attrs) = guard.as_ref() {
            for name in attrs.keys() {
                list.extend_from_slice(name.as_bytes());
                list.push(0);
            }
        }
        list
    }

    fn remove(&self, lease: &InodeLease, name: &str, allow_user: bool) -> Result<(), FsError> {
        // A remove carries MAY_WRITE, so `user.*` on a symlink or device
        // node is EPERM whether or not the attribute is there.
        Self::check_name(name, allow_user)?;
        match self.raw_remove(name) {
            Some(value) => {
                lease.uncharge_xattr(simple_xattr_space(name, value.len()));
                Ok(())
            }
            None => Err(FsError::NotFound),
        }
    }

    // ── uncharged accessors, for POSIX ACLs ───────────────────────────
    //
    // A tmpfs ACL is not a `simple_xattr`: `simple_set_acl` stores it in
    // the inode's cached-ACL pointer and `shmem_xattr_handler_set` never
    // sees it, so it costs no inode space. NARF keeps the encoded blob in
    // the same map for storage, and these three skip the accounting to
    // match.

    fn raw_get(&self, name: &str) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .as_ref()
            .and_then(|attrs| attrs.get(name).cloned())
    }

    fn raw_insert(&self, name: &str, value: Vec<u8>) {
        self.entries
            .lock()
            .get_or_insert_with(|| Box::new(BTreeMap::new()))
            .insert(String::from(name), value);
    }

    fn raw_remove(&self, name: &str) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .as_mut()
            .and_then(|attrs| attrs.remove(name))
    }
}

/// `fs/xattr.c::do_setxattr` -> `fs/posix_acl.c::do_set_acl` ->
/// `vfs_set_acl` -> `set_posix_acl` -> `simple_set_acl`, collapsed onto one
/// node and shared by every `MemFs` inode that can hold an ACL.
///
/// `value` is the raw `system.posix_acl_{access,default}` payload. An EMPTY
/// value, or a well-formed header with zero entries, removes the ACL:
/// `do_set_acl` only decodes `if (size)`, and `posix_acl_from_xattr`
/// returns NULL for a zero-entry header, so both reach
/// `vfs_set_acl(..., NULL)`.
///
/// `setxattr`'s `XATTR_CREATE`/`XATTR_REPLACE` flags are deliberately
/// ignored — `do_setxattr` drops them on the POSIX-ACL path, passing only
/// name/value/size to `do_set_acl`.
///
/// `is_dir` is `set_posix_acl`'s
/// `if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode)) return acl ?
/// -EACCES : 0;` — a default ACL is storable only on a directory, which is
/// what makes `setfacl -d` a directory-only operation and what stops the
/// inheritance chain at the first non-directory.
///
/// LINUX-GAP: `set_posix_acl` also requires `inode_owner_or_capable()`
/// (`-EPERM` otherwise). `FileOps`/`DirOps` methods carry no credential, so
/// that check has to live in the syscall layer; nothing calls it there yet,
/// so today any task that can reach the inode can set its ACL.
fn memfs_set_acl(
    xattrs: &Xattrs,
    perms: &AtomicU32,
    is_dir: bool,
    ty: AclType,
    value: &[u8],
) -> Result<(), FsError> {
    let acl = if value.is_empty() {
        None
    } else {
        PosixAcl::from_xattr(value)?
    };
    if ty == AclType::Default {
        if !is_dir {
            return match acl {
                Some(_) => Err(FsError::PermissionDenied),
                None => Ok(()),
            };
        }
        // A default ACL is inherited, never enforced, so unlike the access
        // ACL it does not touch the directory's mode.
        return match acl {
            Some(acl) => {
                acl.valid()?;
                xattrs.raw_insert(XATTR_NAME_POSIX_ACL_DEFAULT, acl.to_xattr());
                Ok(())
            }
            None => {
                xattrs.raw_remove(XATTR_NAME_POSIX_ACL_DEFAULT);
                Ok(())
            }
        };
    }
    let acl = match acl {
        Some(acl) => acl,
        None => {
            xattrs.raw_remove(XATTR_NAME_POSIX_ACL_ACCESS);
            return Ok(());
        }
    };
    acl.valid()?;
    // `simple_set_acl` -> `posix_acl_update_mode`: the mode's low 9 bits
    // become whatever the ACL says, and an ACL that is exactly expressible
    // as mode bits is not stored at all.
    //
    // LINUX-GAP: the `in_group_or_capable()` half of
    // `posix_acl_update_mode` drops S_ISGID when the caller is neither in
    // the file's group nor CAP_FSETID-privileged. There is no credential to
    // test here, so NARF passes `true` (keep the bit) — the same answer
    // Linux gives for the common case of the owner acting on their own
    // file, and never a widening of the rwx bits.
    let (mode, stored) = crate::posix_acl::posix_acl_update_mode(
        (perms.load(Ordering::Relaxed) & 0o7777) as u16,
        acl,
        true,
    )?;
    match stored {
        Some(acl) => xattrs.raw_insert(XATTR_NAME_POSIX_ACL_ACCESS, acl.to_xattr()),
        None => {
            xattrs.raw_remove(XATTR_NAME_POSIX_ACL_ACCESS);
        }
    }
    perms.store(mode as u32, Ordering::Relaxed);
    Ok(())
}

/// Default permission bits for a freshly minted `MemFile`: 0o666
/// (rw-rw-rw-), owned by root (0, 0). This preserves the historical
/// "root-can-do-anything, everyone has rw" behaviour so DAC enforcement
/// only bites when a file is explicitly minted with tighter perms.
const DEFAULT_PERMS: u16 = 0o666;

/// Monotonic inode allocator for in-memory nodes. Every `MemFile` /
/// `MemDir` / `MemSymlink` claims a unique, stable `st_ino` at
/// construction so distinct nodes never alias. This is load-bearing for
/// more than musl's DSO dedup: systemd's `rm_rf` refuses to descend when
/// a directory and its parent share `(st_dev, st_ino)` (its "you've hit a
/// filesystem root" guard). Previously every tmpfs node reported `ino 0`
/// (the size-0/mtime-0 synthetic fallback for directories), so every
/// `mkdir`-created temp subdir looked like `/` and systemd aborted with
/// "Attempted to remove entire root file system". The base is deliberately
/// high because NARF reports `st_dev = 0` for every mount, so a low base
/// would collide with ext2's small inode numbers (root = 2).
static NEXT_INO: AtomicU64 = AtomicU64::new(0x1000_0000);

/// Claim the next unique in-memory inode number.
fn alloc_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Default)]
struct FileData {
    len: u64,
    pages: BTreeMap<u64, Box<[u8]>>,
}

impl FileData {
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let available = self.len - offset;
        let count = core::cmp::min(buf.len() as u64, available) as usize;
        buf[..count].fill(0);
        let mut copied = 0;
        while copied < count {
            let absolute = offset + copied as u64;
            let index = absolute / PAGE_SIZE;
            let within = (absolute % PAGE_SIZE) as usize;
            let chunk = core::cmp::min(count - copied, PAGE_SIZE as usize - within);
            if let Some(page) = self.pages.get(&index) {
                buf[copied..copied + chunk].copy_from_slice(&page[within..within + chunk]);
            }
            copied += chunk;
        }
        count
    }

    fn missing_pages(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(len as u64)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FsError::NoSpace)?;
        let first = offset / PAGE_SIZE;
        let last = end / PAGE_SIZE;
        Ok((first..=last)
            .filter(|index| !self.pages.contains_key(index))
            .collect())
    }

    fn remove_pages_from(&mut self, first: u64) -> u64 {
        let old = core::mem::take(&mut self.pages);
        let mut removed = 0;
        for (index, page) in old {
            if index >= first {
                removed += 1;
            } else {
                self.pages.insert(index, page);
            }
        }
        removed
    }
}

/// In-memory file: a sparse, page-indexed byte buffer behind a lock, plus
/// per-node DAC metadata (low-9 permission bits + owner uid/gid).
struct MemFile {
    /// Unique, stable inode number (see [`NEXT_INO`]). Immutable after
    /// construction — a plain `u64`, not an atomic, per the per-node
    /// heap-cost note on the metadata fields below.
    ino: u64,
    data: IrqSafeSpinLock<FileData>,
    _inode_lease: InodeLease,
    /// DAC metadata as lock-free atomics — kept deliberately small: a
    /// MemFs node is created for every file in the kernel-test suite, so
    /// three spinlocks here (vs three `AtomicU32`) measurably grew the
    /// suite's heap footprint and tipped its margin. `perms` holds the
    /// low-9 rwxrwxrwx bits; `uid`/`gid` the owner. Relaxed ordering is
    /// fine — this is independent metadata, not a synchronisation point.
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    /// The three inode timestamps as wall-clock nanoseconds since the
    /// epoch. Three 8-byte atomics per node — deliberately NOT a lock, per
    /// the heap-margin note above. mtime is stamped by `write` and set
    /// explicitly through `FileOps::set_times` (utimensat/utime/utimes);
    /// ctime moves with every metadata change; atime follows relatime.
    times: Times,
    /// Hard links to this inode. Starts at 1 for a named file and at **0**
    /// for an `O_TMPFILE` inode — Linux creates that one with
    /// `inode->i_nlink == 0` and `linkat(AT_EMPTY_PATH)` is what raises it,
    /// so `fstat` on the fd reporting 0 is the documented way to tell an
    /// unlinked temporary apart from a named file.
    nlink: AtomicU32,
    /// Content/length generation used by the generic shared-mmap page cache.
    /// Zero is never published, so wrap simply skips it. A cache entry is
    /// reusable after its final unmap only while this generation matches.
    mmap_generation: AtomicU64,
    /// True when this node is a bound AF_UNIX socket (created by `bind()`
    /// on a pathname address). `stat`/`enumerate` then report S_IFSOCK so
    /// `stat`/`[ -S ]`/`ls -l`/`unlink` on the socket path behave like
    /// Linux (a pathname socket is a real filesystem inode). Immutable
    /// after creation — a plain `bool`, not an atomic, to stay off the
    /// per-node heap-cost path the atomics above were chosen for.
    sock: bool,
    xattrs: Xattrs,
}

impl MemFile {
    /// Mint a `MemFile` with default perms (0o666) and owner (0, 0).
    /// The filesystem instance this inode belongs to — NARF's `inode->i_sb`.
    /// Compared by `Arc` identity, never dereferenced for the comparison.
    fn superblock(&self) -> &Arc<MemSuper> {
        &self._inode_lease.superblock
    }

    fn new(superblock: &Arc<MemSuper>, bytes: &[u8]) -> Result<Self, FsError> {
        Self::new_with_attrs(superblock, bytes, DEFAULT_PERMS, 0, 0)
    }

    fn new_with_attrs(
        superblock: &Arc<MemSuper>,
        bytes: &[u8],
        perms: u16,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FsError> {
        let inode_lease = superblock.reserve_inode(uid, gid)?;
        let file = MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: inode_lease,
            perms: AtomicU32::new((perms & 0o7777) as u32),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            times: Times::now(),
            nlink: AtomicU32::new(1),
            mmap_generation: AtomicU64::new(1),
            sock: false,
            xattrs: Xattrs::new(),
        };
        if !bytes.is_empty() {
            // A seed is all-or-nothing: unlike a userspace write there is no
            // caller to hand a short count back to, so a partial fill would
            // silently create a truncated file. Dropping `file` here
            // releases both its inode and whatever blocks it did get.
            if file.write_inner(0, bytes)? != bytes.len() {
                return Err(FsError::NoSpace);
            }
        }
        Ok(file)
    }

    /// Mint a `MemFile` with explicit perms + owner. Used to seed files
    /// that must enforce a real DAC boundary (e.g. /etc/shadow 0600).
    fn with_perms_owner(bytes: Vec<u8>, perms: u16, uid: u32, gid: u32) -> Self {
        let superblock = MemSuper::new(MemFsKind::Generic, None, None);
        let file = MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: superblock
                .reserve_inode(uid, gid)
                .expect("unlimited memfs inode reservation"),
            perms: AtomicU32::new((perms & 0o7777) as u32),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            times: Times::now(),
            nlink: AtomicU32::new(1),
            mmap_generation: AtomicU64::new(1),
            sock: false,
            xattrs: Xattrs::new(),
        };
        let written = file
            .write_inner(0, &bytes)
            .expect("unlimited memfs seed write");
        assert_eq!(written, bytes.len(), "unlimited memfs seed write was short");
        file
    }

    /// Mint a pathname-AF_UNIX-socket node (S_IFSOCK) with the given perms.
    fn new_socket(superblock: &Arc<MemSuper>, perms: u16) -> Result<Self, FsError> {
        Ok(MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: superblock.reserve_inode(0, 0)?,
            perms: AtomicU32::new((perms & 0o7777) as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            times: Times::now(),
            nlink: AtomicU32::new(1),
            mmap_generation: AtomicU64::new(1),
            sock: true,
            xattrs: Xattrs::new(),
        })
    }

    /// Stamp mtime (and, as `file_update_time` does, ctime) = wall-now.
    /// Called on every successful write so `make`-style newer-than
    /// comparisons see fresh build outputs as newer than their sources.
    fn touch_mtime_now(&self) {
        self.times.touch_mtime();
    }

    fn bump_mmap_generation(&self) {
        let _ = self
            .mmap_generation
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                Some(value.wrapping_add(1).max(1))
            });
    }

    fn alloc_zero_page() -> Result<Box<[u8]>, FsError> {
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE_SIZE as usize)
            .map_err(|_| FsError::NoSpace)?;
        page.resize(PAGE_SIZE as usize, 0);
        Ok(page.into_boxed_slice())
    }

    /// Write `buf` at `offset`, returning how much of it landed.
    ///
    /// A write that runs out of room part-way returns a SHORT COUNT, not an
    /// error. `mm/filemap.c::generic_perform_write` — the loop tmpfs's
    /// `shmem_file_write_iter` runs — breaks out of its per-folio loop when
    /// `write_begin` fails and ends with:
    ///
    /// ```text
    /// if (!written)
    ///         return status;
    /// iocb->ki_pos += written;
    /// return written;
    /// ```
    ///
    /// so the error surfaces only when nothing at all was written; the next
    /// write is the one that reports ENOSPC. All-or-nothing was visibly
    /// wrong: `cp` onto a nearly-full `/tmp` left an EMPTY file and
    /// reported ENOSPC, where Linux fills the filesystem and reports the
    /// short write.
    ///
    /// The common case still charges every page it needs in one go; the
    /// per-page walk is only the fallback once that bulk reservation has
    /// been refused, so a successful write takes the superblock counters
    /// exactly once regardless of size.
    fn write_inner(&self, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(FsError::NoSpace)?;
        let uid = self.uid.load(Ordering::Relaxed);
        let gid = self.gid.load(Ordering::Relaxed);
        let mut data = self.data.lock();
        let missing = data.missing_pages(offset, buf.len())?;
        let count = missing.len() as u64;
        let superblock = &self._inode_lease.superblock;
        let bulk = superblock.reserve_blocks(uid, gid, count);
        if bulk.is_ok() {
            let mut allocated = Vec::new();
            let mut failure = None;
            if allocated.try_reserve_exact(missing.len()).is_err() {
                failure = Some(FsError::NoSpace);
            } else {
                for index in missing {
                    match Self::alloc_zero_page() {
                        Ok(page) => allocated.push((index, page)),
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    }
                }
            }
            match failure {
                None => {
                    for (index, page) in allocated {
                        data.pages.insert(index, page);
                    }
                    let copied = Self::fill_pages(&mut data, offset, buf);
                    debug_assert_eq!(copied, buf.len());
                    data.len = core::cmp::max(data.len, end);
                    // Publish the new generation before the data lock opens.
                    // A mapper which observes the mutated bytes can therefore
                    // never validate an idle fallback page against the
                    // preceding generation.
                    self.bump_mmap_generation();
                    drop(data);
                    self.touch_mtime_now();
                    return Ok(buf.len());
                }
                Some(error) => {
                    // The heap, not the mount, ran out. Hand the blocks back
                    // and fall through to the page-at-a-time walk, which can
                    // still place whatever pages it does manage to allocate.
                    drop(allocated);
                    superblock.release_blocks(uid, gid, count);
                    let _ = error;
                }
            }
        }
        // Slow path: charge and materialise one page at a time, in ascending
        // order, so what lands is the PREFIX of the write — a short write is
        // only meaningful if the bytes that made it are the first ones.
        let mut written = 0usize;
        let mut refusal = bulk.err();
        while written < buf.len() {
            let absolute = offset + written as u64;
            let index = absolute / PAGE_SIZE;
            let within = (absolute % PAGE_SIZE) as usize;
            let chunk = core::cmp::min(buf.len() - written, PAGE_SIZE as usize - within);
            if let alloc::collections::btree_map::Entry::Vacant(slot) = data.pages.entry(index) {
                if let Err(error) = superblock.reserve_blocks(uid, gid, 1) {
                    refusal = Some(error);
                    break;
                }
                match Self::alloc_zero_page() {
                    Ok(page) => {
                        slot.insert(page);
                    }
                    Err(error) => {
                        superblock.release_blocks(uid, gid, 1);
                        refusal = Some(error);
                        break;
                    }
                }
            }
            let page = data
                .pages
                .get_mut(&index)
                .expect("write materialised this page");
            page[within..within + chunk].copy_from_slice(&buf[written..written + chunk]);
            written += chunk;
        }
        if written == 0 {
            // `if (!written) return status;`
            return Err(refusal.unwrap_or(FsError::NoSpace));
        }
        data.len = core::cmp::max(data.len, offset + written as u64);
        self.bump_mmap_generation();
        drop(data);
        self.touch_mtime_now();
        Ok(written)
    }

    /// Copy `buf` into pages that are already materialised, returning the
    /// byte count. The caller guarantees every page in range exists.
    fn fill_pages(data: &mut FileData, offset: u64, buf: &[u8]) -> usize {
        let mut copied = 0;
        while copied < buf.len() {
            let absolute = offset + copied as u64;
            let index = absolute / PAGE_SIZE;
            let within = (absolute % PAGE_SIZE) as usize;
            let chunk = core::cmp::min(buf.len() - copied, PAGE_SIZE as usize - within);
            let page = data
                .pages
                .get_mut(&index)
                .expect("write reserved every missing page");
            page[within..within + chunk].copy_from_slice(&buf[copied..copied + chunk]);
            copied += chunk;
        }
        copied
    }

    fn punch_hole(&self, offset: u64, len: u64) -> Result<(), FsError> {
        let end = offset.checked_add(len).ok_or(FsError::InvalidData)?;
        let mut data = self.data.lock();
        let indexes: Vec<u64> = data
            .pages
            .range((offset / PAGE_SIZE)..end.div_ceil(PAGE_SIZE))
            .map(|(&index, _)| index)
            .collect();
        let mut released = 0;
        for index in indexes {
            let page_start = index * PAGE_SIZE;
            let page_end = page_start + PAGE_SIZE;
            if offset <= page_start && end >= page_end {
                data.pages.remove(&index);
                released += 1;
            } else if let Some(page) = data.pages.get_mut(&index) {
                let start = offset.saturating_sub(page_start) as usize;
                let stop = core::cmp::min(end.saturating_sub(page_start), PAGE_SIZE) as usize;
                if start < stop {
                    page[start..stop].fill(0);
                }
            }
        }
        self.bump_mmap_generation();
        drop(data);
        self._inode_lease.superblock.release_blocks(
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
            released,
        );
        Ok(())
    }

    /// `set_posix_acl` on a regular file — never a directory, so a DEFAULT
    /// ACL is refused. See [`memfs_set_acl`].
    fn set_acl(&self, ty: AclType, value: &[u8]) -> Result<(), FsError> {
        memfs_set_acl(&self.xattrs, &self.perms, false, ty, value)
    }
}

impl Drop for MemFile {
    fn drop(&mut self) {
        let blocks = self.data.lock().pages.len() as u64;
        self._inode_lease.superblock.release_blocks(
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
            blocks,
        );
    }
}

/// Mint a fresh empty in-memory file outside any directory. The
/// returned `FileOps` handle owns the storage; dropping the last
/// reference frees the bytes. Used by `sys_memfd_create` so an
/// anonymous fd can back a real `MemFile` without occupying a
/// VFS path.
pub fn new_anon_file() -> Arc<dyn FileOps> {
    let superblock = MemSuper::new_anonymous();
    Arc::new(MemFile::new(&superblock, &[]).expect("unlimited anonymous memfile"))
}

/// Mint a standalone in-memory file with explicit DAC metadata (initial
/// contents + low-9 perm bits + owner uid/gid). The returned `FileOps`
/// handle enforces those perms via `stat()`/`owners()`. Used by the DAC
/// kernel tests to construct a 0600 root-owned file (or a 0o666 world-rw
/// file) without going through a mounted FS.
pub fn new_file_with_perms_owner(
    bytes: Vec<u8>,
    perms: u16,
    uid: u32,
    gid: u32,
) -> Arc<dyn FileOps> {
    Arc::new(MemFile::with_perms_owner(bytes, perms, uid, gid))
}

impl fmt::Debug for MemFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemFile")
            .field("len", &self.data.lock().len)
            .finish_non_exhaustive()
    }
}

impl FileOps for MemFile {
    fn ino(&self) -> u64 {
        self.ino
    }

    /// `shmem_file_operations` sets no `.poll`, so a tmpfs regular file is
    /// not pollable — see `fs_inode_can_poll`. Constant rather than a type
    /// test because this type is only ever a regular file: MemFs has
    /// `MemFifo` and `MemSpecial` for the kinds that dispatch elsewhere, and
    /// both keep the pollable default.
    fn can_poll(&self) -> bool {
        false
    }

    /// Needed so a destination directory can recognise one of its own inodes.
    /// `MemDir::link_node` downcasts here to compare superblocks, and the
    /// default `None` would make every node — including this filesystem's own
    /// — look like it came from somewhere else.
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // `file_accessed()` -> `touch_atime()` on every read; the relatime
        // test inside keeps a warm read loop from restamping the inode.
        self.times.touch_atime();
        Box::pin(async move { Ok(self.data.lock().read(offset, buf)) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.write_inner(offset, buf) })
    }

    fn set_times(&self, atime_ns: Option<u64>, mtime_ns: Option<u64>) -> Result<(), FsError> {
        // `notify_change` with ATTR_ATIME/ATTR_MTIME also sets ctime:
        // "For the ATTR_*TIME cases the caller ... setattr_copy() updates
        // the ctime". So an explicit utimensat leaves a ctime of now, not
        // the time it set.
        if let Some(ns) = atime_ns {
            self.times.atime_ns.store(ns, Ordering::Relaxed);
        }
        if let Some(ns) = mtime_ns {
            self.times.mtime_ns.store(ns, Ordering::Relaxed);
        }
        if atime_ns.is_some() || mtime_ns.is_some() {
            self.times.touch_ctime();
        }
        Ok(())
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            nlink: self.nlink.load(Ordering::Relaxed),
            dev: self.superblock().dev,
            atime_ns: self.times.atime(),
            ctime_ns: self.times.ctime(),
            tracked: true,
        }
    }

    fn stat(&self) -> Stat {
        let data = self.data.lock();
        Stat {
            size: data.len,
            blocks: data.pages.len() as u64 * SECTORS_PER_PAGE,
            mode: Mode {
                file_type: if self.sock {
                    FileType::Socket
                } else {
                    FileType::File
                },
                perms: (self.perms.load(Ordering::Relaxed) & 0o7777) as u16,
            },
            // Report wall-ns as cycles so the stat ABI's cycles→ns
            // conversion (`stat_linux`: `cycles_to_ns(mtime_cycles)`)
            // hands userspace back the exact epoch-ns that utimensat /
            // the last write stored — the tar -x / cp -p / make
            // round-trip. 0 (never stamped) stays 0.
            //
            // `ns_to_cycles` is the exact inverse of the `cycles_to_ns`
            // the stat path applies, so the round-trip is lossless. The
            // old pair was `* cycles_per_ns()` here and `/ cycles_per_ns()`
            // there — self-cancelling ONLY because both were the same
            // truncated integer, which stopped being true the moment
            // either side moved to the calibrated scale.
            mtime_cycles: narf_time::ns_to_cycles(self.times.mtime()),
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // Transfer this file's block + inode charge to the new owner,
            // enforcing their quota (chown returns EDQUOT past a hard limit).
            // Hold `data` so the page count is stable against a concurrent
            // write; lock order is data -> super.
            let data = self.data.lock();
            self._inode_lease
                .rechown(uid, gid, data.pages.len() as u64)?;
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            drop(data);
            self.perms.fetch_and(!0o6000, Ordering::Relaxed);
            // `notify_change`/`setattr_copy`: an ownership change moves
            // ctime and leaves mtime alone.
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let perms = perms & 0o7777;
            // The other half of the mode<->ACL coherence rule. tmpfs —
            // the filesystem MemFs stands in for — ends
            // `mm/shmem.c::shmem_setattr` with
            //     if (attr->ia_valid & ATTR_MODE)
            //             error = posix_acl_chmod(idmap, dentry, inode->i_mode);
            // and `fs/posix_acl.c::posix_acl_chmod` runs
            // `__posix_acl_chmod_masq` over the ACCESS ACL. Without this a
            // `chmod` would move the mode bits while the ACL kept granting
            // the old rights — and since the mode's group triplet IS the
            // ACL_MASK, dropping it makes `chmod g-w` a no-op for every
            // maskable entry.
            if let Some(raw) = self.xattrs.raw_get(XATTR_NAME_POSIX_ACL_ACCESS) {
                // The stored blob is always a canonical `to_xattr()` of an
                // ACL that already passed `valid()` in `set_acl`, so the
                // decode cannot fail; the non-matching arm is unreachable
                // rather than a silent skip of a corrupt ACL.
                if let Ok(Some(mut acl)) = PosixAcl::from_xattr(&raw) {
                    acl.chmod_masq(perms)?;
                    self.xattrs
                        .raw_insert(XATTR_NAME_POSIX_ACL_ACCESS, acl.to_xattr());
                }
            }
            self.perms.store(perms as u32, Ordering::Relaxed);
            // chmod is a ctime-only change: making a file executable must
            // not make `make` think it was rebuilt.
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut data = self.data.lock();
            if len < data.len {
                let first_removed = len.div_ceil(PAGE_SIZE);
                let released = data.remove_pages_from(first_removed);
                if len % PAGE_SIZE != 0 {
                    if let Some(page) = data.pages.get_mut(&(len / PAGE_SIZE)) {
                        page[(len % PAGE_SIZE) as usize..].fill(0);
                    }
                }
                self._inode_lease.superblock.release_blocks(
                    self.uid.load(Ordering::Relaxed),
                    self.gid.load(Ordering::Relaxed),
                    released,
                );
            }
            // Extending a tmpfs file creates a hole. No page/block is charged
            // until a write or fallocate materialises it.
            data.len = len;
            self.bump_mmap_generation();
            drop(data);
            self.touch_mtime_now();
            Ok(())
        })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // `system.posix_acl_{access,default}` are not opaque blobs: Linux
            // routes them away from the generic xattr handler entirely
            // (`fs/xattr.c::do_setxattr` -> `set_posix_acl`/`vfs_set_acl`),
            // decodes and validates them, and keeps the file mode in step.
            // See `set_acl` below.
            if let Some(ty) = AclType::from_xattr_name(name) {
                return self.set_acl(ty, value);
            }
            // `xattr_permission` bars `user.*` on anything that is not a
            // regular file or a directory — including the S_IFSOCK inode a
            // bound pathname AF_UNIX socket leaves behind, which `MemFile`
            // also backs. Every attribute is charged inode space.
            self.xattrs
                .set(&self._inode_lease, name, value, flags, !self.sock)?;
            // `shmem_xattr_handler_set` ends with `inode_set_ctime_current`.
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.xattrs.get(name) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.xattrs.list()) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // `fs/xattr.c::removexattr` routes the two ACL names to
            // `vfs_remove_acl` -> `set_posix_acl(type, NULL)`, which for a
            // DEFAULT ACL on a non-directory is `return acl ? -EACCES : 0`
            // — a silent success, not ENODATA. A `MemFile` is never a
            // directory, so removing its (impossible) default ACL is a
            // no-op.
            //
            // Removing the ACCESS ACL takes the generic path below on
            // purpose: `simple_set_acl` calls `posix_acl_update_mode` with
            // a NULL acl, and `posix_acl_equiv_mode` returns 0 immediately
            // for a NULL acl without touching `*mode_p`. So the mode must
            // survive the removal untouched.
            // `fs/xattr.c::removexattr` routes BOTH ACL names away from
            // the generic path entirely:
            //
            //     if (is_posix_acl_xattr(name))
            //             return vfs_remove_acl(idmap, d, name);
            //
            // and `vfs_remove_acl` ends at `set_posix_acl(type, NULL)`.
            // For tmpfs that is `simple_set_acl(NULL)`, which caches a
            // NULL ACL and returns **0** — so removing an ACL that is not
            // there is a silent success, not ENODATA. (An absent DEFAULT
            // ACL on a non-directory takes `set_posix_acl`'s
            // `return acl ? -EACCES : 0` to the same 0.)
            //
            // The mode must survive either way: `posix_acl_update_mode`
            // hands a NULL acl to `posix_acl_equiv_mode`, which returns
            // immediately without touching `*mode_p`.
            if AclType::from_xattr_name(name).is_some() {
                if name == XATTR_NAME_POSIX_ACL_ACCESS {
                    self.xattrs.raw_remove(name);
                }
                return Ok(());
            }
            self.xattrs.remove(&self._inode_lease, name, !self.sock)?;
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            const KEEP_SIZE: u32 = 0x01;
            const PUNCH_HOLE: u32 = 0x02;
            const ZERO_RANGE: u32 = 0x10;
            if len == 0 || mode & !(KEEP_SIZE | PUNCH_HOLE | ZERO_RANGE) != 0 {
                return Err(FsError::Unsupported);
            }
            if mode & PUNCH_HOLE != 0 {
                if mode != PUNCH_HOLE | KEEP_SIZE {
                    return Err(FsError::Unsupported);
                }
                return self.punch_hole(offset, len);
            }
            let end = offset.checked_add(len).ok_or(FsError::NoSpace)?;
            let chunk = [0u8; PAGE_SIZE as usize];
            let old_len = self.data.lock().len;
            let mut position = offset;
            while position < end {
                let within = position % PAGE_SIZE;
                let count = core::cmp::min(PAGE_SIZE - within, end - position) as usize;
                if mode & ZERO_RANGE != 0
                    || !self.data.lock().pages.contains_key(&(position / PAGE_SIZE))
                {
                    self.write_inner(position, &chunk[..count])?;
                }
                position += count as u64;
            }
            let mut data = self.data.lock();
            let new_len = if mode & KEEP_SIZE != 0 {
                old_len
            } else {
                core::cmp::max(old_len, end)
            };
            // Plain fallocate over already-backed bytes is a semantic no-op.
            // Linux leaves both the inode contents and its page-cache folios
            // valid in that case; invalidating NARF's mmap cache here forced
            // the next mapper to re-read and re-snapshot an unchanged page.
            // A write_inner call above already advanced the generation while
            // holding this same data lock. Only a pure EOF extension still
            // needs a generation change here.
            if data.len != new_len {
                data.len = new_len;
                self.bump_mmap_generation();
            }
            drop(data);
            Ok(())
        })
    }

    fn mmap_cache_generation(&self) -> Option<u64> {
        Some(self.mmap_generation.load(Ordering::Acquire))
    }

    fn seek<'a>(&'a self, offset: u64, whence: u32) -> FsFuture<'a, u64> {
        Box::pin(async move {
            const SEEK_DATA: u32 = 3;
            const SEEK_HOLE: u32 = 4;
            let data = self.data.lock();
            if offset >= data.len {
                return Err(FsError::NoSpace);
            }
            let page_index = offset / PAGE_SIZE;
            match whence {
                SEEK_DATA => {
                    if data.pages.contains_key(&page_index) {
                        Ok(offset)
                    } else {
                        data.pages
                            .range((page_index + 1)..)
                            .next()
                            .map(|(&index, _)| index * PAGE_SIZE)
                            .filter(|&position| position < data.len)
                            .ok_or(FsError::NoSpace)
                    }
                }
                SEEK_HOLE => {
                    if !data.pages.contains_key(&page_index) {
                        return Ok(offset);
                    }
                    let mut index = page_index + 1;
                    while data.pages.contains_key(&index) {
                        index += 1;
                    }
                    Ok(core::cmp::min(index * PAGE_SIZE, data.len))
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

/// In-memory symlink: an immutable target path. The target is stored
/// verbatim and exposed to readers via `FileOps::read`; writes return
/// `ReadOnly` (POSIX symlink targets are immutable — `symlink(2)`
/// creates and `readlink(2)` reads, but there is no `writelink(2)`).
struct MemSymlink {
    /// Unique, stable inode number (see [`NEXT_INO`]).
    ino: u64,
    target: String,
    _inode_lease: InodeLease,
    uid: AtomicU32,
    gid: AtomicU32,
    times: Times,
    xattrs: Xattrs,
}

impl fmt::Debug for MemSymlink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemSymlink")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl FileOps for MemSymlink {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let bytes = self.target.as_bytes();
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
        Stat {
            size: self.target.len() as u64,
            blocks: 1,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // A symlink holds no data blocks; transfer only its inode charge.
            self._inode_lease.rechown(uid, gid, 0)?;
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            Ok(())
        })
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            // A symlink is never hard-linked by NARF's namespace ops.
            nlink: 1,
            dev: self._inode_lease.superblock.dev,
            atime_ns: self.times.atime(),
            ctime_ns: self.times.ctime(),
            tracked: true,
        }
    }

    // `shmem_symlink_inode_operations` carries `.listxattr`, and the
    // handlers hang off the superblock, so a tmpfs symlink holds extended
    // attributes. `user.*` is not among them: `xattr_permission` allows
    // that namespace only on regular files and directories.
    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.xattrs
                .set(&self._inode_lease, name, value, flags, false)
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.xattrs.get(name) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.xattrs.list()) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.xattrs.remove(&self._inode_lease, name, false) })
    }
}

struct MemSpecial {
    ino: u64,
    file_type: FileType,
    rdev: u64,
    _inode_lease: InodeLease,
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    times: Times,
    xattrs: Xattrs,
}

impl fmt::Debug for MemSpecial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemSpecial")
            .field("ino", &self.ino)
            .field("file_type", &self.file_type)
            .field("rdev", &self.rdev)
            .finish()
    }
}

impl FileOps for MemSpecial {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: self.file_type,
                perms: (self.perms.load(Ordering::Relaxed) & 0o7777) as u16,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // A special node holds no data blocks; transfer only its inode
            // charge to the new owner (enforcing their inode quota).
            self._inode_lease.rechown(uid, gid, 0)?;
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            self.perms.fetch_and(!0o6000, Ordering::Relaxed);
            Ok(())
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
            Ok(())
        })
    }

    fn rdev(&self) -> u64 {
        self.rdev
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            nlink: 1,
            dev: self._inode_lease.superblock.dev,
            atime_ns: self.times.atime(),
            ctime_ns: self.times.ctime(),
            tracked: true,
        }
    }

    // `shmem_special_inode_operations` carries `.listxattr`; a device node
    // or socket on tmpfs holds `trusted.*`/`security.*` attributes (SELinux
    // labels device nodes this way) but not `user.*`.
    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.xattrs
                .set(&self._inode_lease, name, value, flags, false)
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.xattrs.get(name) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.xattrs.list()) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.xattrs.remove(&self._inode_lease, name, false) })
    }
}

/// A named FIFO plus its tmpfs/ramfs inode reservation. Open descriptions
/// retain this wrapper, so unlink cannot release inode quota prematurely.
struct MemFifo {
    node: Arc<crate::fifo::FifoNode>,
    _inode_lease: InodeLease,
    times: Times,
    xattrs: Xattrs,
}

impl FileOps for MemFifo {
    fn ino(&self) -> u64 {
        self.node.ino()
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        self.node.read(offset, buf)
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        self.node.write(offset, buf)
    }

    fn stat(&self) -> Stat {
        self.node.stat()
    }

    fn owners(&self) -> (u32, u32) {
        self.node.owners()
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        self.node.set_owners(uid, gid)
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.node.set_perms(perms)
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn fifo_shared(&self) -> Option<Arc<crate::fifo::FifoShared>> {
        self.node.fifo_shared()
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            nlink: 1,
            dev: self._inode_lease.superblock.dev,
            atime_ns: self.times.atime(),
            ctime_ns: self.times.ctime(),
            tracked: true,
        }
    }

    // A FIFO is one of `shmem_special_inode_operations`' inodes, so it holds
    // extended attributes — `trusted.*`/`security.*` only, since
    // `xattr_permission` confines `user.*` to regular files and directories.
    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.xattrs
                .set(&self._inode_lease, name, value, flags, false)
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.xattrs.get(name) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.xattrs.list()) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.xattrs.remove(&self._inode_lease, name, false) })
    }
}

/// One directory entry. The discriminant carries either an `Arc`-
/// owned file, an `Arc`-owned subdirectory, an `Arc`-owned symlink,
/// an externally-minted node filed in via `link_node` (the O_TMPFILE
/// materialisation target), or an `Arc`-owned named-pipe (FIFO) node;
/// all kinds drop their underlying storage when the last reference
/// disappears.
enum Entry {
    File(Arc<MemFile>),
    Dir(Arc<MemDir>),
    Symlink(Arc<MemSymlink>),
    Special(Arc<MemSpecial>),
    /// A file node minted outside this directory and later filed into it
    /// by `DirOps::link_node` — the materialisation target of an
    /// `O_TMPFILE` fd's `linkat(AT_EMPTY_PATH)`. Held as a trait object
    /// so the fd and the name alias the exact same inode (a write through
    /// either is visible via the other). Its file type comes from
    /// `stat()` rather than a discriminant.
    Node(Arc<dyn FileOps>),
    /// A named pipe. The `FifoNode` owns the shared pipe buffer; every
    /// `open()` of this entry resolves to the same node (and thus the same
    /// buffer), so all openers rendezvous — see `crate::fifo`.
    Fifo(Arc<MemFifo>),
}

// Linux's dcache hashes directory/name pairs and performs the common lookup
// without serializing all readers on the inode lock. MemFs keeps its mutable
// BTreeMap authoritative, but remembers successful subdirectory lookups in a
// bounded per-CPU cache. Entries hold Weak references so an unlinked directory
// still releases its inode/quota when the last real user goes away.
const MEMDIR_CACHE_WAYS: usize = 8;

struct MemDirCacheEntry {
    parent_ino: u64,
    generation: u64,
    name: String,
    dir: Weak<MemDir>,
}

struct MemDirCache {
    entries: [Option<MemDirCacheEntry>; MEMDIR_CACHE_WAYS],
    replace: usize,
}

impl MemDirCache {
    const fn new() -> Self {
        Self {
            entries: [const { None }; MEMDIR_CACHE_WAYS],
            replace: 0,
        }
    }
}

static MEMDIR_CACHES: [IrqSafeSpinLock<MemDirCache>; narf_lib::percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(MemDirCache::new()) }; narf_lib::percpu::MAX_CPUS];

fn memdir_cache() -> &'static IrqSafeSpinLock<MemDirCache> {
    &MEMDIR_CACHES[narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1)]
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Arc<dyn FileOps>` isn't `Debug`, so a derive can't cover the
        // `Node` arm; render each variant by name.
        match self {
            Entry::File(file) => f.debug_tuple("File").field(file).finish(),
            Entry::Dir(dir) => f.debug_tuple("Dir").field(dir).finish(),
            Entry::Symlink(link) => f.debug_tuple("Symlink").field(link).finish(),
            Entry::Special(node) => f.debug_tuple("Special").field(node).finish(),
            Entry::Node(_) => f.debug_tuple("Node").finish(),
            Entry::Fifo(_) => f.debug_tuple("Fifo").finish(),
        }
    }
}

/// A directory node: owns the `BTreeMap` of children behind a lock.
/// `MemDir` is the unit of recursion — both the root and every
/// subdirectory created via `mkdir` are `MemDir`s.
struct MemDir {
    /// Unique, stable inode number (see [`NEXT_INO`]). Distinguishes a
    /// directory from its parent so systemd's `rm_rf` root-guard doesn't
    /// mistake a `mkdir`-created temp dir for the filesystem root.
    ino: u64,
    superblock: Arc<MemSuper>,
    _inode_lease: InodeLease,
    entries: IrqSafeSpinLock<BTreeMap<String, Entry>>,
    /// Invalidates cached `(this directory, child name)` lookups after a
    /// namespace mutation. Updated while `entries` is locked.
    entry_generation: AtomicU64,
    /// Directory permission bits (low 12). Defaults to 0o777; `chmod(2)`
    /// on the directory updates it so `stat` reflects the real mode —
    /// dbus/systemd require `XDG_RUNTIME_DIR` to not be group/other-
    /// writable, so `chmod 0700` on a tmpfs dir must actually take.
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    times: Times,
    /// Whether this directory carries a `system.posix_acl_default`.
    ///
    /// Every create in this directory has to ask — inheritance replaces the
    /// umask — and almost no directory has one, so the answer is kept in a
    /// byte instead of behind the xattr lock. Set and cleared by
    /// `set_xattr`/`remove_xattr` on the two ACL paths, which are the only
    /// writers of that entry.
    has_default_acl: core::sync::atomic::AtomicBool,
    /// Immediate SUBDIRECTORIES, so `st_nlink` can be Linux's
    /// `2 + subdirs` without walking the entry map on every `stat`.
    /// Maintained under the `entries` lock alongside the map itself.
    ///
    /// `find` reads a directory's link count to decide whether it can hold
    /// subdirectories at all (the leaf optimisation): a count of exactly 2
    /// means every remaining child is a non-directory and need not be
    /// stat'd. Reporting a flat 1 disabled that for every directory.
    subdirs: AtomicU32,
    /// `shmem_dir_inode_operations` carries `.listxattr`, so a tmpfs
    /// directory takes extended attributes like any other inode — this is
    /// where an SELinux label on `/tmp` itself lives.
    xattrs: Xattrs,
}

impl fmt::Debug for MemDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemDir")
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl MemDir {
    /// Record that a subdirectory appeared or disappeared, so `st_nlink`
    /// stays `2 + subdirs`.
    fn adjust_subdirs(&self, delta: i32) {
        if delta > 0 {
            self.subdirs.fetch_add(delta as u32, Ordering::Relaxed);
        } else if delta < 0 {
            let _ = self
                .subdirs
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(count.saturating_sub((-delta) as u32))
                });
        }
    }

    /// A namespace change in this directory: `shmem_{create,mkdir,unlink,
    /// rmdir,rename2,…}` all end at `inode_set_mtime_to_ts(dir,
    /// inode_set_ctime_current(dir))`, so both stamps move together.
    fn touch_dir_mtime(&self) {
        self.times.touch_mtime();
    }

    /// Adjust the link count of the inode an entry names, when the entry
    /// itself is added or removed. Directories are not counted here — their
    /// link count is derived from [`MemDir::subdirs`].
    /// Whether an entry names a subdirectory, i.e. whether moving it
    /// changes a parent's `st_nlink`.
    fn entry_is_dir(entry: &Entry) -> bool {
        matches!(entry, Entry::Dir(_))
    }

    /// Both directories a rename touched: `simple_rename_timestamp` stamps
    /// mtime+ctime on the old AND new parent. The moved inode's own ctime
    /// is stamped at the point it is re-filed, where the entry is still in
    /// hand.
    fn stamp_rename(&self, destination: &MemDir) {
        self.touch_dir_mtime();
        if !core::ptr::eq(self, destination) {
            destination.touch_dir_mtime();
        }
    }

    fn adjust_entry_nlink(entry: &Entry, delta: i32) {
        let file = match entry {
            Entry::File(file) => Some(&**file),
            Entry::Node(node) => node.as_any().and_then(|any| any.downcast_ref::<MemFile>()),
            _ => None,
        };
        if let Some(file) = file {
            let _ = file
                .nlink
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(if delta >= 0 {
                        count.saturating_add(delta as u32)
                    } else {
                        count.saturating_sub((-delta) as u32)
                    })
                });
            // Adding or dropping a name is a change to the INODE's
            // metadata: `shmem_link`/`shmem_unlink` stamp
            // `inode_set_ctime_current(inode)` on the target.
            file.times.touch_ctime();
        }
    }

    #[inline]
    fn bump_entry_generation(&self) {
        self.entry_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn cached_dir(&self, name: &str, generation: u64) -> Option<Arc<MemDir>> {
        let cache = memdir_cache().lock();
        cache
            .entries
            .iter()
            .flatten()
            .find(|entry| {
                entry.parent_ino == self.ino && entry.generation == generation && entry.name == name
            })?
            .dir
            .upgrade()
    }

    fn cache_dir(&self, name: &str, generation: u64, dir: &Arc<MemDir>) {
        if self.entry_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let entry = MemDirCacheEntry {
            parent_ino: self.ino,
            generation,
            name: name.to_string(),
            dir: Arc::downgrade(dir),
        };
        let evicted = {
            let mut cache = memdir_cache().lock();
            if self.entry_generation.load(Ordering::Acquire) != generation {
                return;
            }
            let index = cache
                .entries
                .iter()
                .position(|slot| {
                    slot.as_ref()
                        .map(|old| {
                            old.parent_ino == self.ino && old.name == name
                                || old.dir.strong_count() == 0
                        })
                        .unwrap_or(true)
                })
                .unwrap_or_else(|| {
                    let index = cache.replace;
                    cache.replace = (cache.replace + 1) % MEMDIR_CACHE_WAYS;
                    index
                });
            cache.entries[index].replace(entry)
        };
        drop(evicted);
    }

    fn contains_dir(&self, needle: *const MemDir) -> bool {
        if core::ptr::eq(self, needle) {
            return true;
        }
        let children: Vec<Arc<MemDir>> = self
            .entries
            .lock()
            .values()
            .filter_map(|entry| match entry {
                Entry::Dir(dir) => Some(Arc::clone(dir)),
                _ => None,
            })
            .collect();
        children.iter().any(|dir| dir.contains_dir(needle))
    }

    fn validate_replacement(source: &Entry, destination: &Entry) -> Result<(), FsError> {
        match (source, destination) {
            (Entry::Dir(_), Entry::Dir(dir)) if !dir.entries.lock().is_empty() => {
                Err(FsError::Busy)
            }
            (Entry::Dir(_), Entry::Dir(_)) => Ok(()),
            (Entry::Dir(_), _) | (_, Entry::Dir(_)) => Err(FsError::InvalidPath),
            _ => Ok(()),
        }
    }

    fn rename_entry(
        &self,
        old_name: &str,
        destination: &MemDir,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
            || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
        {
            return Err(FsError::Unsupported);
        }
        if !Arc::ptr_eq(&self.superblock, &destination.superblock) {
            return Err(FsError::InvalidPath);
        }
        if core::ptr::eq(self, destination) && old_name == new_name {
            return self
                .entries
                .lock()
                .contains_key(old_name)
                .then_some(())
                .ok_or(FsError::NotFound);
        }

        let moving_dir = self
            .entries
            .lock()
            .get(old_name)
            .and_then(|entry| match entry {
                Entry::Dir(dir) => Some(Arc::clone(dir)),
                _ => None,
            });
        if moving_dir
            .as_ref()
            .is_some_and(|dir| dir.contains_dir(destination as *const MemDir))
        {
            return Err(FsError::InvalidPath);
        }

        if core::ptr::eq(self, destination) {
            let mut entries = self.entries.lock();
            if flags == RENAME_EXCHANGE {
                let old = entries.remove(old_name).ok_or(FsError::NotFound)?;
                let new = match entries.remove(new_name) {
                    Some(new) => new,
                    None => {
                        entries.insert(old_name.to_string(), old);
                        return Err(FsError::NotFound);
                    }
                };
                entries.insert(old_name.to_string(), new);
                entries.insert(new_name.to_string(), old);
                self.bump_entry_generation();
                drop(entries);
                // Both entries keep the same parent, so no link count
                // moves; only the timestamps do.
                self.stamp_rename(self);
                return Ok(());
            }
            if flags == RENAME_NOREPLACE && entries.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            let source = entries.remove(old_name).ok_or(FsError::NotFound)?;
            if let Some(target) = entries.get(new_name) {
                if let Err(error) = Self::validate_replacement(&source, target) {
                    entries.insert(old_name.to_string(), source);
                    return Err(error);
                }
            }
            // A replaced destination loses its name — for a file that is a
            // link count going down (and possibly to zero), for a directory
            // it is one fewer `..` pointing at this one.
            // The moved inode's name changed but its data did not, so it
            // takes a ctime stamp and no link-count change.
            Self::adjust_entry_nlink(&source, 0);
            if let Some(replaced) = entries.insert(new_name.to_string(), source) {
                Self::adjust_entry_nlink(&replaced, -1);
                if Self::entry_is_dir(&replaced) {
                    self.adjust_subdirs(-1);
                }
            }
            self.bump_entry_generation();
            drop(entries);
            self.stamp_rename(self);
            return Ok(());
        }

        let self_first = (self as *const Self as usize) < (destination as *const Self as usize);
        let (mut first, mut second) = if self_first {
            (self.entries.lock(), destination.entries.lock())
        } else {
            (destination.entries.lock(), self.entries.lock())
        };
        let (source_entries, destination_entries) = if self_first {
            (&mut first, &mut second)
        } else {
            (&mut second, &mut first)
        };
        if flags == RENAME_EXCHANGE {
            let old = source_entries.remove(old_name).ok_or(FsError::NotFound)?;
            let new = match destination_entries.remove(new_name) {
                Some(new) => new,
                None => {
                    source_entries.insert(old_name.to_string(), old);
                    return Err(FsError::NotFound);
                }
            };
            // Each entry changes parent, so a directory on either side
            // moves its `..` link with it.
            let old_is_dir = Self::entry_is_dir(&old);
            let new_is_dir = Self::entry_is_dir(&new);
            source_entries.insert(old_name.to_string(), new);
            destination_entries.insert(new_name.to_string(), old);
            self.bump_entry_generation();
            destination.bump_entry_generation();
            drop(first);
            drop(second);
            if old_is_dir {
                self.adjust_subdirs(-1);
                destination.adjust_subdirs(1);
            }
            if new_is_dir {
                destination.adjust_subdirs(-1);
                self.adjust_subdirs(1);
            }
            self.stamp_rename(destination);
            return Ok(());
        }
        if flags == RENAME_NOREPLACE && destination_entries.contains_key(new_name) {
            return Err(FsError::Busy);
        }
        let source = source_entries.remove(old_name).ok_or(FsError::NotFound)?;
        if let Some(target) = destination_entries.get(new_name) {
            if let Err(error) = Self::validate_replacement(&source, target) {
                source_entries.insert(old_name.to_string(), source);
                return Err(error);
            }
        }
        let source_is_dir = Self::entry_is_dir(&source);
        Self::adjust_entry_nlink(&source, 0);
        if let Some(replaced) = destination_entries.insert(new_name.to_string(), source) {
            Self::adjust_entry_nlink(&replaced, -1);
            if Self::entry_is_dir(&replaced) {
                destination.adjust_subdirs(-1);
            }
        }
        self.bump_entry_generation();
        destination.bump_entry_generation();
        drop(first);
        drop(second);
        if source_is_dir {
            self.adjust_subdirs(-1);
            destination.adjust_subdirs(1);
        }
        self.stamp_rename(destination);
        Ok(())
    }

    fn clone_linkable(entry: &Entry) -> Result<Entry, FsError> {
        match entry {
            Entry::Dir(_) => Err(FsError::InvalidPath),
            Entry::File(file) => Ok(Entry::File(Arc::clone(file))),
            Entry::Symlink(link) => Ok(Entry::Symlink(Arc::clone(link))),
            Entry::Special(node) => Ok(Entry::Special(Arc::clone(node))),
            Entry::Node(node) => Ok(Entry::Node(Arc::clone(node))),
            Entry::Fifo(node) => Ok(Entry::Fifo(Arc::clone(node))),
        }
    }
}

impl DirOps for MemDir {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            Entry::File(f) => Some(Arc::clone(f) as Arc<dyn FileOps>),
            Entry::Symlink(s) => Some(Arc::clone(s) as Arc<dyn FileOps>),
            Entry::Special(node) => Some(Arc::clone(node) as Arc<dyn FileOps>),
            Entry::Node(n) => Some(Arc::clone(n)),
            Entry::Fifo(p) => Some(Arc::clone(p) as Arc<dyn FileOps>),
            Entry::Dir(_) => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let generation = self.entry_generation.load(Ordering::Acquire);
        if let Some(dir) = self.cached_dir(name, generation) {
            return Some(dir as Arc<dyn DirOps>);
        }
        let (dir, generation) = {
            let g = self.entries.lock();
            let generation = self.entry_generation.load(Ordering::Acquire);
            let dir = match g.get(name)? {
                Entry::Dir(d) => Arc::clone(d),
                Entry::File(_) | Entry::Special(_) | Entry::Node(_) => return None,
                // Symlinks are never auto-traversed: `readlink`-style
                // callers want the target bytes via `lookup`, not a
                // resolved DirOps. Path resolution that wants to follow
                // a symlink chain must do so explicitly.
                Entry::Symlink(_) => return None,
                // A FIFO is a file, not a directory — never descendable.
                Entry::Fifo(_) => return None,
            };
            (dir, generation)
        };
        self.cache_dir(name, generation, &dir);
        Some(dir as Arc<dyn DirOps>)
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `DirEntry::name` is `&'static str`; we can't synthesise
        // that from our `String` keys without leaking. The kernel's
        // readdir path uses `enumerate()` (overridden below) which
        // returns owned `(String, FileType)` pairs instead.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let g = self.entries.lock();
        g.iter()
            .skip(cursor)
            .take(max)
            .map(|(name, entry)| {
                let ft = match entry {
                    Entry::File(f) if f.sock => FileType::Socket,
                    Entry::File(_) => FileType::File,
                    Entry::Dir(_) => FileType::Dir,
                    Entry::Symlink(_) => FileType::Symlink,
                    Entry::Special(node) => node.file_type,
                    // A linked-in node reports whatever type it stats as
                    // (an O_TMPFILE materialisation is a regular file).
                    Entry::Node(n) => n.stat().mode.file_type,
                    Entry::Fifo(_) => FileType::Fifo,
                };
                (name.clone(), ft)
            })
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(Entry::Dir(_)) => Err(FsError::InvalidPath),
                Some(Entry::File(_))
                | Some(Entry::Symlink(_))
                | Some(Entry::Special(_))
                | Some(Entry::Node(_))
                | Some(Entry::Fifo(_)) => {
                    if let Some(entry) = g.remove(name) {
                        Self::adjust_entry_nlink(&entry, -1);
                    }
                    drop(g);
                    self.touch_dir_mtime();
                    Ok(())
                }
            }
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let f = Arc::new(MemFile::new(&self.superblock, &[])?);
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            drop(g);
            self.touch_dir_mtime();
            Ok(f as Arc<dyn FileOps>)
        })
    }

    fn create_with_attrs<'a>(
        &'a self,
        name: &'a str,
        perms: u16,
        uid: u32,
        gid: u32,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let f = Arc::new(MemFile::new_with_attrs(
                &self.superblock,
                &[],
                perms,
                uid,
                gid,
            )?);
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            Ok(f as Arc<dyn FileOps>)
        })
    }

    /// Create an S_IFSOCK node — the filesystem inode Linux materialises
    /// when a pathname AF_UNIX socket is `bind()`-ed. Makes the bound path
    /// `stat`/`[ -S ]`/`ls`/`unlink`-visible (wayland, dbus, and shells all
    /// probe the socket path this way). Connection routing still goes
    /// through the socket layer's LISTENERS registry; this node is the
    /// filesystem-visible marker.
    fn create_socket<'a>(&'a self, name: &'a str, perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let f = Arc::new(MemFile::new_socket(&self.superblock, perms)?);
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            Ok(f as Arc<dyn FileOps>)
        })
    }

    /// Materialise a special node. Only `FileType::Fifo` is honoured on
    /// tmpfs — `mkfifo`/`mknod(S_IFIFO)` on `/run`, `/tmp`, `/etc`. The FIFO
    /// node owns a fresh shared pipe buffer; every later `open()` of this
    /// path resolves to the same node (`lookup` above), so all openers
    /// rendezvous on that one buffer. Device / block nodes aren't backed by
    /// tmpfs (return `Unsupported` so the syscall layer falls back to a
    /// plain file, matching the pre-FIFO behaviour); the `rdev` argument is
    /// unused for a FIFO.
    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if !matches!(
                file_type,
                FileType::Fifo | FileType::Special | FileType::Block
            ) {
                return Err(FsError::Unsupported);
            }
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            if file_type == FileType::Fifo {
                let fifo = Arc::new(MemFifo {
                    node: Arc::new(crate::fifo::FifoNode::new(alloc_ino(), DEFAULT_PERMS)),
                    _inode_lease: self.superblock.reserve_inode(0, 0)?,
                    times: Times::now(),
                    xattrs: Xattrs::new(),
                });
                g.insert(name.to_string(), Entry::Fifo(Arc::clone(&fifo)));
                drop(g);
                self.touch_dir_mtime();
                Ok(fifo as Arc<dyn FileOps>)
            } else {
                let node = Arc::new(MemSpecial {
                    ino: alloc_ino(),
                    file_type,
                    rdev,
                    _inode_lease: self.superblock.reserve_inode(0, 0)?,
                    perms: AtomicU32::new(DEFAULT_PERMS as u32),
                    uid: AtomicU32::new(0),
                    gid: AtomicU32::new(0),
                    times: Times::now(),
                    xattrs: Xattrs::new(),
                });
                g.insert(name.to_string(), Entry::Special(Arc::clone(&node)));
                drop(g);
                self.touch_dir_mtime();
                Ok(node as Arc<dyn FileOps>)
            }
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let d = Arc::new(MemDir {
                ino: alloc_ino(),
                superblock: Arc::clone(&self.superblock),
                _inode_lease: self.superblock.reserve_inode(0, 0)?,
                entries: IrqSafeSpinLock::new(BTreeMap::new()),
                entry_generation: AtomicU64::new(1),
                perms: AtomicU32::new(0o755),
                uid: AtomicU32::new(self.uid.load(Ordering::Relaxed)),
                gid: AtomicU32::new(self.gid.load(Ordering::Relaxed)),
                times: Times::now(),
                has_default_acl: core::sync::atomic::AtomicBool::new(false),
                subdirs: AtomicU32::new(0),
                xattrs: Xattrs::new(),
            });
            g.insert(name.to_string(), Entry::Dir(Arc::clone(&d)));
            self.bump_entry_generation();
            // A new subdirectory's `..` is a link to this one, so the
            // parent's `st_nlink` goes up (`shmem_mkdir` -> `inc_nlink(dir)`).
            self.adjust_subdirs(1);
            drop(g);
            self.touch_dir_mtime();
            Ok(d as Arc<dyn DirOps>)
        })
    }

    fn dir_mtime_ns(&self) -> u64 {
        self.times.mtime()
    }

    fn default_acl(&self) -> Option<Vec<u8>> {
        // The common directory has none, and this is on the create path.
        if !self.has_default_acl.load(Ordering::Acquire) {
            return None;
        }
        self.xattrs.raw_get(XATTR_NAME_POSIX_ACL_DEFAULT)
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            // Linux gives a directory one link for its name in the parent,
            // one for its own `.`, and one more for each child's `..`.
            nlink: 2u32.saturating_add(self.subdirs.load(Ordering::Relaxed)),
            dev: self.superblock.dev,
            atime_ns: self.times.atime(),
            ctime_ns: self.times.ctime(),
            tracked: true,
        }
    }

    fn dir_mode(&self) -> u16 {
        (self.perms.load(Ordering::Relaxed) & 0o7777) as u16
    }

    fn set_dir_mode(&self, perms: u16) {
        self.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
    }

    fn dir_owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_dir_owners(&self, uid: u32, gid: u32) {
        self.uid.store(uid, Ordering::Relaxed);
        self.gid.store(gid, Ordering::Relaxed);
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(Entry::File(_)) | Some(Entry::Special(_)) | Some(Entry::Node(_)) => {
                    Err(FsError::InvalidPath)
                }
                Some(Entry::Symlink(_)) => Err(FsError::InvalidPath),
                Some(Entry::Fifo(_)) => Err(FsError::InvalidPath),
                Some(Entry::Dir(d)) => {
                    if !d.entries.lock().is_empty() {
                        return Err(FsError::Busy);
                    }
                    g.remove(name);
                    self.bump_entry_generation();
                    self.adjust_subdirs(-1);
                    drop(g);
                    self.touch_dir_mtime();
                    Ok(())
                }
            }
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let s = Arc::new(MemSymlink {
                ino: alloc_ino(),
                target: target.to_string(),
                _inode_lease: self.superblock.reserve_inode(0, 0)?,
                uid: AtomicU32::new(self.uid.load(Ordering::Relaxed)),
                gid: AtomicU32::new(self.gid.load(Ordering::Relaxed)),
                times: Times::now(),
                xattrs: Xattrs::new(),
            });
            g.insert(name.to_string(), Entry::Symlink(Arc::clone(&s)));
            drop(g);
            self.touch_dir_mtime();
            Ok(s as Arc<dyn FileOps>)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.rename_entry(old_name, self, new_name, 0) })
    }

    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|value| value.downcast_ref::<MemDir>())
                .ok_or(FsError::InvalidPath)?;
            self.rename_entry(old_name, destination, new_name, flags)
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            // link(2) NEVER replaces an existing destination — EEXIST
            // (unlike rename's atomic-replace contract above).
            if g.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            // Cloning the Arc IS the hard link: both names now alias the
            // one backing node, so a write through either is visible via
            // the other, and the node lives until the last name (or open
            // fd) drops it — exactly the inode refcount model. A symlink
            // entry links the symlink itself (linkat(2) default without
            // AT_SYMLINK_FOLLOW). Directories can't be hard-linked
            // (Linux: EPERM).
            let aliased = Self::clone_linkable(g.get(old_name).ok_or(FsError::NotFound)?)?;
            Self::adjust_entry_nlink(&aliased, 1);
            g.insert(new_name.to_string(), aliased);
            drop(g);
            self.touch_dir_mtime();
            Ok(())
        })
    }

    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|value| value.downcast_ref::<MemDir>())
                .ok_or(FsError::InvalidPath)?;
            if !Arc::ptr_eq(&self.superblock, &destination.superblock) {
                return Err(FsError::InvalidPath);
            }
            let self_first = core::ptr::eq(self, destination)
                || (self as *const Self as usize) < (destination as *const Self as usize);
            let mut first = if self_first {
                self.entries.lock()
            } else {
                destination.entries.lock()
            };
            if core::ptr::eq(self, destination) {
                if first.contains_key(new_name) {
                    return Err(FsError::Busy);
                }
                let linked = Self::clone_linkable(first.get(old_name).ok_or(FsError::NotFound)?)?;
                Self::adjust_entry_nlink(&linked, 1);
                first.insert(new_name.to_string(), linked);
                drop(first);
                self.touch_dir_mtime();
                return Ok(());
            }
            let mut second = if self_first {
                destination.entries.lock()
            } else {
                self.entries.lock()
            };
            let (source, target) = if self_first {
                (&mut first, &mut second)
            } else {
                (&mut second, &mut first)
            };
            if target.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            let linked = Self::clone_linkable(source.get(old_name).ok_or(FsError::NotFound)?)?;
            Self::adjust_entry_nlink(&linked, 1);
            target.insert(new_name.to_string(), linked);
            drop(first);
            drop(second);
            destination.touch_dir_mtime();
            Ok(())
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    fn link_node<'a>(&'a self, name: &'a str, node: Arc<dyn FileOps>) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // `fs/namei.c::vfs_link`: `if (dir->i_sb != inode->i_sb) return
            // -EXDEV;`. A hard link cannot span filesystems, and this is the
            // only place that can tell — by the time the node arrives it is a
            // bare `Arc<dyn FileOps>` with nothing on it naming an owner.
            //
            // Without this the node was stored verbatim, so `linkat` by fd
            // from another mount SUCCEEDED, leaving a name in this directory
            // backed by an inode this filesystem does not own: its quota, its
            // link count and its lifetime all belong somewhere else. That is
            // worse than the wrong errno it was previously reported as.
            //
            // Two ways to fail it, both EXDEV: a node that is not a `MemFile`
            // at all came from a different filesystem, and a `MemFile` whose
            // superblock is not ours came from a different MOUNT of this one.
            // The second matters because every kernel-test MemFs is a separate
            // instance, so a same-type check alone would let them cross.
            let source = node
                .as_any()
                .and_then(|any| any.downcast_ref::<MemFile>())
                .ok_or(FsError::CrossDevice)?;
            // An anonymous inode belongs to no mount, so filing it here is an
            // adoption rather than a crossing — see `MemSuper::anonymous`.
            let source_sb = source.superblock();
            if !source_sb.is_anonymous() && !Arc::ptr_eq(&self.superblock, source_sb) {
                return Err(FsError::CrossDevice);
            }
            let mut g = self.entries.lock();
            // linkat NEVER replaces an existing name (like `link` above).
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            // Store the passed trait object verbatim: the caller's
            // O_TMPFILE fd and this new name now alias the one inode, so
            // the bytes already written through the fd are visible under
            // the name the instant it appears.
            let entry = Entry::Node(node);
            // `linkat(AT_EMPTY_PATH)` on an O_TMPFILE fd is what gives the
            // inode its first name: Linux's `shmem_tmpfile` leaves
            // `i_nlink == 0` and `vfs_link` -> `inc_nlink` raises it here.
            Self::adjust_entry_nlink(&entry, 1);
            g.insert(name.to_string(), entry);
            drop(g);
            self.touch_dir_mtime();
            Ok(())
        })
    }

    fn tmpfile<'a>(&'a self, mode: u32) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let file = Arc::new(MemFile::new(&self.superblock, &[])?);
            file.perms.store(mode & 0o7777, Ordering::Relaxed);
            // An O_TMPFILE inode has NO name: `shmem_tmpfile` reaches
            // `d_tmpfile`, which does `inode_dec_link_count(inode)` from 1
            // to 0. `fstat` on the fd reporting `st_nlink == 0` is how
            // userspace tells an unlinked temporary from a named file, and
            // it is also the state `linkat(AT_EMPTY_PATH)` raises.
            file.nlink.store(0, Ordering::Relaxed);
            Ok(file as Arc<dyn FileOps>)
        })
    }

    // A directory takes `user.*` as well: `xattr_permission` allows that
    // namespace on regular files AND directories.
    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // The two POSIX ACL names are not opaque blobs; a DIRECTORY is
            // also the only inode that can hold a DEFAULT ACL, which is
            // what `setfacl -d` installs and what every file created below
            // inherits.
            if let Some(ty) = AclType::from_xattr_name(name) {
                memfs_set_acl(&self.xattrs, &self.perms, true, ty, value)?;
                if ty == AclType::Default {
                    self.has_default_acl.store(
                        self.xattrs.raw_get(XATTR_NAME_POSIX_ACL_DEFAULT).is_some(),
                        Ordering::Release,
                    );
                }
                self.times.touch_ctime();
                return Ok(());
            }
            self.xattrs
                .set(&self._inode_lease, name, value, flags, true)?;
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.xattrs.get(name) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.xattrs.list()) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // `removexattr` routes both ACL names to `vfs_remove_acl` ->
            // `set_posix_acl(type, NULL)`, which returns 0 whether or not
            // an ACL was cached.
            if AclType::from_xattr_name(name).is_some() {
                self.xattrs.raw_remove(name);
                if name == XATTR_NAME_POSIX_ACL_DEFAULT {
                    self.has_default_acl.store(false, Ordering::Release);
                }
                self.times.touch_ctime();
                return Ok(());
            }
            self.xattrs.remove(&self._inode_lease, name, true)?;
            self.times.touch_ctime();
            Ok(())
        })
    }

    fn supports_tmpfile(&self) -> bool {
        true
    }
}

/// Mutable in-memory FS. Mount-time seeding is supported via
/// [`MemFs::with_seeds`] so the validate harness can mount
/// `/tmp` already populated with a few files for unlink/read probes.
pub struct MemFs {
    name: &'static str,
    root: Arc<MemDir>,
    superblock: Arc<MemSuper>,
}

impl fmt::Debug for MemFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemFs")
            .field("name", &self.name)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl MemFs {
    #[allow(clippy::too_many_arguments)]
    fn configured(
        name: &'static str,
        kind: MemFsKind,
        max_blocks: Option<u64>,
        max_inodes: Option<u64>,
        root_mode: u16,
        root_uid: u32,
        root_gid: u32,
    ) -> Result<Self, FsError> {
        Self::configured_quota(
            name,
            kind,
            max_blocks,
            max_inodes,
            root_mode,
            root_uid,
            root_gid,
            false,
            false,
            QuotaDefaults::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn configured_quota(
        name: &'static str,
        kind: MemFsKind,
        max_blocks: Option<u64>,
        max_inodes: Option<u64>,
        root_mode: u16,
        root_uid: u32,
        root_gid: u32,
        usrquota: bool,
        grpquota: bool,
        quota_limits: QuotaDefaults,
    ) -> Result<Self, FsError> {
        let superblock = MemSuper::with_quota(
            kind,
            max_blocks,
            max_inodes,
            usrquota,
            grpquota,
            quota_limits,
        );
        let root = Arc::new(MemDir {
            ino: alloc_ino(),
            superblock: Arc::clone(&superblock),
            _inode_lease: superblock.reserve_inode(0, 0)?,
            entries: IrqSafeSpinLock::new(BTreeMap::new()),
            entry_generation: AtomicU64::new(1),
            perms: AtomicU32::new(root_mode as u32),
            uid: AtomicU32::new(root_uid),
            gid: AtomicU32::new(root_gid),
            times: Times::now(),
            has_default_acl: core::sync::atomic::AtomicBool::new(false),
            subdirs: AtomicU32::new(0),
            xattrs: Xattrs::new(),
        });
        Ok(Self {
            name,
            root,
            superblock,
        })
    }

    /// Empty FS.
    pub fn new(name: &'static str) -> Self {
        Self::configured(name, MemFsKind::Generic, None, None, 0o755, 0, 0)
            .expect("unlimited MemFs root inode")
    }

    /// Construct with pre-seeded files at the root. Each `(name,
    /// contents)` pair becomes a regular file at the FS's root with
    /// `contents` bytes. Names must not contain `/`.
    pub fn with_seeds(name: &'static str, seeds: &[(&str, &[u8])]) -> Self {
        let fs = Self::new(name);
        {
            let mut g = fs.root.entries.lock();
            for (n, c) in seeds {
                let f =
                    Arc::new(MemFile::new(&fs.superblock, c).expect("unlimited MemFs seed inode"));
                g.insert((*n).to_string(), Entry::File(f));
            }
        }
        fs
    }

    /// Diagnostic: number of root-level entries currently in the FS.
    /// Subdirectory contents are not counted recursively.
    pub fn file_count(&self) -> usize {
        self.root.entries.lock().len()
    }

    /// Apply explicit DAC metadata (perms + owner) to a root-level file
    /// previously seeded via [`MemFs::with_seeds`]. Returns `true` if a
    /// regular file with `name` was found and updated, `false` otherwise
    /// (missing, or the entry is a dir/symlink). Used by boot-init to
    /// turn /etc/shadow into a real 0600 root-owned secret. Only the
    /// low-9 perm bits are stored.
    pub fn set_file_perms_owner(&self, name: &str, perms: u16, uid: u32, gid: u32) -> bool {
        let g = self.root.entries.lock();
        match g.get(name) {
            Some(Entry::File(f)) => {
                f.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
                f.uid.store(uid, Ordering::Relaxed);
                f.gid.store(gid, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }
}

impl FsInstance for MemFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::clone(&self.root) as Arc<dyn DirOps>
    }
    fn name(&self) -> &str {
        self.name
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move { Ok(self.superblock.statfs()) })
    }
}

/// Linux tmpfs: sparse page-backed files with per-mount block/inode limits,
/// mount-root metadata, and live statfs accounting.
pub struct TmpFs {
    inner: MemFs,
    /// RAM pages this mount sized itself against. Kept so a later
    /// `remount,size=N%` resolves the percentage against the same total,
    /// and so `show_options` can recover `shmem_default_max_blocks()`.
    total_pages: u64,
    /// The options this mount was created with. `show_options` needs the
    /// policy flags (`inode32`/`inode64`, `noswap`, the quota hard limits)
    /// that are not recoverable from the live superblock counters.
    options: TmpFsOptions,
}

impl fmt::Debug for TmpFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TmpFs")
            .field("inner", &self.inner)
            .field("total_pages", &self.total_pages)
            .finish()
    }
}

impl TmpFs {
    pub fn from_options(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        Self::from_options_with_total(options, narf_memory::frame::stats().total as u64, uid, gid)
    }

    pub fn from_options_with_total(
        options: &str,
        total_pages: u64,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FsError> {
        let parsed = TmpFsOptions::parse(options, total_pages, uid, gid)?;
        let inner = MemFs::configured_quota(
            "tmpfs",
            MemFsKind::Tmpfs,
            parsed.max_blocks,
            parsed.max_inodes,
            parsed.root_mode,
            parsed.root_uid,
            parsed.root_gid,
            parsed.usrquota,
            parsed.grpquota,
            parsed.quota_limits,
        )?;
        Ok(Self {
            inner,
            total_pages,
            options: parsed,
        })
    }

    /// Linux `mm/shmem.c::shmem_show_options` — the `,`-prefixed
    /// filesystem-specific option list `/proc/mounts` and
    /// `/proc/<pid>/mountinfo` carry for this mount.
    ///
    /// Every field is printed only when it differs from the default, which
    /// is what makes the common `tmpfs /run tmpfs rw,inode64 0 0` line
    /// short. Two deliberate shapes to keep:
    ///
    ///  * `size=` is in KiB (`K(sbinfo->max_blocks)`), not pages or bytes,
    ///    and is printed against the LIVE limit so it tracks a remount.
    ///  * `inode64`/`inode32` is always printed, since
    ///    `CONFIG_TMPFS_INODE64=y` is the modern default and userspace uses
    ///    the line to confirm which inode width it got.
    pub fn show_options(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let superblock = &self.inner.superblock;
        let max_blocks = superblock.max_blocks.load(Ordering::Relaxed);
        let max_inodes = superblock.max_inodes.load(Ordering::Relaxed);
        // `shmem_default_max_{blocks,inodes}()` — half of RAM, in pages.
        let default_half = self.total_pages / 2;
        if max_blocks != default_half {
            // K(x) = x << (PAGE_SHIFT - 10): pages to KiB.
            let _ = write!(
                out,
                ",size={}k",
                max_blocks.saturating_mul(PAGE_SIZE / 1024)
            );
        }
        if max_inodes != default_half {
            let _ = write!(out, ",nr_inodes={}", max_inodes);
        }
        let root = self.inner.root();
        let mode = root.dir_mode();
        if mode != (0o777 | 0o1000) {
            let _ = write!(out, ",mode={:03o}", mode);
        }
        let (uid, gid) = root.dir_owners();
        if uid != 0 {
            let _ = write!(out, ",uid={}", uid);
        }
        if gid != 0 {
            let _ = write!(out, ",gid={}", gid);
        }
        let _ = write!(out, ",inode{}", if self.options.inode64 { 64 } else { 32 });
        // `huge=` and `mpol=` are omitted: NARF is always `huge=never`
        // (`if (sbinfo->huge)` is false) with no superblock mempolicy,
        // which is exactly when Linux prints neither.
        if self.options.noswap {
            out.push_str(",noswap");
        }
        let (usr_on, grp_on) = {
            let state = superblock.quotas.lock();
            (state.usr.on, state.grp.on)
        };
        if usr_on {
            out.push_str(",usrquota");
        }
        if grp_on {
            out.push_str(",grpquota");
        }
        let limits = self.inner.superblock.quota_defaults();
        if limits.usrquota_bhardlimit != 0 {
            let _ = write!(
                out,
                ",usrquota_block_hardlimit={}",
                limits.usrquota_bhardlimit
            );
        }
        if limits.grpquota_bhardlimit != 0 {
            let _ = write!(
                out,
                ",grpquota_block_hardlimit={}",
                limits.grpquota_bhardlimit
            );
        }
        if limits.usrquota_ihardlimit != 0 {
            let _ = write!(
                out,
                ",usrquota_inode_hardlimit={}",
                limits.usrquota_ihardlimit
            );
        }
        if limits.grpquota_ihardlimit != 0 {
            let _ = write!(
                out,
                ",grpquota_inode_hardlimit={}",
                limits.grpquota_ihardlimit
            );
        }
        out
    }
}

impl FsInstance for TmpFs {
    fn root(&self) -> Arc<dyn DirOps> {
        self.inner.root()
    }

    fn name(&self) -> &str {
        "tmpfs"
    }

    fn show_options(&self) -> String {
        TmpFs::show_options(self)
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        self.inner.statfs()
    }

    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        self.inner
            .superblock
            .reconfigure_tmpfs(options, self.total_pages)
    }

    fn quota_on(&self, kind: QuotaKind) -> Result<(), FsError> {
        self.inner.superblock.quota_on(kind)
    }
    fn quota_off(&self, kind: QuotaKind) -> Result<(), FsError> {
        self.inner.superblock.quota_off(kind)
    }
    fn quota_get(&self, kind: QuotaKind, id: u32) -> Result<FsDqBlk, FsError> {
        self.inner.superblock.quota_get(kind, id)
    }
    fn quota_get_next(&self, kind: QuotaKind, id: u32) -> Result<(u32, FsDqBlk), FsError> {
        self.inner.superblock.quota_get_next(kind, id)
    }
    fn quota_set(&self, kind: QuotaKind, id: u32, blk: &FsDqBlk) -> Result<(), FsError> {
        self.inner.superblock.quota_set(kind, id, blk)
    }
    fn quota_get_info(&self, kind: QuotaKind) -> Result<FsDqInfo, FsError> {
        self.inner.superblock.quota_get_info(kind)
    }
    fn quota_set_info(&self, kind: QuotaKind, info: &FsDqInfo) -> Result<(), FsError> {
        self.inner.superblock.quota_set_info(kind, info)
    }
    fn quota_sync(&self) -> Result<(), FsError> {
        // RAM-backed: quotas are always in sync. Succeed on a tmpfs mount.
        Ok(())
    }
}

/// Linux ramfs: the same POSIX in-memory inode/data behavior as tmpfs but
/// deliberately unlimited, unswappable, and non-resizable.
pub struct RamFs {
    inner: MemFs,
}

impl fmt::Debug for RamFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamFs").field("inner", &self.inner).finish()
    }
}

impl RamFs {
    pub fn from_options(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        let parsed = RamFsOptions::parse(options, uid, gid)?;
        Ok(Self {
            inner: MemFs::configured(
                "ramfs",
                MemFsKind::Ramfs,
                None,
                None,
                parsed.root_mode,
                parsed.root_uid,
                parsed.root_gid,
            )?,
        })
    }
}

impl FsInstance for RamFs {
    fn root(&self) -> Arc<dyn DirOps> {
        self.inner.root()
    }

    fn name(&self) -> &str {
        "ramfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        self.inner.statfs()
    }
}

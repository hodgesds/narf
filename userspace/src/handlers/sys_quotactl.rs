#[allow(unused_imports)]
use super::*;

use narf_filesystem::{FsDqBlk, FsDqInfo, FsError, QuotaKind};

// ── Linux quotactl cmd encoding (`<linux/quota.h>`) ─────────────────
// cmd = (subcmd << SUBCMDSHIFT) | type
const SUBCMDSHIFT: u32 = 8;
const SUBCMDMASK: u32 = 0x00ff;
const Q_SYNC: u32 = 0x0080_0001;
const Q_QUOTAON: u32 = 0x0080_0002;
const Q_QUOTAOFF: u32 = 0x0080_0003;
const Q_GETFMT: u32 = 0x0080_0004;
const Q_GETINFO: u32 = 0x0080_0005;
const Q_SETINFO: u32 = 0x0080_0006;
const Q_GETQUOTA: u32 = 0x0080_0007;
const Q_SETQUOTA: u32 = 0x0080_0008;
const Q_GETNEXTQUOTA: u32 = 0x0080_0009;

const USRQUOTA: u32 = 0;
const GRPQUOTA: u32 = 1;

/// Linux counts quota block limits in 1024-byte units; NARF tmpfs blocks are
/// 4 KiB pages. Four quota blocks per fs block.
const QUOTA_BLOCKS_PER_FS_BLOCK: u64 = FS_BLOCK / QUOTA_BLOCK;
const QUOTA_BLOCK: u64 = 1024;
const FS_BLOCK: u64 = 4096;

/// `struct if_dqblk` / `struct if_dqinfo` are u64-aligned; both are ≤ 72 bytes.
const IF_DQBLK_LEN: usize = 72;
const IF_DQINFO_LEN: usize = 24;

/// The on-disk quota format id reported for `Q_GETFMT`. Linux's generic
/// "vfs v0" format; tmpfs has no on-disk file but must report *some* format so
/// `quotaon`/`repquota` proceed.
const QFMT_VFS_V0: u32 = 2;

// Negative errno returns, per `quotactl(2)`. Every error path in this handler
// uses one of these named constants so the SAME failure always reports the
// SAME errno — a mismatch here surfaces far from its cause and is miserable to
// debug.
const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EIO: i64 = -5;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EDQUOT: i64 = -122;

/// Map a filesystem error to the `quotactl(2)` errno. The quota fs methods only
/// ever produce the variants enumerated here; the catch-all is a defensive
/// `EIO` for a genuinely unexpected error (it must not silently alias a case
/// that has a specific Linux errno).
fn quota_errno(error: FsError) -> i64 {
    match error {
        // Quota of this type is not enabled, or the fs has no quota support at
        // all — Linux reports both as ESRCH.
        FsError::Unsupported => ESRCH,
        // Q_GETNEXTQUOTA ran off the end of the id space.
        FsError::NotFound => ENOENT,
        FsError::QuotaExceeded => EDQUOT,
        FsError::NoSpace => ENOSPC,
        FsError::InvalidData | FsError::InvalidPath => EINVAL,
        FsError::PermissionDenied => EPERM,
        _ => EIO,
    }
}

/// Convert an internal [`FsDqBlk`] (fs blocks / absolute inodes) into a
/// Linux `struct if_dqblk` byte image (1 KiB blocks / bytes).
fn encode_dqblk(dq: &FsDqBlk, id: Option<u32>) -> [u8; IF_DQBLK_LEN] {
    let mut b = [0u8; IF_DQBLK_LEN];
    b[0..8].copy_from_slice(&(dq.blocks_hard * QUOTA_BLOCKS_PER_FS_BLOCK).to_le_bytes());
    b[8..16].copy_from_slice(&(dq.blocks_soft * QUOTA_BLOCKS_PER_FS_BLOCK).to_le_bytes());
    b[16..24].copy_from_slice(&(dq.blocks_used * FS_BLOCK).to_le_bytes()); // curspace in bytes
    b[24..32].copy_from_slice(&dq.inodes_hard.to_le_bytes());
    b[32..40].copy_from_slice(&dq.inodes_soft.to_le_bytes());
    b[40..48].copy_from_slice(&dq.inodes_used.to_le_bytes());
    b[48..56].copy_from_slice(&dq.btime.to_le_bytes());
    b[56..64].copy_from_slice(&dq.itime.to_le_bytes());
    b[64..68].copy_from_slice(&dq.valid.to_le_bytes());
    // `struct if_nextdqblk` appends dqb_id where if_dqblk has its trailing pad.
    if let Some(id) = id {
        b[68..72].copy_from_slice(&id.to_le_bytes());
    }
    b
}

/// Parse a Linux `struct if_dqblk` byte image into an internal [`FsDqBlk`].
fn decode_dqblk(b: &[u8; IF_DQBLK_LEN]) -> FsDqBlk {
    let rd = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    FsDqBlk {
        blocks_hard: rd(0) / QUOTA_BLOCKS_PER_FS_BLOCK,
        blocks_soft: rd(8) / QUOTA_BLOCKS_PER_FS_BLOCK,
        blocks_used: rd(16) / FS_BLOCK, // curspace bytes → fs blocks
        inodes_hard: rd(24),
        inodes_soft: rd(32),
        inodes_used: rd(40),
        btime: rd(48),
        itime: rd(56),
        valid: u32::from_le_bytes(b[64..68].try_into().unwrap()),
    }
}

fn quota_kind(type_: u32) -> Option<QuotaKind> {
    match type_ {
        USRQUOTA => Some(QuotaKind::User),
        GRPQUOTA => Some(QuotaKind::Group),
        _ => None,
    }
}

/// Resolve the `special` argument (a path on / device of the target mount) to
/// its filesystem instance, re-rooting through the caller's namespace.
fn fs_for_special(
    special_ptr: u64,
) -> Result<alloc::sync::Arc<dyn narf_filesystem::FsInstance>, i64> {
    let raw = copy_user_cstr_checked(special_ptr, 4096)?;
    let path = resolve_cwd_path(current_task_id(), &raw);
    current_fs_arc_at(&path).ok_or(ENOENT)
}

pub(crate) fn sys_quotactl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cmd = args.arg0 as u32;
    let special = args.arg1;
    let id = args.arg2 as u32;
    let addr = args.arg3;

    let subcmd = cmd >> SUBCMDSHIFT;
    let type_ = cmd & SUBCMDMASK;

    let ret: i64 = quotactl_dispatch(subcmd, type_, special, id, addr);
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

fn quotactl_dispatch(subcmd: u32, type_: u32, special: u64, id: u32, addr: u64) -> i64 {
    // Q_SYNC with a NULL special syncs every mount; for RAM-backed tmpfs that
    // is a no-op that always succeeds.
    if subcmd == Q_SYNC && special == 0 {
        return 0;
    }
    let Some(kind) = quota_kind(type_) else {
        return EINVAL; // unknown/unsupported quota type
    };
    let fs = match fs_for_special(special) {
        Ok(fs) => fs,
        Err(e) => return e,
    };

    match subcmd {
        Q_QUOTAON => fs.quota_on(kind).map_or_else(quota_errno, |()| 0),
        Q_QUOTAOFF => fs.quota_off(kind).map_or_else(quota_errno, |()| 0),
        Q_SYNC => fs.quota_sync().map_or_else(quota_errno, |()| 0),
        Q_GETFMT => {
            // Report the generic format id so quota tools proceed.
            match fs.quota_get_info(kind) {
                Ok(_) => write_user_u32(addr, QFMT_VFS_V0),
                Err(e) => quota_errno(e),
            }
        }
        Q_GETQUOTA => match fs.quota_get(kind, id) {
            Ok(dq) => write_user_bytes(addr, &encode_dqblk(&dq, None)),
            Err(e) => quota_errno(e),
        },
        Q_GETNEXTQUOTA => match fs.quota_get_next(kind, id) {
            Ok((nid, dq)) => write_user_bytes(addr, &encode_dqblk(&dq, Some(nid))),
            Err(e) => quota_errno(e),
        },
        Q_SETQUOTA => {
            let mut buf = [0u8; IF_DQBLK_LEN];
            // SAFETY: `addr` is the user if_dqblk pointer; copy_from_user checks it.
            if unsafe { copy_from_user(&mut buf, addr) }.is_err() {
                return EFAULT;
            }
            let blk = decode_dqblk(&buf);
            fs.quota_set(kind, id, &blk)
                .map_or_else(quota_errno, |()| 0)
        }
        Q_GETINFO => match fs.quota_get_info(kind) {
            Ok(info) => write_user_bytes(addr, &encode_dqinfo(&info)),
            Err(e) => quota_errno(e),
        },
        Q_SETINFO => {
            let mut buf = [0u8; IF_DQINFO_LEN];
            // SAFETY: `addr` is the user if_dqinfo pointer; copy_from_user checks it.
            if unsafe { copy_from_user(&mut buf, addr) }.is_err() {
                return EFAULT;
            }
            let info = decode_dqinfo(&buf);
            fs.quota_set_info(kind, &info)
                .map_or_else(quota_errno, |()| 0)
        }
        _ => EINVAL, // unknown subcommand
    }
}

fn encode_dqinfo(info: &FsDqInfo) -> [u8; IF_DQINFO_LEN] {
    let mut b = [0u8; IF_DQINFO_LEN];
    b[0..8].copy_from_slice(&info.bgrace.to_le_bytes());
    b[8..16].copy_from_slice(&info.igrace.to_le_bytes());
    b[16..20].copy_from_slice(&info.flags.to_le_bytes());
    b[20..24].copy_from_slice(&info.valid.to_le_bytes());
    b
}

fn decode_dqinfo(b: &[u8; IF_DQINFO_LEN]) -> FsDqInfo {
    FsDqInfo {
        bgrace: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        igrace: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        flags: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        valid: u32::from_le_bytes(b[20..24].try_into().unwrap()),
    }
}

fn write_user_bytes(addr: u64, bytes: &[u8]) -> i64 {
    if addr == 0 {
        return EFAULT;
    }
    // SAFETY: `addr` is the user destination; copy_to_user checks the range.
    match unsafe { copy_to_user(addr, bytes) } {
        Ok(()) => 0,
        Err(_) => EFAULT,
    }
}

fn write_user_u32(addr: u64, value: u32) -> i64 {
    write_user_bytes(addr, &value.to_le_bytes())
}

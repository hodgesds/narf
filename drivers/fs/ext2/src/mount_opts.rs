//! ext4 mount-parameter validation for a remount.
//!
//! `mount -o remount` / `fsconfig(FSCONFIG_CMD_RECONFIGURE)` hands the
//! filesystem the options the generic layer did not consume (`ro`, `rw`,
//! `sync`, ... are superblock flags and never reach here). Linux parses each
//! against `ext4_param_specs` (`fs/ext4/super.c`) and refuses anything else
//! with `"ext4: Unknown parameter '%s'"` — -EINVAL — and a known key given
//! the wrong kind of value with the same errno.
//!
//! Every CachyOS/Arch fstab line for an ext4 root carries some of these
//! (`noatime` is a VFS flag, but `commit=60`, `errors=remount-ro`,
//! `discard`, `barrier=1` are ext4's), and `systemd-remount-fs` remounts `/`
//! with them on every boot.
//!
//! LINUX-GAP: the tuning parameters are accepted and not modelled — NARF's
//! ext driver has no commit timer, discard, delalloc or quota to adjust.
//! The ones Linux refuses on a remount (`ext4_parse_param` /
//! `ext4_check_opt_consistency`: "Cannot specify journal on remount",
//! "Cannot change data mode on remount", "can't change dax mount option
//! while remounting") are refused here too, against the state NARF always
//! mounts with (internal journal, `data=ordered`, no DAX policy).

use narf_filesystem::FsError;

/// How a parameter takes its value (`include/linux/fs_parser.h`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `fsparam_flag` — no value.
    Flag,
    /// `fsparam_u32` — a decimal unsigned value.
    U32,
    /// `fsparam_s32`.
    S32,
    /// `fsparam_uid` / `fsparam_gid` — a decimal id.
    Id,
    /// `fsparam_string` / `fsparam_string_empty` / `fsparam_bdev`.
    Str,
    /// `fsparam_enum` over the given names.
    Enum(&'static [&'static str]),
}

const ERRORS: &[&str] = &["continue", "panic", "remount-ro"];
const DATA: &[&str] = &["journal", "ordered", "writeback"];
const DATA_ERR: &[&str] = &["abort", "ignore"];
const JQFMT: &[&str] = &["vfsold", "vfsv0", "vfsv1"];
const DAX: &[&str] = &["always", "inode", "never"];

/// `ext4_param_specs`, in its order. A name listed twice accepts either
/// shape (`barrier` and `barrier=1`, `dax` and `dax=never`, ...).
const SPECS: &[(&str, Kind)] = &[
    ("bsddf", Kind::Flag),
    ("minixdf", Kind::Flag),
    ("grpid", Kind::Flag),
    ("bsdgroups", Kind::Flag),
    ("nogrpid", Kind::Flag),
    ("sysvgroups", Kind::Flag),
    ("resgid", Kind::Id),
    ("resuid", Kind::Id),
    ("sb", Kind::U32),
    ("errors", Kind::Enum(ERRORS)),
    ("nouid32", Kind::Flag),
    ("debug", Kind::Flag),
    ("oldalloc", Kind::Flag),
    ("orlov", Kind::Flag),
    ("user_xattr", Kind::Flag),
    ("acl", Kind::Flag),
    ("norecovery", Kind::Flag),
    ("noload", Kind::Flag),
    ("bh", Kind::Flag),
    ("nobh", Kind::Flag),
    ("commit", Kind::U32),
    ("min_batch_time", Kind::U32),
    ("max_batch_time", Kind::U32),
    ("journal_dev", Kind::U32),
    ("journal_path", Kind::Str),
    ("journal_checksum", Kind::Flag),
    ("nojournal_checksum", Kind::Flag),
    ("journal_async_commit", Kind::Flag),
    ("abort", Kind::Flag),
    ("data", Kind::Enum(DATA)),
    ("data_err", Kind::Enum(DATA_ERR)),
    ("usrjquota", Kind::Str),
    ("grpjquota", Kind::Str),
    ("jqfmt", Kind::Enum(JQFMT)),
    ("grpquota", Kind::Flag),
    ("quota", Kind::Flag),
    ("noquota", Kind::Flag),
    ("usrquota", Kind::Flag),
    ("prjquota", Kind::Flag),
    ("barrier", Kind::Flag),
    ("barrier", Kind::U32),
    ("nobarrier", Kind::Flag),
    ("i_version", Kind::Flag),
    ("dax", Kind::Flag),
    ("dax", Kind::Enum(DAX)),
    ("stripe", Kind::U32),
    ("delalloc", Kind::Flag),
    ("nodelalloc", Kind::Flag),
    ("warn_on_error", Kind::Flag),
    ("nowarn_on_error", Kind::Flag),
    ("debug_want_extra_isize", Kind::U32),
    ("mblk_io_submit", Kind::Flag),
    ("nomblk_io_submit", Kind::Flag),
    ("block_validity", Kind::Flag),
    ("noblock_validity", Kind::Flag),
    ("inode_readahead_blks", Kind::U32),
    ("journal_ioprio", Kind::U32),
    ("auto_da_alloc", Kind::U32),
    ("auto_da_alloc", Kind::Flag),
    ("noauto_da_alloc", Kind::Flag),
    ("dioread_nolock", Kind::Flag),
    ("nodioread_nolock", Kind::Flag),
    ("dioread_lock", Kind::Flag),
    ("discard", Kind::Flag),
    ("nodiscard", Kind::Flag),
    ("init_itable", Kind::U32),
    ("init_itable", Kind::Flag),
    ("noinit_itable", Kind::Flag),
    ("max_dir_size_kb", Kind::U32),
    ("test_dummy_encryption", Kind::Flag),
    ("test_dummy_encryption", Kind::Str),
    ("inlinecrypt", Kind::Flag),
    ("nombcache", Kind::Flag),
    ("no_mbcache", Kind::Flag),
    ("prefetch_block_bitmaps", Kind::Flag),
    ("no_prefetch_block_bitmaps", Kind::Flag),
    ("mb_optimize_scan", Kind::S32),
    ("check", Kind::Str),
    ("nocheck", Kind::Flag),
    ("reservation", Kind::Flag),
    ("noreservation", Kind::Flag),
    ("journal", Kind::U32),
];

/// `fs_parse` for one `key[=value]`: does some spec of this name accept
/// this shape of value?
fn kind_accepts(kind: Kind, value: Option<&str>) -> bool {
    match (kind, value) {
        (Kind::Flag, None) => true,
        (Kind::Flag, Some(_)) => false,
        (_, None) => false,
        (Kind::U32 | Kind::Id, Some(v)) => !v.is_empty() && v.parse::<u32>().is_ok(),
        (Kind::S32, Some(v)) => v.parse::<i32>().is_ok(),
        (Kind::Str, Some(_)) => true,
        (Kind::Enum(names), Some(v)) => names.contains(&v),
    }
}

/// Validate a remount's ext4 parameter string. `Unsupported` is the
/// "Unknown parameter" answer (the syscall layer reports it as -EINVAL, as
/// `vfs_parse_fs_param` does); `InvalidData` a known key with a bad value
/// or a change `__ext4_remount` refuses.
pub fn validate_remount(options: &str) -> Result<(), FsError> {
    for item in options.split(',').filter(|s| !s.is_empty()) {
        let (key, value) = match item.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (item, None),
        };
        let mut known = false;
        let mut accepted = false;
        for (name, kind) in SPECS {
            if *name == key {
                known = true;
                accepted |= kind_accepts(*kind, value);
            }
        }
        if !known {
            return Err(FsError::Unsupported);
        }
        if !accepted {
            return Err(FsError::InvalidData);
        }
        // `__ext4_remount`'s refusals, against NARF's fixed mount state
        // (data=ordered, internal journal, no DAX).
        let refused = match (key, value) {
            // "Cannot change data mode on remount".
            ("data", Some(mode)) => mode != "ordered",
            // "Cannot specify journal on remount".
            ("journal_dev" | "journal_path", _) => true,
            // "can't change dax mount option while remounting": the mount
            // is neither DAX_ALWAYS nor DAX_NEVER, so only `dax=inode` is
            // not a change.
            ("dax", Some(mode)) => mode != "inode",
            ("dax", None) => true,
            _ => false,
        };
        if refused {
            return Err(FsError::InvalidData);
        }
    }
    Ok(())
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The parameters a stock ext4 fstab line carries all pass, in every
/// shape `ext4_param_specs` gives them (`barrier` bare and `barrier=1`).
fn smoke_ext4_remount_accepts_fstab_options() -> TestResult {
    let lines = [
        "",
        "commit=60",
        "errors=remount-ro",
        "barrier,barrier=1,nobarrier",
        "discard,nodelalloc,data=ordered,data_err=abort",
        "user_xattr,acl,resuid=0,resgid=0,dax=inode",
        "init_itable,init_itable=10,auto_da_alloc=1,mb_optimize_scan=-1",
    ];
    for line in lines {
        if validate_remount(line).is_err() {
            return TestResult::Fail("a Linux-accepted ext4 remount parameter was refused");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_remount_accepts_fstab_options);

/// Linux's refusals: an unknown key ("Unknown parameter", reported as
/// `Unsupported` -> -EINVAL), a flag given a value, a number that is not
/// one, an enum value outside its table, and the changes ext4 refuses on
/// a remount (data mode, journal device, DAX policy).
fn smoke_ext4_remount_refuses_like_linux() -> TestResult {
    let cases: [(&str, bool); 9] = [
        ("bogus", true),
        ("noacl", true),
        ("acl=1", false),
        ("commit=abc", false),
        ("commit", false),
        ("errors=explode", false),
        ("data=journal", false),
        ("journal_dev=5", false),
        ("dax=always", false),
    ];
    for (line, unknown) in cases {
        match validate_remount(line) {
            Err(FsError::Unsupported) if unknown => {}
            Err(FsError::InvalidData) if !unknown => {}
            _ => return TestResult::Fail("an ext4 remount parameter Linux refuses was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_remount_refuses_like_linux);

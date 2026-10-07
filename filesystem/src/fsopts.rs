//! Mount-option parsing shared by the block filesystem drivers.
//!
//! Linux parses a mount's data string one parameter at a time
//! (`vfs_parse_fs_param`): the superblock flag names are consumed by the VFS
//! first, then the filesystem's own `fs_parameter_spec` table, and anything
//! left over is `"%s: Unknown parameter '%s'"` — **-EINVAL**, not
//! -EOPNOTSUPP. A parameter's value is parsed in the base its spec declares:
//! `fsparam_u32oct` is base 8 (`umask=022` is octal), `fsparam_u32` is base 0
//! (`mode=0444` octal by its leading zero, `mode=444` decimal), and
//! `fsparam_uid` / `fsparam_gid` are base 0 too.
//!
//! The drivers that need this are the ones whose on-disk format carries no
//! POSIX ownership — FAT, exFAT, ISO 9660, UDF — because for them the mount
//! options ARE the ownership and permission model: `fat_fill_super` starts
//! every inode from the mounting task's uid/gid and umask. Each driver keeps
//! its own spec table (they differ, and the differences are ABI); what lives
//! here is the lexing, the integer bases, and the ownership defaults they
//! share.

use crate::FsError;

/// One `key` or `key=value` of a mount data string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opt<'a> {
    pub key: &'a str,
    pub value: Option<&'a str>,
}

/// Split a mount data string the way `vfs_parse_monolithic_sep` does: on
/// commas, skipping empty entries, with the first `=` separating key from
/// value (a value may itself contain `=`).
pub fn iter(data: &str) -> impl Iterator<Item = Opt<'_>> {
    data.split(',')
        .filter(|part| !part.is_empty())
        .map(|raw| match raw.split_once('=') {
            Some((key, value)) => Opt {
                key,
                value: Some(value),
            },
            None => Opt {
                key: raw,
                value: None,
            },
        })
}

/// `vfs_parse_sb_flag`: the option names the VFS consumes before the
/// filesystem's table is consulted, plus the `source` every type accepts
/// (`vfs_parse_fs_param_source`). A driver must tolerate these in its data
/// string — `fsconfig(2)` callers set them as parameters rather than flags,
/// and NARF's `fsconfig` path renders them back into this string.
pub fn is_vfs_param(key: &str) -> bool {
    matches!(
        key,
        "ro" | "rw"
            | "sync"
            | "async"
            | "dirsync"
            | "nodirsync"
            | "lazytime"
            | "nolazytime"
            | "mand"
            | "nomand"
            | "silent"
            | "loud"
            | "source"
    )
}

/// `kstrtoull(s, base, ...)`: an optional leading `+`, base-0 prefix handling
/// (`0x` hex, leading `0` octal), digits only, and one optional trailing
/// newline. No leading/trailing space, no `0o`, no internal separators —
/// which is why `umask= 022` and `uid=1_000` are EINVAL on Linux.
pub fn kstrtou64(s: &str, base: u32) -> Option<u64> {
    let s = s.strip_suffix('\n').unwrap_or(s);
    let s = s.strip_prefix('+').unwrap_or(s);
    let (digits, radix) = match base {
        0 => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                (hex, 16)
            } else if s.len() > 1 && s.starts_with('0') {
                (&s[1..], 8)
            } else {
                (s, 10)
            }
        }
        b => (s, b),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// `kstrtouint(s, base, ...)`.
pub fn kstrtouint(s: &str, base: u32) -> Option<u32> {
    kstrtou64(s, base).and_then(|v| u32::try_from(v).ok())
}

/// `kstrtoint(s, base, ...)` — `kstrtoll` accepts one leading `-`.
pub fn kstrtoint(s: &str, base: u32) -> Option<i32> {
    match s.strip_prefix('-') {
        Some(rest) => kstrtou64(rest, base)
            .and_then(|v| i64::try_from(v).ok())
            .and_then(|v| i32::try_from(-v).ok()),
        None => kstrtou64(s, base).and_then(|v| i32::try_from(v).ok()),
    }
}

/// A required value in `base`, or the EINVAL a missing/malformed one gets.
pub fn uint_value(value: Option<&str>, base: u32) -> Result<u32, FsError> {
    value
        .and_then(|v| kstrtouint(v, base))
        .ok_or(FsError::InvalidData)
}

/// A required signed value in `base` (`fsparam_s32`).
pub fn int_value(value: Option<&str>, base: u32) -> Result<i32, FsError> {
    value
        .and_then(|v| kstrtoint(v, base))
        .ok_or(FsError::InvalidData)
}

/// A flag parameter: a value makes it EINVAL
/// (`fs_parse`: "Unexpected value for '%s'").
pub fn flag_only(value: Option<&str>) -> Result<(), FsError> {
    if value.is_some() {
        return Err(FsError::InvalidData);
    }
    Ok(())
}

/// An enum parameter: the value must be one of `names`.
pub fn enum_value(value: Option<&str>, names: &[&str]) -> Result<(), FsError> {
    match value {
        Some(v) if names.contains(&v) => Ok(()),
        _ => Err(FsError::InvalidData),
    }
}

/// A string parameter: any non-empty value (`fs_param_is_string`).
pub fn string_value(value: Option<&str>) -> Result<(), FsError> {
    match value {
        Some(v) if !v.is_empty() => Ok(()),
        _ => Err(FsError::InvalidData),
    }
}

/// The ownership and permission model of a filesystem whose on-disk format
/// has none: `uid=` / `gid=` and the `umask=` / `dmask=` / `fmask=` masks,
/// with Linux's defaults.
///
/// `fat_fill_super` / `exfat_fill_super` / `isofs_fill_super` all start here:
///
/// ```text
/// opts->fs_uid = current_uid();
/// opts->fs_gid = current_gid();
/// opts->fs_fmask = opts->fs_dmask = current_umask();
/// ```
///
/// so an unprivileged `mount` of a FAT stick owns its files, and the kernel's
/// own mounts land on `init_fs.umask` (0022).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerOpts {
    pub uid: u32,
    pub gid: u32,
    /// Cleared from a regular file's mode.
    pub fmask: u16,
    /// Cleared from a directory's mode.
    pub dmask: u16,
    /// Whether `uid=` / `gid=` were given, for `show_options`.
    pub set_uid: bool,
    pub set_gid: bool,
}

impl OwnerOpts {
    /// The mounting task's credentials and umask, before any option.
    pub fn from_mount(uid: u32, gid: u32, umask: u16) -> Self {
        Self {
            uid,
            gid,
            fmask: umask & 0o777,
            dmask: umask & 0o777,
            set_uid: false,
            set_gid: false,
        }
    }

    /// `uid=`/`gid=` (base 0) and `umask=`/`dmask=`/`fmask=` (base 8).
    /// Returns `false` for a key it does not own, so a driver's table keeps
    /// control of what it accepts.
    pub fn take(&mut self, opt: Opt<'_>) -> Result<bool, FsError> {
        match opt.key {
            "uid" => {
                self.uid = uint_value(opt.value, 0)?;
                self.set_uid = true;
            }
            "gid" => {
                self.gid = uint_value(opt.value, 0)?;
                self.set_gid = true;
            }
            "umask" => {
                let m = (uint_value(opt.value, 8)? & 0o777) as u16;
                self.fmask = m;
                self.dmask = m;
            }
            "dmask" => self.dmask = (uint_value(opt.value, 8)? & 0o777) as u16,
            "fmask" => self.fmask = (uint_value(opt.value, 8)? & 0o777) as u16,
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// `fat_make_mode`'s masking half: the permission bits a mode keeps.
pub fn masked(base: u16, mask: u16) -> u16 {
    base & !mask & 0o777
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The integer bases are per-parameter ABI: `umask=022` is 18 decimal (octal
/// 022) because `fsparam_u32oct` parses base 8, while `mode=0444` is octal
/// and `mode=444` decimal because `fsparam_u32` parses base 0.
fn smoke_fsopts_integer_bases_match_fs_parser() -> TestResult {
    if kstrtouint("022", 8) != Some(0o22) {
        return TestResult::Fail("base 8: 022 should be octal 022");
    }
    if kstrtouint("0444", 0) != Some(0o444) {
        return TestResult::Fail("base 0: a leading zero means octal");
    }
    if kstrtouint("444", 0) != Some(444) {
        return TestResult::Fail("base 0: no prefix means decimal");
    }
    if kstrtouint("0x1ff", 0) != Some(0x1ff) {
        return TestResult::Fail("base 0: 0x means hex");
    }
    if kstrtoint("-30", 0) != Some(-30) {
        return TestResult::Fail("kstrtoint should accept one leading minus");
    }
    // Rejections `kstrtouint` makes that `from_str_radix` alone would not.
    for bad in [" 22", "22 ", "0o22", "2_2", "", "+", "8", "09"] {
        if kstrtouint(bad, 8).is_some() {
            return TestResult::Fail("kstrtouint accepted a value Linux rejects");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/fsopts",
    smoke_fsopts_integer_bases_match_fs_parser
);

/// Ownership defaults come from the mounting task, and the masks subtract
/// from the base mode the way `fat_make_mode` applies them.
fn smoke_fsopts_owner_defaults_and_masks() -> TestResult {
    let mut o = OwnerOpts::from_mount(1000, 100, 0o022);
    if o.uid != 1000 || o.gid != 100 || o.fmask != 0o022 || o.dmask != 0o022 {
        return TestResult::Fail("defaults are not the mounting task's uid/gid/umask");
    }
    if masked(0o777, o.dmask) != 0o755 || masked(0o777, o.fmask) != 0o755 {
        return TestResult::Fail("0777 under umask 022 should be 0755");
    }
    for (key, value) in [
        ("uid", "0"),
        ("gid", "0"),
        ("umask", "077"),
        ("dmask", "027"),
    ] {
        match o.take(Opt {
            key,
            value: Some(value),
        }) {
            Ok(true) => {}
            _ => return TestResult::Fail("an ownership option was not taken"),
        }
    }
    if o.uid != 0 || o.gid != 0 || o.fmask != 0o077 || o.dmask != 0o027 {
        return TestResult::Fail("ownership options did not apply in order");
    }
    if !o.set_uid || !o.set_gid {
        return TestResult::Fail("uid=/gid= should record that they were set");
    }
    // umask= sets both masks; a later dmask= overrides only its own.
    if masked(0o777, o.fmask) != 0o700 || masked(0o777, o.dmask) != 0o750 {
        return TestResult::Fail("the mask pair did not apply independently");
    }
    match o.take(Opt {
        key: "umask",
        value: None,
    }) {
        Err(FsError::InvalidData) => {}
        _ => return TestResult::Fail("umask without a value should be EINVAL"),
    }
    match o.take(Opt {
        key: "flush",
        value: None,
    }) {
        Ok(false) => TestResult::Pass,
        _ => TestResult::Fail("a key OwnerOpts does not own should be left to the driver"),
    }
}
kernel_test_in!("filesystem/fsopts", smoke_fsopts_owner_defaults_and_masks);

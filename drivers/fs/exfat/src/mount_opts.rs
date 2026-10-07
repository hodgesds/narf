//! `exfat_parse_param` (`fs/exfat/super.c`).
//!
//! Like FAT, exFAT stores no POSIX metadata, so the mount options are the
//! ownership and permission model: `exfat_fill_super` starts from the
//! mounting task's uid, gid and umask, and `exfat_make_mode` derives each
//! inode's mode. NARF refused any non-empty data string with
//! `Unsupported` (EOPNOTSUPP), so the `mount -t exfat -o uid=1000,gid=1000`
//! form every removable-media mounter uses failed, and the mounts that
//! worked reported root-owned 0666/0444 for the whole volume.
//!
//! Unknown parameters are EINVAL, as `vfs_parse_fs_param` reports them.
//!
//! LINUX-GAP: `iocharset=` (NARF decodes exFAT's UTF-16 names to UTF-8 with
//! no NLS table), `errors=`, `discard`/`nodiscard`, `keep_last_dots`,
//! `zero_size_dir`, `allow_utime=`, and the deprecated `utf8`/`debug`/
//! `namecase=`/`codepage=` are accepted and not acted on — Linux accepts
//! each, so refusing them would break a legitimate mount line, and the
//! machinery they steer (NLS tables, discard, the dot-stripping name rules)
//! does not exist here.

use narf_filesystem::fsopts::{self, Opt, OwnerOpts};
use narf_filesystem::FsError;

/// The parsed mount state a volume keeps (`exfat_sb_info::options`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExfatOpts {
    pub owners: OwnerOpts,
    /// `sys_tz` / `time_offset=`: minutes to ADD to an on-disk timestamp
    /// that carries no UTC offset of its own.
    pub tz_offset_min: i16,
}

impl ExfatOpts {
    /// Linux's pre-option state.
    pub fn defaults(uid: u32, gid: u32, umask: u16) -> Self {
        Self {
            owners: OwnerOpts::from_mount(uid, gid, umask),
            tz_offset_min: 0,
        }
    }

    /// `exfat_make_mode(sbi, attr, 0777)`:
    ///
    /// ```text
    /// if ((attr & EXFAT_ATTR_READONLY) && !(attr & EXFAT_ATTR_SUBDIR))
    ///         mode &= ~0222;
    /// if (attr & EXFAT_ATTR_SUBDIR)
    ///         return (mode & ~sbi->options.fs_dmask) | S_IFDIR;
    /// return (mode & ~sbi->options.fs_fmask) | S_IFREG;
    /// ```
    ///
    /// Note the asymmetry with FAT: exFAT has no `rodir`, so READONLY never
    /// applies to a directory.
    pub fn make_mode(&self, read_only: bool, is_dir: bool) -> u16 {
        let base: u16 = if read_only && !is_dir {
            0o777 & !0o222
        } else {
            0o777
        };
        fsopts::masked(
            base,
            if is_dir {
                self.owners.dmask
            } else {
                self.owners.fmask
            },
        )
    }
}

const ERRORS: &[&str] = &["continue", "panic", "remount-ro"];

/// `exfat_parse_param` over the parameters the generic layer did not consume.
pub fn parse(options: &str, uid: u32, gid: u32, umask: u16) -> Result<ExfatOpts, FsError> {
    let mut opts = ExfatOpts::defaults(uid, gid, umask);
    for opt in fsopts::iter(options) {
        if fsopts::is_vfs_param(opt.key) {
            continue;
        }
        if opts.owners.take(opt)? {
            continue;
        }
        apply(&mut opts, opt)?;
    }
    Ok(opts)
}

fn apply(opts: &mut ExfatOpts, opt: Opt<'_>) -> Result<(), FsError> {
    match opt.key {
        // Acted on: the timestamps exFAT stores without a UTC offset.
        "time_offset" => {
            let minutes = fsopts::int_value(opt.value, 0)?;
            // `exfat_parse_param`: "Valid range: [-23:59, +23:59]".
            if !(-23 * 60 - 59..=23 * 60 + 59).contains(&minutes) {
                return Err(FsError::InvalidData);
            }
            opts.tz_offset_min = minutes as i16;
        }
        "sys_tz" => fsopts::flag_only(opt.value)?,
        // Accepted, not modelled — see the module LINUX-GAP.
        "allow_utime" => {
            let _ = fsopts::uint_value(opt.value, 8)?;
        }
        "iocharset" => fsopts::string_value(opt.value)?,
        "errors" => fsopts::enum_value(opt.value, ERRORS)?,
        "discard" | "nodiscard" | "keep_last_dots" | "zero_size_dir" | "nozero_size_dir"
        | "utf8" | "debug" => fsopts::flag_only(opt.value)?,
        "namecase" | "codepage" => {
            let _ = fsopts::uint_value(opt.value, 0)?;
        }
        _ => return Err(FsError::InvalidData),
    }
    Ok(())
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The mount lines exFAT media arrive with parse, the ownership options
/// reach the mode, and `exfat_make_mode`'s directory asymmetry holds.
fn smoke_exfat_opts_match_linux() -> TestResult {
    for line in [
        "",
        "uid=1000,gid=1000,umask=022",
        "rw,uid=1000,gid=1000,fmask=0133,dmask=0022,iocharset=utf8",
        "errors=remount-ro,discard,keep_last_dots,time_offset=-480",
        "sys_tz,allow_utime=0020",
    ] {
        if parse(line, 0, 0, 0o022).is_err() {
            return TestResult::Fail("a mount line Linux accepts was refused");
        }
    }
    let opts = match parse("uid=1000,gid=100,fmask=0133,dmask=0022", 0, 0, 0) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("the ownership options did not parse"),
    };
    if opts.owners.uid != 1000 || opts.owners.gid != 100 {
        return TestResult::Fail("uid=/gid= did not reach the ownership state");
    }
    if opts.make_mode(false, false) != 0o644 || opts.make_mode(false, true) != 0o755 {
        return TestResult::Fail("fmask/dmask did not reach the mode");
    }
    if opts.make_mode(true, false) != 0o444 {
        return TestResult::Fail("READONLY should clear a file's write bits");
    }
    if opts.make_mode(true, true) != 0o755 {
        return TestResult::Fail("exFAT has no rodir: READONLY must not touch a directory");
    }
    for line in [
        "bogus",
        "uid=x",
        "umask",
        "umask=778",
        "discard=1",
        "errors=explode",
        "time_offset=1440",
        "iocharset",
    ] {
        match parse(line, 0, 0, 0o022) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("an exFAT parameter Linux refuses was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_opts_match_linux);

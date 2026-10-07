//! `fat_parse_param` / `vfat_parse_param` (`fs/fat/inode.c`,
//! `fs/fat/namei_vfat.c`).
//!
//! FAT has no POSIX metadata on disk, so these options ARE its ownership and
//! permission model: `fat_fill_super` starts from the mounting task's uid,
//! gid and umask, and `fat_fill_inode` derives every mode from
//! `fat_make_mode`. A driver that refuses the options cannot report Linux's
//! modes at all — which is what NARF did: any non-empty data string was
//! `Unsupported` (EOPNOTSUPP), so `mount -t vfat -o uid=1000,gid=1000,
//! umask=022 /dev/sdb1 /mnt` — the form udisks, udev rules and every
//! removable-media fstab line use — failed outright, and the mounts that did
//! succeed reported one hardcoded owner and mode for the whole volume.
//!
//! Unknown parameters are EINVAL (`vfs_parse_fs_param`'s
//! `"%s: Unknown parameter '%s'"`), not EOPNOTSUPP, and so is a known one
//! given a value of the wrong shape.
//!
//! LINUX-GAP: the options NARF stores and does not act on, because the
//! machinery behind them does not exist here — `codepage=`/`iocharset=`/
//! `utf8`/`uni_xlate` (NARF decodes long names as UTF-16 → UTF-8
//! unconditionally and has no NLS table set), `shortname=` (the 8.3 name is
//! only ever a lookup fallback, never what readdir reports),
//! `flush`/`discard`/`usefree`/`nfs=`/`dos1xfloppy`/`quiet`/`debug`/
//! `errors=`, `check=`, `allow_utime=` (NARF's `utime` path does not consult
//! it) and `sys_immutable`. Linux accepts each of them, so refusing them
//! would break a legitimate mount line; applying them needs subsystems NARF
//! does not have. `nocase` and `dots`/`nodots`/`dotsOK` belong to the msdos
//! dialect and are accepted for the same reason.

use narf_filesystem::fsopts::{self, Opt, OwnerOpts};
use narf_filesystem::FsError;

/// The parsed mount state a volume keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatOpts {
    pub owners: OwnerOpts,
    /// `showexec`: a file whose 8.3 extension is not EXE/COM/BAT loses its
    /// execute bits (`fat_fill_inode`'s `S_IRUGO|S_IWUGO` base).
    pub showexec: bool,
    /// `rodir`: honour ATTR_RO on DIRECTORIES too. Without it a read-only
    /// directory is still writable, because the attribute means "no new
    /// files" on Windows and that is not what POSIX write permission says.
    pub rodir: bool,
    /// `tz=UTC` / `time_offset=`: seconds to ADD to an on-disk local time to
    /// get UTC (`fat_tz_offset`, negated minutes).
    pub tz_offset_secs: i64,
}

impl FatOpts {
    /// Linux's pre-option state: the mounting task's credentials and umask.
    pub fn defaults(uid: u32, gid: u32, umask: u16) -> Self {
        Self {
            owners: OwnerOpts::from_mount(uid, gid, umask),
            showexec: false,
            rodir: false,
            tz_offset_secs: 0,
        }
    }

    /// `fat_make_mode(sbi, attrs, base)`:
    ///
    /// ```text
    /// if (attrs & ATTR_RO && !((attrs & ATTR_DIR) && !sbi->options.rodir))
    ///         mode &= ~S_IWUGO;
    /// if (attrs & ATTR_DIR)
    ///         return (mode & ~sbi->options.fs_dmask) | S_IFDIR;
    /// else
    ///         return (mode & ~sbi->options.fs_fmask) | S_IFREG;
    /// ```
    ///
    /// The base is `S_IRWXUGO` (0777) for a directory and for a file, except
    /// under `showexec`, where a non-executable extension starts at 0666.
    /// NARF reported 0666 (or 0444 for ATTR_RO) for files and left
    /// directories on the VFS default 0755 — so neither the mask options nor
    /// the umask of the mounting task reached a single mode bit.
    pub fn make_mode(&self, attr_ro: bool, is_dir: bool, exec_ext: bool) -> u16 {
        let base: u16 = if !is_dir && self.showexec && !exec_ext {
            0o666
        } else {
            0o777
        };
        let base = if attr_ro && (!is_dir || self.rodir) {
            base & !0o222
        } else {
            base
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

    /// `is_exec(de->name + 8)`: the 8.3 extension `showexec` treats as
    /// executable.
    pub fn exec_extension(ext: &[u8]) -> bool {
        matches!(ext, b"EXE" | b"COM" | b"BAT")
    }
}

/// `fat_param_check` / `fat_param_tz` / `fat_param_errors` /
/// `fat_param_nfs` / `fat_param_shortname` value sets.
const CHECK: &[&str] = &["relaxed", "normal", "strict", "r", "n", "s"];
const TZ: &[&str] = &["utc", "UTC"];
const ERRORS: &[&str] = &["continue", "panic", "remount-ro"];
const NFS: &[&str] = &["stale_rw", "nostale_ro"];
const SHORTNAME: &[&str] = &["lower", "win95", "winnt", "mixed"];
const BOOL: &[&str] = &["0", "1", "y", "n", "yes", "no", "true", "false"];

/// `fat_parse_param` + `vfat_parse_param`, over the parameters the generic
/// layer did not consume.
///
/// NARF registers one option surface for `fat`/`vfat`/`fat16`/`fat32`: Linux
/// splits `msdos` (fat_param_specs) from `vfat` (plus vfat_param_specs), and
/// a parameter from the wrong dialect is EINVAL there. The union is accepted
/// here rather than tracking which alias a mount used, so a `vfat` line never
/// loses an option it is entitled to; the cost is that an `msdos`-only mount
/// also accepts `shortname=`, which changes nothing it reports.
pub fn parse(options: &str, uid: u32, gid: u32, umask: u16) -> Result<FatOpts, FsError> {
    let mut opts = FatOpts::defaults(uid, gid, umask);
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

fn apply(opts: &mut FatOpts, opt: Opt<'_>) -> Result<(), FsError> {
    match opt.key {
        // Acted on.
        "showexec" => {
            fsopts::flag_only(opt.value)?;
            opts.showexec = true;
        }
        "rodir" => {
            fsopts::flag_only(opt.value)?;
            opts.rodir = true;
        }
        // `tz=UTC` pins the on-disk times to UTC, which is what NARF decodes
        // them as already (it keeps no kernel timezone).
        "tz" => fsopts::enum_value(opt.value, TZ)?,
        // "GMT+-12 hours should be enough for all cases".
        "time_offset" => {
            let minutes = fsopts::int_value(opt.value, 0)?;
            if !(-12 * 60..=12 * 60).contains(&minutes) {
                return Err(FsError::InvalidData);
            }
            opts.tz_offset_secs = i64::from(-minutes) * 60;
        }
        // Accepted, not modelled — see the module LINUX-GAP.
        "allow_utime" => {
            let _ = fsopts::uint_value(opt.value, 8)?;
        }
        "codepage" | "blocksize" | "fat" => {
            let _ = fsopts::uint_value(opt.value, 0)?;
        }
        "iocharset" | "cvf_format" | "cvf_options" => fsopts::string_value(opt.value)?,
        "check" => fsopts::enum_value(opt.value, CHECK)?,
        "errors" => fsopts::enum_value(opt.value, ERRORS)?,
        "shortname" => fsopts::enum_value(opt.value, SHORTNAME)?,
        "conv" => fsopts::string_value(opt.value)?,
        // `fsparam_flag` / `fsparam_flag_no` / `fsparam_bool` shapes.
        "usefree" | "nocase" | "quiet" | "debug" | "sys_immutable" | "flush" | "discard"
        | "dos1xfloppy" | "uni_xlate" | "nonumtail" | "dots" | "nodots" => {
            fsopts::flag_only(opt.value)?
        }
        "utf8" | "dotsOK" => {
            if let Some(v) = opt.value {
                if !BOOL.contains(&v) {
                    return Err(FsError::InvalidData);
                }
            }
        }
        "nfs" => {
            if let Some(v) = opt.value {
                if !NFS.contains(&v) {
                    return Err(FsError::InvalidData);
                }
            }
        }
        // `fsparam_flag_no("discard")` also spells the negative form, and
        // `posix` is Linux's deprecated-but-accepted no-op.
        "nodiscard" | "posix" => fsopts::flag_only(opt.value)?,
        // `"%s: Unknown parameter '%s'"` — EINVAL.
        _ => return Err(FsError::InvalidData),
    }
    Ok(())
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The mount lines removable media actually arrive with all parse, and the
/// ownership and mask options reach the mode.
fn smoke_fat_opts_accept_removable_media_lines() -> TestResult {
    let lines = [
        "",
        "uid=1000,gid=1000,umask=022",
        "rw,uid=1000,gid=1000,dmask=0022,fmask=0133,iocharset=utf8,shortname=mixed",
        "ro,flush,discard,errors=remount-ro,tz=UTC",
        "showexec,rodir,allow_utime=0020,time_offset=-480,codepage=437",
        "quiet,nocase,usefree,nfs=nostale_ro,check=relaxed,utf8=1",
    ];
    for line in lines {
        if parse(line, 0, 0, 0o022).is_err() {
            return TestResult::Fail("a mount line Linux accepts was refused");
        }
    }
    let opts = match parse("uid=1000,gid=100,umask=077", 0, 0, 0o022) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("uid/gid/umask did not parse"),
    };
    if opts.owners.uid != 1000 || opts.owners.gid != 100 {
        return TestResult::Fail("uid=/gid= did not reach the ownership state");
    }
    // umask=077 is octal: 0777 & ~0077 = 0700.
    if opts.make_mode(false, false, false) != 0o700 || opts.make_mode(false, true, false) != 0o700 {
        return TestResult::Fail("umask= did not reach the mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_opts_accept_removable_media_lines
);

/// `fat_make_mode`: 0777 under the matching mask, ATTR_RO clearing write for
/// files always and for directories only with `rodir`, and `showexec`'s
/// extension test.
fn smoke_fat_opts_make_mode_matches_linux() -> TestResult {
    let plain = FatOpts::defaults(0, 0, 0);
    if plain.make_mode(false, false, false) != 0o777 {
        return TestResult::Fail("umask 0 should leave a file at 0777");
    }
    if plain.make_mode(true, false, false) != 0o555 {
        return TestResult::Fail("ATTR_RO should clear a file's write bits");
    }
    if plain.make_mode(true, true, false) != 0o777 {
        return TestResult::Fail("ATTR_RO on a directory needs rodir to apply");
    }
    let rodir = match parse("rodir", 0, 0, 0) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("rodir did not parse"),
    };
    if rodir.make_mode(true, true, false) != 0o555 {
        return TestResult::Fail("rodir should make ATTR_RO apply to a directory");
    }
    let showexec = match parse("showexec", 0, 0, 0) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("showexec did not parse"),
    };
    if showexec.make_mode(false, false, false) != 0o666 {
        return TestResult::Fail("showexec should drop x from a non-executable extension");
    }
    if showexec.make_mode(false, false, true) != 0o777 {
        return TestResult::Fail("showexec should keep x for EXE/COM/BAT");
    }
    if showexec.make_mode(false, true, false) != 0o777 {
        return TestResult::Fail("showexec applies to files, not directories");
    }
    if !FatOpts::exec_extension(b"EXE") || FatOpts::exec_extension(b"TXT") {
        return TestResult::Fail("is_exec should match EXE/COM/BAT only");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_opts_make_mode_matches_linux);

/// Linux's refusals: an unknown parameter, a flag given a value, a value of
/// the wrong shape, an out-of-table enum, and `time_offset` outside ±12h.
fn smoke_fat_opts_refuse_like_linux() -> TestResult {
    for line in [
        "bogus",
        "noexec",
        "uid",
        "uid=abc",
        "umask=778",
        "umask",
        "rodir=1",
        "flush=yes",
        "shortname=sideways",
        "errors=explode",
        "tz=CET",
        "time_offset=721",
        "time_offset=-721",
        "iocharset",
    ] {
        match parse(line, 0, 0, 0o022) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("a FAT mount parameter Linux refuses was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_opts_refuse_like_linux);

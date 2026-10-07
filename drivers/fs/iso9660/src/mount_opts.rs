//! `isofs_parse_param` (`fs/isofs/inode.c`).
//!
//! ISO 9660 stores no POSIX metadata either, so `uid=`, `gid=`, `mode=` and
//! `dmode=` are the whole ownership and permission surface. NARF refused any
//! non-empty data string with `Unsupported` (EOPNOTSUPP), so
//! `mount -t iso9660 -o ro,mode=0444,uid=1000 /dev/sr0 /mnt` failed and every
//! mount reported root-owned 0555 directories and 0444 files.
//!
//! The file default is Linux's, and it is not 0444:
//!
//! ```text
//! /*
//!  * Set default permissions: r-x for all.  The disc could be shared
//!  * with DOS machines so virtually anything could be a valid executable.
//!  */
//! inode->i_mode = S_IFREG | S_IRUGO | S_IXUGO;
//! ```
//!
//! so a binary or script burnt to a disc is executable on Linux. Unlike FAT,
//! isofs does NOT default to the mounting task's ids or umask: `popt->uid =
//! GLOBAL_ROOT_UID` and the mode defaults are fixed.
//!
//! LINUX-GAP: `norock` / `overriderockperm` and `nojoliet` change nothing,
//! because NARF implements neither Rock Ridge (RRIP: POSIX uid/gid/mode,
//! symlinks, long names, device nodes) nor Joliet (the UCS-2 supplementary
//! descriptor). Linux reads both by default, so a disc authored by
//! `mkisofs -r -J` shows long names, symlinks and real ownership there and
//! the bare ECMA-119 8.3-style names here. `map=`, `check=`, `session=`,
//! `sbsector=`, `block=`, `iocharset=`, `utf8`, `cruft`, `unhide`, `hide`,
//! `showassoc`, `nocompress` and `conv=` are accepted and not acted on —
//! Linux accepts each, and refusing them would break an otherwise valid
//! mount line.

use narf_filesystem::fsopts::{self, OwnerOpts};
use narf_filesystem::FsError;

/// `isofs_sb_info`'s ownership and permission state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsoOpts {
    pub owners: OwnerOpts,
    /// `mode=`, else `S_IRUGO | S_IXUGO`.
    pub fmode: u16,
    /// `dmode=`, else `S_IRUGO | S_IXUGO`.
    pub dmode: u16,
}

impl Default for IsoOpts {
    fn default() -> Self {
        Self {
            // `popt->uid = GLOBAL_ROOT_UID; popt->gid = GLOBAL_ROOT_GID`,
            // and no umask: isofs takes explicit modes, not masks.
            owners: OwnerOpts::from_mount(0, 0, 0),
            fmode: 0o555,
            dmode: 0o555,
        }
    }
}

impl IsoOpts {
    /// `isofs_read_inode`'s mode for a record.
    pub fn mode(&self, is_dir: bool) -> u16 {
        if is_dir {
            self.dmode
        } else {
            self.fmode
        }
    }
}

const MAP: &[&str] = &["normal", "off", "acorn", "n", "o", "a"];
const CHECK: &[&str] = &["relaxed", "strict", "r", "s"];

/// `isofs_parse_param` over the parameters the generic layer did not consume.
pub fn parse(options: &str) -> Result<IsoOpts, FsError> {
    let mut opts = IsoOpts::default();
    for opt in fsopts::iter(options) {
        if fsopts::is_vfs_param(opt.key) {
            continue;
        }
        match opt.key {
            // Acted on. `fsparam_uid`/`fsparam_gid` are base 0, and so are
            // `mode`/`dmode` (`fsparam_u32`), which is why `mode=0444` is
            // octal by its leading zero and `mode=444` is decimal.
            "uid" | "gid" => {
                opts.owners.take(opt)?;
            }
            "mode" => opts.fmode = (fsopts::uint_value(opt.value, 0)? & 0o7777) as u16,
            "dmode" => opts.dmode = (fsopts::uint_value(opt.value, 0)? & 0o7777) as u16,
            // Accepted, not modelled — see the module LINUX-GAP.
            "norock" | "nojoliet" | "unhide" | "hide" | "showassoc" | "cruft" | "utf8"
            | "overriderockperm" | "nocompress" => fsopts::flag_only(opt.value)?,
            "session" | "sbsector" | "block" => {
                let _ = fsopts::uint_value(opt.value, 0)?;
            }
            "iocharset" | "conv" => fsopts::string_value(opt.value)?,
            "map" => fsopts::enum_value(opt.value, MAP)?,
            "check" => fsopts::enum_value(opt.value, CHECK)?,
            // `"%s: Unknown parameter '%s'"` — EINVAL.
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok(opts)
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// A disc's default modes are Linux's r-x-for-all — including for files,
/// "because the disc could be shared with DOS machines so virtually anything
/// could be a valid executable" — and `mode=`/`dmode=`/`uid=`/`gid=` move
/// them.
fn smoke_iso_opts_match_linux() -> TestResult {
    let d = IsoOpts::default();
    if d.mode(false) != 0o555 || d.mode(true) != 0o555 {
        return TestResult::Fail("the isofs default mode should be r-x for all");
    }
    if d.owners.uid != 0 || d.owners.gid != 0 {
        return TestResult::Fail("isofs defaults to root ownership, not the mounting task");
    }
    for line in [
        "",
        "ro",
        "mode=0444,dmode=0555,uid=1000,gid=1000",
        "norock,nojoliet,check=relaxed,map=normal,block=2048",
        "session=1,sbsector=0,iocharset=utf8,utf8,unhide,cruft",
    ] {
        if parse(line).is_err() {
            return TestResult::Fail("a mount line Linux accepts was refused");
        }
    }
    let opts = match parse("mode=0444,dmode=0500,uid=1000,gid=100") {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("the ownership options did not parse"),
    };
    if opts.mode(false) != 0o444 || opts.mode(true) != 0o500 {
        return TestResult::Fail("mode=/dmode= did not reach the mode");
    }
    if opts.owners.uid != 1000 || opts.owners.gid != 100 {
        return TestResult::Fail("uid=/gid= did not reach the ownership state");
    }
    // `fsparam_u32` is base 0: a leading zero is octal, no prefix decimal.
    match parse("mode=444") {
        Ok(o) if o.mode(false) == (444 & 0o7777) => {}
        _ => return TestResult::Fail("mode= should parse in base 0, as fsparam_u32 does"),
    }
    for line in [
        "bogus",
        "norock=1",
        "mode",
        "mode=zz",
        "map=sideways",
        "iocharset",
    ] {
        match parse(line) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("an isofs parameter Linux refuses was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/iso9660", smoke_iso_opts_match_linux);

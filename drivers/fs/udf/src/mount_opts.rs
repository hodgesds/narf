//! `udf_parse_param` (`fs/udf/super.c`).
//!
//! UDF is the one format in this family that DOES record POSIX metadata —
//! the File Entry carries `Uid`, `Gid` and a `Permissions` word, and the ICB
//! tag carries setuid/setgid/sticky — so the options here override what is on
//! disk rather than inventing it: `uid=`/`gid=` replace the recorded ids
//! (and stand in for `UDF_INVALID_ID`, "not recorded"), `mode=`/`dmode=`
//! replace the converted permissions, and `umask=` subtracts from whatever
//! the mode ended up being.
//!
//! NARF refused any non-empty data string with `Unsupported` (EOPNOTSUPP),
//! so `mount -t udf -o ro,uid=1000 /dev/sr0 /mnt` failed.
//!
//! LINUX-GAP: `novrs`, `nostrict`, `unhide`, `undelete`, `adinicb` /
//! `noadinicb`, `shortad`, `longad`, `bs=`, `session=`, `lastblock=`,
//! `anchor=`, `volume=`, `partition=`, `fileset=`, `rootdir=`, `utf8` and
//! `iocharset=` are accepted and not acted on — Linux accepts each, and the
//! structures they steer (the VRS skip, multi-session anchors, the
//! allocation-descriptor preference for writes, NLS tables) are either
//! write-path or not modelled here. `uid=forget`/`uid=ignore`, the string
//! spellings Linux also takes for those two parameters, are accepted and
//! treated as "use the recorded id", which is what `ignore` means.

use narf_filesystem::fsopts::{self, Opt, OwnerOpts};
use narf_filesystem::FsError;

/// `udf_sb_info`'s ownership and permission overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdfOpts {
    /// `uid=`/`gid=` and their "was it set" flags: unlike FAT, an unset id
    /// means "report what the File Entry recorded".
    pub owners: OwnerOpts,
    /// `mode=` — replaces a non-directory's converted permissions.
    pub fmode: Option<u16>,
    /// `dmode=` — replaces a directory's.
    pub dmode: Option<u16>,
    /// `umask=` — cleared from the mode either way (`inode->i_mode &=
    /// ~sbi->s_umask`).
    pub umask: u16,
}

impl Default for UdfOpts {
    /// Linux's pre-option state: no id or mode override, no umask —
    /// `udf_init_fs_context` leaves `s_uid`/`s_gid` at the global root ids
    /// and `s_fmode`/`s_dmode` at `UDF_INVALID_MODE`.
    fn default() -> Self {
        Self {
            owners: OwnerOpts::from_mount(0, 0, 0),
            fmode: None,
            dmode: None,
            umask: 0,
        }
    }
}

impl UdfOpts {
    /// `udf_fill_inode`'s ownership and mode decisions, given what the File
    /// Entry recorded.
    ///
    /// ```text
    /// if (uid == UDF_INVALID_ID || UDF_QUERY_FLAG(sb, UDF_FLAG_UID_SET))
    ///         inode->i_uid = sbi->s_uid;
    /// else
    ///         i_uid_write(inode, uid);
    /// ...
    /// if (!dir && sbi->s_fmode != UDF_INVALID_MODE)  i_mode = sbi->s_fmode;
    /// else if (dir && sbi->s_dmode != UDF_INVALID_MODE) i_mode = sbi->s_dmode;
    /// else  i_mode = udf_convert_permissions(fe);
    /// i_mode &= ~sbi->s_umask;
    /// ```
    pub fn owner_ids(&self, recorded_uid: u32, recorded_gid: u32) -> (u32, u32) {
        let uid = if recorded_uid == crate::icb::UDF_INVALID_ID || self.owners.set_uid {
            self.owners.uid
        } else {
            recorded_uid
        };
        let gid = if recorded_gid == crate::icb::UDF_INVALID_ID || self.owners.set_gid {
            self.owners.gid
        } else {
            recorded_gid
        };
        (uid, gid)
    }

    pub fn mode(&self, is_dir: bool, permissions: u32, icb_flags: u16) -> u16 {
        let mode = match (is_dir, self.fmode, self.dmode) {
            (false, Some(fmode), _) => fmode,
            (true, _, Some(dmode)) => dmode,
            _ => crate::icb::convert_permissions(permissions, icb_flags),
        };
        mode & !self.umask & 0o7777
    }
}

/// `udf_parse_param` over the parameters the generic layer did not consume.
pub fn parse(options: &str) -> Result<UdfOpts, FsError> {
    let mut opts = UdfOpts::default();
    for opt in fsopts::iter(options) {
        if fsopts::is_vfs_param(opt.key) {
            continue;
        }
        apply(&mut opts, opt)?;
    }
    Ok(opts)
}

fn apply(opts: &mut UdfOpts, opt: Opt<'_>) -> Result<(), FsError> {
    match opt.key {
        // `fsparam_string("uid")`: a number sets it, and `forget`/`ignore`
        // are the historical spellings (`udf_parse_param`'s Opt_uid arm).
        "uid" | "gid" => match opt.value {
            Some("forget") | Some("ignore") => {}
            Some(v) => {
                let id = fsopts::kstrtouint(v, 0).ok_or(FsError::InvalidData)?;
                if opt.key == "uid" {
                    opts.owners.uid = id;
                    opts.owners.set_uid = true;
                } else {
                    opts.owners.gid = id;
                    opts.owners.set_gid = true;
                }
            }
            None => return Err(FsError::InvalidData),
        },
        "umask" => opts.umask = (fsopts::uint_value(opt.value, 0)? & 0o7777) as u16,
        "mode" => opts.fmode = Some((fsopts::uint_value(opt.value, 0)? & 0o7777) as u16),
        "dmode" => opts.dmode = Some((fsopts::uint_value(opt.value, 0)? & 0o7777) as u16),
        // Accepted, not modelled — see the module LINUX-GAP.
        "novrs" | "nostrict" | "unhide" | "undelete" | "adinicb" | "noadinicb" | "shortad"
        | "longad" | "utf8" => fsopts::flag_only(opt.value)?,
        "bs" | "session" | "lastblock" | "anchor" | "volume" | "partition" | "fileset"
        | "rootdir" => {
            let _ = fsopts::uint_value(opt.value, 0)?;
        }
        "iocharset" => fsopts::string_value(opt.value)?,
        _ => return Err(FsError::InvalidData),
    }
    Ok(())
}

// ── kernel tests ────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The recorded ownership and permissions win unless an option overrides
/// them, which is UDF's whole difference from FAT.
fn smoke_udf_opts_match_linux() -> TestResult {
    let d = UdfOpts::default();
    // `permissions` groups sit at 0/2/4 bit shifts: 0o7 | (0o5 << 5) is
    // "rwx" for other and "r-x" for group in UDF's encoding.
    let perms = 0o7 | (0o7 << 5) | (0o7 << 10);
    if d.mode(false, perms, 0) != 0o777 {
        return TestResult::Fail("udf_convert_permissions did not decode a full rwx word");
    }
    if d.owner_ids(1000, 100) != (1000, 100) {
        return TestResult::Fail("a recorded uid/gid should be reported as-is");
    }
    if d.owner_ids(crate::icb::UDF_INVALID_ID, crate::icb::UDF_INVALID_ID) != (0, 0) {
        return TestResult::Fail("UDF_INVALID_ID should fall back to the mount's ids");
    }
    for line in [
        "",
        "ro",
        "uid=1000,gid=1000,umask=022",
        "uid=forget,gid=ignore",
        "mode=0444,dmode=0555,bs=2048,session=1,anchor=256",
        "novrs,nostrict,unhide,undelete,shortad,longad,noadinicb,utf8",
    ] {
        if parse(line).is_err() {
            return TestResult::Fail("a mount line Linux accepts was refused");
        }
    }
    let opts = match parse("uid=1000,gid=100,mode=0600,dmode=0700,umask=0077") {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("the override options did not parse"),
    };
    if opts.owner_ids(5, 6) != (1000, 100) {
        return TestResult::Fail("uid=/gid= should override the recorded ids");
    }
    // umask=0077 clears the group/other bits of whatever mode= gave.
    if opts.mode(false, 0, 0) != 0o600 || opts.mode(true, 0, 0) != 0o700 {
        return TestResult::Fail("mode=/dmode= with umask= did not apply");
    }
    for line in ["bogus", "uid", "umask", "mode=zz", "novrs=1", "iocharset"] {
        match parse(line) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("a UDF parameter Linux refuses was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/udf", smoke_udf_opts_match_linux);

//! `mount -t btrfs` option parsing (`fs/btrfs/super.c::btrfs_parse_param`).
//!
//! The options a distro fstab carries are accepted and recorded on the
//! volume ([`crate::volume::BtrfsVolume::mount_options`]), so the writer and
//! `show_options` can honour them. CachyOS's fstab, for example, passes
//! `subvol=/@,noatime,compress=zstd:1` and the live mount adds
//! `ssd,discard=async,space_cache=v2`.
//!
//! The rule for an option NARF does not implement:
//!
//! - It is **accepted** when it is a run-time policy that leaves the on-disk
//!   format readable by every btrfs. Examples are the compression choice for
//!   new writes, discard, ssd allocation hints, commit interval, autodefrag
//!   and the free-space-tree cache choice (NARF always maintains the free
//!   space tree that the superblock declares).
//! - It is **refused** when it would change the on-disk format or recovery
//!   semantics in a way NARF cannot honour, such as `nodatasum`,
//!   `nodatacow`, `rescue=`, `usebackuproot`, `clear_cache`, `device=`
//!   (multi-device assembly is automatic), `degraded`, `space_cache=v1` and
//!   unknown options.
//!
//! `noatime`/`relatime`/`ro`/`rw` are VFS or superblock flags. `mount(8)`
//! turns them into `MS_*` flags, but they may also arrive in the data
//! string from a kernel `rootflags=`, so they are accepted as no-ops here.

use alloc::string::String;
use core::fmt::Write as _;

use narf_filesystem::FsError;

use crate::volume::Subvol;

/// Compression algorithm requested by `compress=` / `compress-force=`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompressAlgo {
    Zlib,
    Lzo,
    Zstd,
}

/// A `compress=` / `compress-force=` request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Compression {
    pub algo: CompressAlgo,
    /// Explicit `:N` level; `None` is the algorithm default.
    pub level: Option<u8>,
    /// `compress-force=`: compress even incompressible-looking data.
    pub force: bool,
}

/// `discard` mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Discard {
    /// `nodiscard` or nothing.
    #[default]
    Off,
    /// `discard` / `discard=sync`.
    Sync,
    /// `discard=async`.
    Async,
}

/// Parsed `mount -t btrfs` data string.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountOptions {
    pub subvol: Option<Subvol>,
    /// `ro` in the data string (a kernel `rootflags=ro`).
    pub read_only: bool,
    /// `None` = `compress=no` / not given: new data is written uncompressed.
    pub compress: Option<Compression>,
    pub discard: Discard,
    /// `ssd` / `nossd` / `ssd_spread`; `None` = auto-detect.
    pub ssd: Option<bool>,
    /// `space_cache=v2` was requested (the free-space tree).
    pub space_cache_v2: bool,
    /// `commit=N` seconds.
    pub commit_secs: Option<u32>,
    pub autodefrag: bool,
}

fn parse_compress(value: Option<&str>, force: bool) -> Result<Option<Compression>, FsError> {
    // `compress` alone is zlib, like Linux.
    let value = value.unwrap_or("zlib");
    let (name, level) = match value.split_once(':') {
        Some((name, level)) => {
            let level: u8 = level.parse().map_err(|_| FsError::InvalidData)?;
            (name, Some(level))
        }
        None => (value, None),
    };
    let algo = match name {
        "zlib" => CompressAlgo::Zlib,
        "lzo" => CompressAlgo::Lzo,
        "zstd" => CompressAlgo::Zstd,
        "no" | "none" if level.is_none() => return Ok(None),
        _ => return Err(FsError::InvalidData),
    };
    // Linux clamps out-of-range levels; refuse obviously bogus ones instead
    // of recording them.
    let max = match algo {
        CompressAlgo::Zlib => 9,
        CompressAlgo::Lzo => 1,
        CompressAlgo::Zstd => 15,
    };
    if level.is_some_and(|level| level > max) {
        return Err(FsError::InvalidData);
    }
    Ok(Some(Compression { algo, level, force }))
}

/// Parse a `mount -t btrfs` data string.
pub fn parse(options: &str) -> Result<MountOptions, FsError> {
    let mut out = MountOptions::default();
    for option in options.split(',').filter(|s| !s.is_empty()) {
        let (key, value) = match option.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (option, None),
        };
        match (key, value) {
            ("subvolid", Some(v)) => {
                out.subvol = Some(Subvol::Id(v.parse().map_err(|_| FsError::InvalidData)?));
            }
            ("subvol", Some(v)) => {
                // Leading/trailing slashes are harmless, but empty, dot, and
                // dotdot components make resolution ambiguous and are
                // rejected.
                let path = v.trim_matches('/');
                if path.is_empty()
                    || path
                        .split('/')
                        .any(|c| c.is_empty() || c == "." || c == "..")
                {
                    return Err(FsError::Unsupported);
                }
                out.subvol = Some(Subvol::Name(String::from(path)));
            }
            ("ro", None) => out.read_only = true,
            ("rw", None) => out.read_only = false,
            // VFS/superblock flags that may arrive through `rootflags=`.
            (
                "noatime" | "relatime" | "strictatime" | "nodiratime" | "lazytime" | "nolazytime"
                | "defaults",
                None,
            ) => {}
            ("errors", Some("continue" | "remount-ro" | "panic")) => {}
            ("compress", v) => out.compress = parse_compress(v, false)?,
            ("compress-force", v) => out.compress = parse_compress(v, true)?,
            ("discard", None | Some("sync")) => out.discard = Discard::Sync,
            ("discard", Some("async")) => out.discard = Discard::Async,
            ("nodiscard", None) => out.discard = Discard::Off,
            ("ssd" | "ssd_spread", None) => out.ssd = Some(true),
            ("nossd" | "nossd_spread", None) => out.ssd = Some(false),
            ("space_cache", Some("v2")) => out.space_cache_v2 = true,
            ("commit", Some(v)) => {
                out.commit_secs = Some(v.parse().map_err(|_| FsError::InvalidData)?);
            }
            ("autodefrag", None) => out.autodefrag = true,
            ("noautodefrag", None) => out.autodefrag = false,
            // Pure run-time behaviour with no format impact.
            (
                "barrier"
                | "nobarrier"
                | "flushoncommit"
                | "noflushoncommit"
                | "acl"
                | "noacl"
                | "user_subvol_rm_allowed"
                | "enospc_debug"
                | "noenospc_debug"
                | "datacow"
                | "datasum"
                | "treelog"
                | "notreelog"
                | "skip_balance",
                None,
            ) => {}
            ("thread_pool" | "max_inline" | "metadata_ratio" | "check_int_print_mask", Some(_)) => {
            }
            // Everything else either changes the on-disk format / recovery
            // semantics (nodatasum, nodatacow, space_cache=v1, clear_cache,
            // norecovery, rescue=, usebackuproot, degraded, device=,
            // fragment=, ...) or is unknown.
            _ => return Err(FsError::Unsupported),
        }
    }
    Ok(out)
}

impl MountOptions {
    /// Linux `btrfs_show_options` order for the options NARF records, as a
    /// `,`-prefixed list (without `subvolid=`/`subvol=`, which the volume
    /// appends from the mounted tree).
    pub fn render(&self) -> String {
        let mut out = String::new();
        if let Some(c) = self.compress {
            let name = match c.algo {
                CompressAlgo::Zlib => "zlib",
                CompressAlgo::Lzo => "lzo",
                CompressAlgo::Zstd => "zstd",
            };
            let key = if c.force {
                "compress-force"
            } else {
                "compress"
            };
            let _ = write!(out, ",{key}={name}");
            if let Some(level) = c.level {
                let _ = write!(out, ":{level}");
            }
        }
        match self.ssd {
            Some(true) => out.push_str(",ssd"),
            Some(false) => out.push_str(",nossd"),
            None => {}
        }
        match self.discard {
            Discard::Off => {}
            Discard::Sync => out.push_str(",discard"),
            Discard::Async => out.push_str(",discard=async"),
        }
        // The free-space tree is what NARF maintains whenever the superblock
        // declares it; record only the explicit request.
        if self.space_cache_v2 {
            out.push_str(",space_cache=v2");
        }
        if let Some(commit) = self.commit_secs {
            let _ = write!(out, ",commit={commit}");
        }
        if self.autodefrag {
            out.push_str(",autodefrag");
        }
        out
    }
}

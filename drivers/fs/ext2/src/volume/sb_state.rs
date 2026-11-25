//! The superblock across a read-write mount, and the write gate.
//!
//! NARF writes ext4 metadata in place, never through the journal. It keeps
//! the superblock the way Linux ext4 does when it has no journal
//! (`fs/ext4/super.c`):
//!
//! - **Mount read-write** (`ext4_setup_super`): clear `EXT4_VALID_FS`, bump
//!   `s_mnt_count`, set `s_mtime`, give `s_max_mnt_count` its default, and
//!   record the directory-hash signedness if `s_flags` names none
//!   (`ext4_hash_info_init`). This is written with FUA and flushed before
//!   any other write, so a crash can never leave changed metadata on a
//!   filesystem that still says it is clean. The next `e2fsck -p` (the
//!   `fsck` hook of an initramfs, `systemd-fsck`) then does a full check.
//! - **Remount read-only, last unmount** (`ext4_put_super`,
//!   `__ext4_remount`): after everything is written back, restore `s_state`
//!   to its mount-time value, plus `EXT4_ERROR_FS` if an error was seen.
//! - `syncfs` never marks the filesystem clean (Linux does not either).
//!
//! The gate ([`rw_refusal`]) decides whether a mount may write at all.
//! Under `narf.disks=root-rw` it is stricter than Linux: a filesystem with
//! recorded errors, or one that was not cleanly unmounted, stays read-only
//! until e2fsck has seen it. Linux mounts those with a warning.

use core::sync::atomic::Ordering;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::super::htree::hash_version;
use super::super::superblock::{
    compat, incompat, ro_compat, Superblock, EXT2_ERROR_FS, EXT2_FLAGS_SIGNED_HASH,
    EXT2_FLAGS_UNSIGNED_HASH, EXT2_VALID_FS, EXT4_ERRORS_PANIC, EXT4_ERRORS_RO,
};
use super::{metadata_csum, Ext2Volume};

/// Superblock field offsets (`struct ext4_super_block`, checked against
/// e2fsprogs' `struct ext2_super_block`).
pub(crate) mod off {
    pub const MTIME: usize = 0x2c;
    pub const WTIME: usize = 0x30;
    pub const MNT_COUNT: usize = 0x34;
    pub const MAX_MNT_COUNT: usize = 0x36;
    pub const STATE: usize = 0x3a;
    pub const FEATURE_INCOMPAT: usize = 0x60;
    pub const FEATURE_RO_COMPAT: usize = 0x64;
    pub const FLAGS: usize = 0x160;
    pub const ERROR_COUNT: usize = 0x194;
    pub const FIRST_ERROR_TIME: usize = 0x198;
    pub const FIRST_ERROR_INO: usize = 0x19c;
    pub const FIRST_ERROR_BLOCK: usize = 0x1a0;
    pub const FIRST_ERROR_FUNC: usize = 0x1a8;
    pub const FIRST_ERROR_LINE: usize = 0x1c8;
    pub const LAST_ERROR_TIME: usize = 0x1cc;
    pub const LAST_ERROR_INO: usize = 0x1d0;
    pub const LAST_ERROR_LINE: usize = 0x1d4;
    pub const LAST_ERROR_BLOCK: usize = 0x1d8;
    pub const LAST_ERROR_FUNC: usize = 0x1e0;
    pub const WTIME_HI: usize = 0x274;
    pub const MTIME_HI: usize = 0x275;
    pub const FIRST_ERROR_TIME_HI: usize = 0x278;
    pub const LAST_ERROR_TIME_HI: usize = 0x279;
    pub const FIRST_ERROR_ERRCODE: usize = 0x27a;
    pub const LAST_ERROR_ERRCODE: usize = 0x27b;
}

/// `EXT4_DFL_MAX_MNT_COUNT`.
pub(crate) const EXT4_DFL_MAX_MNT_COUNT: u16 = 20;

/// Which rules the write gate applies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GateProfile {
    /// Linux's rules.
    Default,
    /// `narf.disks=root-rw`: the installed root of a real machine.
    RootRw,
}

impl GateProfile {
    /// The profile the boot's disk policy calls for.
    pub fn current() -> Self {
        if narf_block::disk_policy::policy() == narf_block::disk_policy::DiskPolicy::RootRw {
            Self::RootRw
        } else {
            Self::Default
        }
    }
}

/// Why a read-write mount is refused, and what the mount then does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `EXT4_FEATURE_RO_COMPAT_READONLY`: Linux mounts the filesystem
    /// read-only without an error ("filesystem is read-only"), and so does
    /// NARF.
    ReadOnlyFeature,
    /// Linux refuses the read-write mount too (`ext4_feature_set_ok`
    /// returns 0, `ext4_fill_super` fails with EINVAL): a read-write
    /// request fails with `InvalidData` (EINVAL).
    Unsupported(&'static str),
    /// Linux would write this filesystem; NARF does not. A read-write
    /// request fails with `ReadOnly` (EROFS), which makes libmount retry
    /// read-only as it does for a write-protected device.
    Gate(&'static str),
}

impl Refusal {
    pub fn why(&self) -> &'static str {
        match self {
            Self::ReadOnlyFeature => "it has the READONLY feature",
            Self::Unsupported(why) | Self::Gate(why) => why,
        }
    }
}

/// Why a read-write mount of `sb` is refused, or `None` when NARF may
/// write it. `journal_clean` is whether the JBD2 log has nothing to replay
/// (a stale `RECOVER` bit is then repaired); `orphans_empty` whether the
/// orphan file lists nothing (a stale `ORPHAN_PRESENT` likewise).
pub fn rw_refusal(
    sb: &Superblock,
    journal_clean: bool,
    orphans_empty: bool,
    profile: GateProfile,
) -> Option<Refusal> {
    let ro = sb.feature_ro_compat;
    // `ext4_feature_set_ok(sb, readonly = 0)`, in its order: READONLY first,
    // then any bit Linux does not know.
    if ro & ro_compat::READONLY != 0 {
        return Some(Refusal::ReadOnlyFeature);
    }
    if ro & !ro_compat::LINUX_SUPPORTED != 0 {
        return Some(Refusal::Unsupported(
            "couldn't mount RDWR because of unsupported optional features",
        ));
    }
    // LINUX-GAP: everything below is a filesystem Linux writes and NARF
    // does not (yet).
    if ro & !(ro_compat::WRITE_SUPPORTED | ro_compat::ORPHAN_PRESENT) != 0 {
        return Some(Refusal::Gate(
            "it has quota, project, bigalloc, verity or btree_dir features NARF cannot write",
        ));
    }
    if ro & ro_compat::GDT_CSUM != 0 && !sb.has_metadata_csum() {
        return Some(Refusal::Gate(
            "its group descriptors use the legacy gdt_csum checksum",
        ));
    }
    if sb.feature_incompat & incompat::RECOVER != 0 && !journal_clean {
        return Some(Refusal::Gate(
            "its journal needs recovery; mount it once with Linux or run e2fsck",
        ));
    }
    if ro & ro_compat::ORPHAN_PRESENT != 0 && !orphans_empty {
        return Some(Refusal::Gate(
            "its orphan file lists inodes still to be released; run e2fsck",
        ));
    }
    // The pre-orphan-file list (`s_last_orphan`): NARF never walks it.
    if sb.last_orphan != 0 {
        return Some(Refusal::Gate(
            "its orphan inode list is not empty; run e2fsck",
        ));
    }
    // `make_indexed_dir` would index new directories with this hash.
    if sb.feature_compat & compat::DIR_INDEX != 0 && sb.def_hash_version > hash_version::TEA {
        return Some(Refusal::Gate(
            "its default directory hash is not legacy, half-MD4 or TEA",
        ));
    }
    if profile == GateProfile::RootRw {
        // LINUX-GAP: Linux mounts these read-write with "warning: mounting
        // fs with errors" / "mounting unchecked fs". NARF writes without a
        // journal, so on a production root it insists that e2fsck has seen
        // the filesystem first.
        if sb.state & EXT2_ERROR_FS != 0 {
            return Some(Refusal::Gate("it has recorded errors; run e2fsck"));
        }
        if sb.state & EXT2_VALID_FS == 0 {
            return Some(Refusal::Gate("it was not cleanly unmounted; run e2fsck"));
        }
    }
    None
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// `ext4_update_tstamp`: the low 32 bits and the `_hi` byte.
fn put_time(b: &mut [u8], lo: usize, hi: usize, secs: u64) {
    put_u32(b, lo, secs as u32);
    b[hi] = (secs >> 32) as u8;
}

/// Where in the code an error was found, for the superblock's error record
/// (`s_first_error_*`, `s_last_error_*`).
#[derive(Copy, Clone, Debug)]
pub struct ErrorSite {
    /// The NARF function, recorded as Linux records `__func__`.
    pub func: &'static str,
    pub ino: u32,
    pub block: u64,
    /// The errno the operation failed with (positive; 0 means
    /// EFSCORRUPTED, as `save_error_info` defaults it).
    pub errno: i64,
}

/// `ext4_errno_to_code`: the `EXT4_ERR_*` code e2fsck reads from
/// `s_*_error_errcode`.
fn errno_to_code(errno: i64) -> u8 {
    use narf_lib::errno::*;
    match errno {
        EIO => 2,
        ENOMEM => 3,
        EBADMSG => 4, // EFSBADCRC
        EUCLEAN => 5, // EFSCORRUPTED
        ENOSPC => 6,
        ENOKEY => 7,
        EROFS => 8,
        EFBIG => 9,
        EEXIST => 10,
        ERANGE => 11,
        EOVERFLOW => 12,
        EBUSY => 13,
        ENOTDIR => 14,
        ENOTEMPTY => 15,
        ESHUTDOWN => 16,
        EFAULT => 17,
        _ => 1, // EXT4_ERR_UNKNOWN
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Whether this mount writes nothing.
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Acquire)
    }

    /// Why the write gate refused a read-write mount, if it did.
    pub fn refusal(&self) -> Option<Refusal> {
        self.refusal
    }

    /// One read-modify-write of the primary superblock: `f` edits the
    /// bytes, then `s_wtime` and the checksum are refreshed and the block
    /// goes to the device with FUA, followed by a cache flush, so the state
    /// is on media before the caller writes anything that depends on it.
    /// Serialized with the allocation counters' own superblock writes.
    pub(crate) async fn sb_update(&self, f: impl FnOnce(&mut [u8])) -> Result<(), FsError> {
        let _guard = self.allocation_lock.lock().await;
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        f(&mut bytes);
        put_time(
            &mut bytes,
            off::WTIME,
            off::WTIME_HI,
            u64::from(Self::now_secs()),
        );
        metadata_csum::write_superblock_checksum(&self.superblock, &mut bytes)
            .ok_or(FsError::InvalidData)?;
        self.write_byte_range_fua(1024, &bytes).await?;
        self.device.flush_result().await.map_err(FsError::Io)
    }

    /// `ext4_setup_super` for a read-write mount without a journal, plus
    /// the repair of a stale `RECOVER` / `ORPHAN_PRESENT` the gate found
    /// clean. Marks the filesystem dirty; [`Self::mark_clean`] undoes it.
    pub(crate) async fn setup_super(&self) -> Result<(), FsError> {
        let now = u64::from(Self::now_secs());
        let platform_unsigned = core::ffi::c_char::MIN == 0;
        self.sb_update(|b| {
            let mut incompat_bits = get_u32(b, off::FEATURE_INCOMPAT);
            let mut ro_bits = get_u32(b, off::FEATURE_RO_COMPAT);
            incompat_bits &= !incompat::RECOVER;
            ro_bits &= !ro_compat::ORPHAN_PRESENT;
            put_u32(b, off::FEATURE_INCOMPAT, incompat_bits);
            put_u32(b, off::FEATURE_RO_COMPAT, ro_bits);
            let state = get_u16(b, off::STATE);
            put_u16(b, off::STATE, state & !EXT2_VALID_FS);
            if get_u16(b, off::MAX_MNT_COUNT) as i16 == 0 {
                put_u16(b, off::MAX_MNT_COUNT, EXT4_DFL_MAX_MNT_COUNT);
            }
            put_u16(
                b,
                off::MNT_COUNT,
                get_u16(b, off::MNT_COUNT).wrapping_add(1),
            );
            put_time(b, off::MTIME, off::MTIME_HI, now);
            let flags = get_u32(b, off::FLAGS);
            if flags & (EXT2_FLAGS_SIGNED_HASH | EXT2_FLAGS_UNSIGNED_HASH) == 0 {
                let bit = if platform_unsigned {
                    EXT2_FLAGS_UNSIGNED_HASH
                } else {
                    EXT2_FLAGS_SIGNED_HASH
                };
                put_u32(b, off::FLAGS, flags | bit);
            }
        })
        .await?;
        self.dirty_marked.store(true, Ordering::Release);
        Ok(())
    }

    /// `ext4_put_super` / remount read-only: restore `s_state` to what the
    /// mount found, with `EXT4_ERROR_FS` if this mount saw an error. The
    /// caller has written back and flushed everything first.
    pub(crate) async fn mark_clean(&self) -> Result<(), FsError> {
        if !self.dirty_marked.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.mount_state;
        if self.errors_seen.load(Ordering::Acquire) {
            state |= EXT2_ERROR_FS;
        }
        self.sb_update(|b| put_u16(b, off::STATE, state)).await?;
        self.dirty_marked.store(false, Ordering::Release);
        Ok(())
    }

    /// Remount read-only (`__ext4_remount` with `SB_RDONLY`): write back
    /// every dirty page and orphan, flush, mark the filesystem clean, then
    /// stop writing.
    pub(crate) async fn remount_read_only(&self) -> Result<(), FsError> {
        if self.is_read_only() {
            return Ok(());
        }
        self.sync_filesystem().await?;
        self.mark_clean().await?;
        self.read_only.store(true, Ordering::Release);
        Ok(())
    }

    /// Remount read-write: the gate again, over the superblock as it is on
    /// the device now, then [`Self::setup_super`].
    pub(crate) async fn remount_read_write(&self) -> Result<(), FsError> {
        if !self.is_read_only() {
            return Ok(());
        }
        if self.device.is_read_only() || !self.journal_overrides.is_empty() {
            return Err(FsError::ReadOnly);
        }
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        let sb = Superblock::parse(&bytes).ok_or(FsError::InvalidData)?;
        // A read-only mount repaired nothing: the flags must be clear now.
        if let Some(refusal) = rw_refusal(&sb, false, false, self.profile) {
            report_refusal(&self.superblock, refusal);
            return Err(match refusal {
                Refusal::Unsupported(_) => FsError::InvalidData,
                Refusal::ReadOnlyFeature | Refusal::Gate(_) => FsError::ReadOnly,
            });
        }
        self.read_only.store(false, Ordering::Release);
        if let Err(error) = self.setup_super().await {
            self.read_only.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    /// `__ext4_error` → `ext4_handle_error`: record an error in the
    /// superblock (`EXT4_ERROR_FS`, `s_error_count`, the first and last
    /// error), then act on it: under `narf.disks=root-rw`, or with
    /// `s_errors=remount-ro`, stop writing; with `s_errors=panic`, panic as
    /// Linux does; otherwise continue.
    pub(crate) async fn fs_error(&self, site: ErrorSite) {
        use core::fmt::Write as _;
        self.errors_seen.store(true, Ordering::Release);
        let _ = writeln!(
            narf_console::Writer,
            "EXT4-fs error ({}): {}: inode #{}: block {}: errno {}",
            uuid_string(&self.superblock),
            site.func,
            site.ino,
            site.block,
            site.errno
        );
        let errno = if site.errno == 0 {
            narf_lib::errno::EUCLEAN
        } else {
            site.errno
        };
        let code = errno_to_code(errno);
        if !self.is_read_only() {
            let now = u64::from(Self::now_secs());
            let _ = self
                .sb_update(|b| {
                    put_u16(b, off::STATE, get_u16(b, off::STATE) | EXT2_ERROR_FS);
                    let count = get_u32(b, off::ERROR_COUNT);
                    let first_unset =
                        get_u32(b, off::FIRST_ERROR_TIME) == 0 && b[off::FIRST_ERROR_TIME_HI] == 0;
                    if first_unset {
                        put_time(b, off::FIRST_ERROR_TIME, off::FIRST_ERROR_TIME_HI, now);
                        put_u32(b, off::FIRST_ERROR_INO, site.ino);
                        b[off::FIRST_ERROR_BLOCK..off::FIRST_ERROR_BLOCK + 8]
                            .copy_from_slice(&site.block.to_le_bytes());
                        put_func(b, off::FIRST_ERROR_FUNC, site.func);
                        put_u32(b, off::FIRST_ERROR_LINE, 0);
                        b[off::FIRST_ERROR_ERRCODE] = code;
                    }
                    put_u32(b, off::ERROR_COUNT, count.saturating_add(1));
                    put_time(b, off::LAST_ERROR_TIME, off::LAST_ERROR_TIME_HI, now);
                    put_u32(b, off::LAST_ERROR_INO, site.ino);
                    b[off::LAST_ERROR_BLOCK..off::LAST_ERROR_BLOCK + 8]
                        .copy_from_slice(&site.block.to_le_bytes());
                    put_func(b, off::LAST_ERROR_FUNC, site.func);
                    put_u32(b, off::LAST_ERROR_LINE, 0);
                    b[off::LAST_ERROR_ERRCODE] = code;
                })
                .await;
        }
        if self.superblock.errors == EXT4_ERRORS_PANIC {
            panic!(
                "EXT4-fs ({}): panic forced after error",
                uuid_string(&self.superblock)
            );
        }
        if (self.profile == GateProfile::RootRw || self.superblock.errors == EXT4_ERRORS_RO)
            && !self.is_read_only()
        {
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs ({}): Remounting filesystem read-only",
                uuid_string(&self.superblock)
            );
            self.read_only.store(true, Ordering::Release);
        }
    }
}

/// `s_*_error_func`: 32 bytes, NUL-padded, not necessarily terminated.
fn put_func(b: &mut [u8], at: usize, func: &str) {
    let field = &mut b[at..at + 32];
    field.fill(0);
    let n = func.len().min(32);
    field[..n].copy_from_slice(&func.as_bytes()[..n]);
}

pub(crate) fn uuid_string(sb: &Superblock) -> alloc::string::String {
    narf_block::partition::format_uuid_bytes(&sb.uuid).to_ascii_lowercase()
}

/// Log a refused read-write mount, in the form the btrfs gate uses, and
/// keep the reason for the boot's root-mount report.
pub(crate) fn report_refusal(sb: &Superblock, refusal: Refusal) {
    use core::fmt::Write as _;
    let line = alloc::format!(
        "ext4 {}: REFUSING read-write mount: {}; mounting READ-ONLY",
        uuid_string(sb),
        refusal.why()
    );
    let _ = writeln!(narf_console::Writer, "{line}");
    narf_filesystem::rw_refusal::record(&line);
}

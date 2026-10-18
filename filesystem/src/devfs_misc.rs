//! Miscellaneous `/dev` nodes: `/dev/full`, `/dev/btrfs-control`.
//!
//! Linux ref: `drivers/char/mem.c full_read` / `full_write`.
//!
//! ## `/dev/full`
//!
//! - `read()` fills the buffer with zeros (same behaviour as `/dev/zero`).
//! - `write()` always returns `FsError::NoSpace` (ENOSPC), signalling that
//!   the device has no room.
//!
//! This is useful for testing applications' error-handling paths: write to
//! `/dev/full` to simulate a disk-full condition without actually filling a
//! disk.
//!
//! ## Deferred
//!
//! - `/dev/loop0..7` — file-backed loopback block devices.  These require
//!   the `block/` loopback driver which is not yet implemented.
//! - `/dev/fuse` — userspace filesystem channel.  Requires the FUSE transport
//!   layer (`filesystem/src/fuse.rs` carries the protocol types but the
//!   channel device node is deferred until a full FUSE daemon is available).

use alloc::boxed::Box;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// `/dev/full` — read returns zeros; write returns ENOSPC.
///
/// Linux ref: `drivers/char/mem.c full_read` (returns zeros, like
///   `/dev/zero`) and `full_write` (returns -ENOSPC).
#[derive(Debug)]
pub struct DevFull;

impl FileOps for DevFull {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        for slot in buf.iter_mut() {
            *slot = 0;
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::NoSpace) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(1, 7)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }
}

// ── /dev/btrfs-control ───────────────────────────────────────────────

/// `BTRFS_IOCTL_MAGIC`.
const BTRFS_IOCTL_MAGIC: u32 = 0x94;
/// `sizeof(struct btrfs_ioctl_vol_args)`: `__s64 fd; char name[4088]`.
const BTRFS_VOL_ARGS_SIZE: u32 = 4096;
const fn btrfs_ioc(dir: u32, nr: u32) -> u32 {
    (dir << 30) | (BTRFS_VOL_ARGS_SIZE << 16) | (BTRFS_IOCTL_MAGIC << 8) | nr
}
/// `BTRFS_IOC_SCAN_DEV` = `_IOW(0x94, 4, struct btrfs_ioctl_vol_args)`.
pub(crate) const BTRFS_IOC_SCAN_DEV: u32 = btrfs_ioc(1, 4);
/// `BTRFS_IOC_FORGET_DEV` = `_IOW(0x94, 5, ...)`.
pub(crate) const BTRFS_IOC_FORGET_DEV: u32 = btrfs_ioc(1, 5);
/// `BTRFS_IOC_DEVICES_READY` = `_IOR(0x94, 39, ...)`.
pub(crate) const BTRFS_IOC_DEVICES_READY: u32 = btrfs_ioc(2, 39);

/// Primary btrfs superblock offset, and the fields read from it.
const BTRFS_SUPER_OFFSET: u64 = 65536;
const BTRFS_SB_FSID: usize = 0x20;
const BTRFS_SB_MAGIC: usize = 0x40;
const BTRFS_SB_NUM_DEVICES: usize = 0x88;

/// `(fsid, num_devices)` from `dev`'s primary btrfs superblock.
fn btrfs_identity(dev: &dyn narf_block::BlockDeviceSync) -> Option<([u8; 16], u64)> {
    let lba = dev.lba_size() as u64;
    if lba == 0 || BTRFS_SUPER_OFFSET % lba != 0 || 4096 % lba != 0 {
        return None;
    }
    let first = BTRFS_SUPER_OFFSET / lba;
    let count = (4096 / lba) as u16;
    if first + u64::from(count) > dev.capacity() {
        return None;
    }
    let mut raw = alloc::vec![0u8; 4096];
    dev.read(first, count, &mut raw).ok()?;
    if raw.get(BTRFS_SB_MAGIC..BTRFS_SB_MAGIC + 8) != Some(b"_BHRfS_M".as_slice()) {
        return None;
    }
    let fsid: [u8; 16] = raw[BTRFS_SB_FSID..BTRFS_SB_FSID + 16].try_into().ok()?;
    let num = u64::from_le_bytes(
        raw[BTRFS_SB_NUM_DEVICES..BTRFS_SB_NUM_DEVICES + 8]
            .try_into()
            .ok()?,
    );
    Some((fsid, num))
}

/// `BTRFS_IOC_DEVICES_READY` for the device at `path`: `Ok(0)` when every
/// member of its filesystem is registered, `Ok(1)` when some are missing
/// (`btrfs_control_ioctl`: `ret = !(fs_devices->num_devices ==
/// fs_devices->total_devices)`), and an error for a path that is not a
/// registered btrfs member.
pub(crate) fn btrfs_devices_ready(path: &str) -> Result<u64, FsError> {
    let name = crate::fs_registry::block_source_name(path).ok_or(FsError::NotFound)?;
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    let (fsid, total) = btrfs_identity(dev.as_ref()).ok_or(FsError::InvalidData)?;
    let present = narf_block::block_devices()
        .into_iter()
        .filter(|entry| btrfs_identity(entry.dev.as_ref()).is_some_and(|(id, _)| id == fsid))
        .count() as u64;
    Ok(u64::from(present < total.max(1)))
}

/// `/dev/btrfs-control` (misc 10:234), the btrfs device-scan channel.
///
/// systemd-udevd's `btrfs` builtin (`64-btrfs.rules`) asks it whether every
/// member of a btrfs filesystem is present. Without the node it records
/// `ID_BTRFS_READY=0` and `SYSTEMD_READY=0`, so the `/dev/disk/by-uuid/<fsid>`
/// device unit never appears and every fstab subvolume mount (the CachyOS
/// layout) times out into emergency mode. NARF assembles multi-device volumes
/// from the block registry at mount, so `SCAN_DEV` and `FORGET_DEV` have
/// nothing to record and succeed.
#[derive(Debug)]
pub struct DevBtrfsControl;

impl FileOps for DevBtrfsControl {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(10, 234)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn crate::IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            if !matches!(
                cmd,
                BTRFS_IOC_SCAN_DEV | BTRFS_IOC_FORGET_DEV | BTRFS_IOC_DEVICES_READY
            ) {
                return Err(FsError::Unsupported);
            }
            let mut args = alloc::vec![0u8; BTRFS_VOL_ARGS_SIZE as usize];
            context.read(arg, &mut args)?;
            let name = &args[8..];
            let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let path = core::str::from_utf8(&name[..len]).map_err(|_| FsError::InvalidData)?;
            match cmd {
                BTRFS_IOC_DEVICES_READY => btrfs_devices_ready(path),
                // `FORGET_DEV` with an empty name forgets every unmounted
                // device; either way there is no scan cache to update.
                _ if path.is_empty() => Ok(0),
                _ => {
                    btrfs_devices_ready(path)?;
                    Ok(0)
                }
            }
        })
    }
}

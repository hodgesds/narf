//! VFS nodes: `BtrfsNode` implements both `FileOps` and `DirOps` (a btrfs inode
//! is one or the other by mode), and `BtrfsVolume` implements `FsInstance`.
//!
//! Like the squashfs driver, all real work is async: the sync `lookup`/`iter`
//! surfaces return empty and the VFS drives `*_async` instead.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, FsIoctlReply,
    FsQuotaInherit, FsStat, FsStatx, FsStatxTimestamp, Mode, Stat,
};

use crate::btree;
use crate::checksum::name_hash;
use crate::dir::{decode_dir_items, DirEntry as BtrfsDirEntry};
use crate::format::{self, BtrfsKey};
use crate::inode::InodeItem;
use crate::volume::BtrfsVolume;

/// Linux `STATX_BASIC_STATS` — the fields this driver populates.
const STATX_BASIC_STATS: u32 = 0x7ff;
/// Linux `STATX_BTIME`: `btrfs_getattr` reports the inode's `otime` as btime.
const STATX_BTIME: u32 = 0x800;

/// Legacy `_IOW(BTRFS_IOCTL_MAGIC, 14, struct btrfs_ioctl_vol_args)`.
pub(crate) const BTRFS_IOC_SUBVOL_CREATE: u32 = 0x5000_940e;
/// `_IOW(BTRFS_IOCTL_MAGIC, 24, struct btrfs_ioctl_vol_args_v2)`.
pub(crate) const BTRFS_IOC_SUBVOL_CREATE_V2: u32 = 0x5000_9418;
/// Legacy `_IOW(BTRFS_IOCTL_MAGIC, 15, struct btrfs_ioctl_vol_args)`.
pub(crate) const BTRFS_IOC_SNAP_DESTROY: u32 = 0x5000_940f;
/// `_IOW(BTRFS_IOCTL_MAGIC, 63, struct btrfs_ioctl_vol_args_v2)`.
pub(crate) const BTRFS_IOC_SNAP_DESTROY_V2: u32 = 0x5000_943f;
/// `_IOR(BTRFS_IOCTL_MAGIC, 25, __u64)` from Linux `uapi/linux/btrfs.h`.
pub(crate) const BTRFS_IOC_SUBVOL_GETFLAGS: u32 = 0x8008_9419;
/// `_IOW(BTRFS_IOCTL_MAGIC, 26, __u64)` from Linux `uapi/linux/btrfs.h`.
pub(crate) const BTRFS_IOC_SUBVOL_SETFLAGS: u32 = 0x4008_941a;
/// Full- and simple-qgroup administration ioctls from Linux `uapi/linux/btrfs.h`.
pub(crate) const BTRFS_IOC_QUOTA_CTL: u32 = 0xc010_9428;
pub(crate) const BTRFS_IOC_QGROUP_ASSIGN: u32 = 0x4018_9429;
pub(crate) const BTRFS_IOC_QGROUP_CREATE: u32 = 0x4010_942a;
// This historical UAPI is encoded `_IOR` even though the structure is input.
pub(crate) const BTRFS_IOC_QGROUP_LIMIT: u32 = 0x8030_942b;
pub(crate) const BTRFS_IOC_QUOTA_RESCAN: u32 = 0x4040_942c;
pub(crate) const BTRFS_IOC_QUOTA_RESCAN_STATUS: u32 = 0x8040_942d;
pub(crate) const BTRFS_IOC_QUOTA_RESCAN_WAIT: u32 = 0x0000_942e;
/// Userspace flag returned by `BTRFS_IOC_SUBVOL_GETFLAGS`. This is distinct
/// from bit 0 in the on-disk `btrfs_root_item.flags` field.
pub(crate) const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
/// Attach the new subvolume's level-0 qgroup to inherited parent qgroups.
pub(crate) const BTRFS_SUBVOL_QGROUP_INHERIT: u64 = 1 << 2;

fn parse_qgroup_inherit(
    input: &[u8],
    flags: u64,
) -> Result<Option<crate::write::QgroupInherit>, FsError> {
    if flags & BTRFS_SUBVOL_QGROUP_INHERIT == 0 {
        if input.len() != 4096 {
            return Err(FsError::InvalidData);
        }
        return Ok(None);
    }
    let size = usize::try_from(u64::from_ne_bytes(
        input[24..32].try_into().map_err(|_| FsError::InvalidData)?,
    ))
    .map_err(|_| FsError::InvalidData)?;
    if !(72..=4096).contains(&size) || input.len() != 4096 + size {
        return Err(FsError::InvalidData);
    }
    let inherit = &input[4096..];
    let inherit_flags = u64::from_ne_bytes(inherit[0..8].try_into().unwrap());
    let count = usize::try_from(u64::from_ne_bytes(inherit[8..16].try_into().unwrap()))
        .map_err(|_| FsError::InvalidData)?;
    let ref_copies = u64::from_ne_bytes(inherit[16..24].try_into().unwrap());
    let excl_copies = u64::from_ne_bytes(inherit[24..32].try_into().unwrap());
    if inherit_flags & !1 != 0
        || ref_copies != 0
        || excl_copies != 0
        || size != 72usize.saturating_add(count.saturating_mul(8))
    {
        return Err(FsError::InvalidData);
    }
    let mut limit = [0u64; 5];
    for (idx, value) in limit.iter_mut().enumerate() {
        let off = 32 + idx * 8;
        *value = u64::from_ne_bytes(inherit[off..off + 8].try_into().unwrap());
    }
    if limit[0] & !0x3f != 0 {
        return Err(FsError::InvalidData);
    }
    let mut parents = Vec::with_capacity(count);
    for idx in 0..count {
        let off = 72 + idx * 8;
        parents.push(u64::from_ne_bytes(
            inherit[off..off + 8].try_into().unwrap(),
        ));
    }
    Ok(Some(crate::write::QgroupInherit {
        flags: inherit_flags,
        parents,
        limit,
    }))
}

/// Convert a packed userspace `dev_t` (as `mknod` delivers it) to the raw kernel
/// `dev_t` btrfs stores on disk — Linux `new_decode_dev` followed by `MKDEV`
/// (`(major << 20) | minor`). Keeps NARF-created device nodes readable by a real
/// kernel with the right major/minor.
fn glibc_to_kernel_dev(dev: u64) -> u64 {
    let major = (dev >> 8) & 0xfff;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xf_ff00);
    (major << 20) | (minor & 0xf_ffff)
}

/// Run an allocating mutation `$op` (a `Result`-valued `.await` expression); if it
/// fails with `NoSpace`, grow the filesystem by one chunk and retry.
/// `grow_add_chunk` returns `NoSpace` once the device is truly full, which then
/// propagates. Bounded so a persistently-failing op can't loop forever.
macro_rules! autogrow {
    ($vol:expr, $op:expr) => {{
        if !$vol.admits_writes() {
            return Err(FsError::ReadOnly);
        }
        // One mutating operation at a time, from its first read to staging.
        let _op = $vol.op_lock().lock().await;
        if !$vol.admits_writes() {
            return Err(FsError::ReadOnly);
        }
        $vol.reap_orphans().await?;
        let mut r = $op;
        let mut tries = 0u32;
        // Under `narf.disks=root-rw` the whole-tree-repacking growth path is
        // never used on a production root; a chunk is allocated the way
        // Linux allocates one instead (`write::root_rw_grow`, path COW only),
        // of the type that ran short, and a device with no room left is
        // ENOSPC.
        let root_rw = crate::rw_gate::active_profile() == crate::rw_gate::Profile::RootRw;
        while tries < 4 && matches!(r, Err(FsError::NoSpace)) {
            if root_rw {
                crate::write::root_rw_grow(&$vol).await?;
            } else {
                crate::write::grow_add_chunk(&$vol).await?;
            }
            tries += 1;
            r = $op;
        }
        r
    }};
}

/// Run a filesystem-wide administrative mutation `$op` that does not go
/// through [`autogrow!`]: gated by [`BtrfsVolume::admits_admin_writes`] before
/// and after taking the operation lock, exactly as `autogrow!` gates ordinary
/// writes, then serialised with them.
macro_rules! admin_op {
    ($vol:expr, $op:expr) => {{
        if !$vol.admits_admin_writes() {
            return Err(FsError::ReadOnly);
        }
        let _op = $vol.op_lock().lock().await;
        if !$vol.admits_admin_writes() {
            return Err(FsError::ReadOnly);
        }
        $op
    }};
}

/// Run the lock-free read `$body` against `$root`, the root `$node` samples,
/// and retry it from the tree's current root if it failed with `InvalidData`
/// while the root moved underneath it: a block of the sampled tree was freed
/// and reused (Linux `verify_parent_transid` and a fresh search). A failure
/// against an unchanged root is real corruption and is returned.
macro_rules! with_root_retry {
    ($node:expr, $vol:expr, |$root:ident| $body:expr) => {{
        // The sampled root stays pinned against reallocation while the body
        // walks from it (`BtrfsVolume::pin_live_root`).
        let mut _pin = $node.pin_root(&$vol);
        let mut $root = match &_pin {
            Some(pin) => pin.root(),
            None => $node.root(&$vol),
        };
        let mut tries = 0u32;
        loop {
            match $body {
                Err(FsError::InvalidData) if tries < 4 => {
                    let next = $node.pin_root(&$vol);
                    let fresh = match &next {
                        Some(pin) => pin.root(),
                        None => $node.fresh_root(&$vol).await?,
                    };
                    if fresh == $root {
                        break Err(FsError::InvalidData);
                    }
                    _pin = next;
                    $root = fresh;
                    tries += 1;
                }
                other => break other,
            }
        }
    }};
}

/// The synchronous VFS lookups can only say "absent", so an I/O or
/// consistency error there would surface as a silent ENOENT. Log those
/// (not plain misses), a bounded number of times.
fn note_lookup_error(name: &str, error: FsError) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static LOGGED: AtomicU32 = AtomicU32::new(0);
    if matches!(error, FsError::NotFound) || LOGGED.fetch_add(1, Ordering::Relaxed) >= 32 {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "btrfs: lookup of {name:?} failed ({error:?}); reported as absent"
    );
}

/// One btrfs inode presented to the VFS. A node records the fs tree it lives in:
/// `None` is the mounted subvolume (resolved dynamically from the live volume,
/// so a COW write's new root is observed), `Some(root)` pins a nested
/// subvolume's fs-tree root reached by descending a `ROOT_ITEM` directory entry.
#[derive(Debug)]
pub struct BtrfsNode<B: BlockDevice + 'static> {
    vol: Weak<BtrfsVolume<B>>,
    tree_root: Option<u64>,
    tree_id: Option<u64>,
    ino: u64,
    /// Shared inode metadata and lifetime, held by every lookup and mapping.
    anchor: Arc<crate::volume::MmapAnchor>,
}

impl<B: BlockDevice + 'static> BtrfsNode<B> {
    pub fn new(
        vol: Weak<BtrfsVolume<B>>,
        tree_root: Option<u64>,
        ino: u64,
        inode: InodeItem,
    ) -> Arc<Self> {
        let volume = vol.upgrade().expect("node constructed from a live volume");
        let anchor = volume.mmap_anchor(volume.fs_tree_id(), ino, inode);
        Arc::new(BtrfsNode {
            vol,
            tree_root,
            tree_id: None,
            ino,
            anchor,
        })
    }

    fn new_in_subvolume(
        vol: Weak<BtrfsVolume<B>>,
        tree_root: u64,
        tree_id: u64,
        ino: u64,
        inode: InodeItem,
    ) -> Arc<Self> {
        let volume = vol.upgrade().expect("node constructed from a live volume");
        let anchor = volume.mmap_anchor(tree_id, ino, inode);
        Arc::new(BtrfsNode {
            vol,
            tree_root: Some(tree_root),
            tree_id: Some(tree_id),
            ino,
            anchor,
        })
    }

    /// Snapshot of the cached inode.
    fn inode(&self) -> InodeItem {
        *self.anchor.inode.lock()
    }

    fn cache_inode(&self, inode: InodeItem) {
        *self.anchor.inode.lock() = inode;
        self.anchor
            .live_size
            .store(inode.size, core::sync::atomic::Ordering::Release);
    }

    async fn refresh_inode(&self) -> Result<InodeItem, FsError> {
        let vol = self.volume()?;
        let _op = vol.op_lock().lock().await;
        let inode = with_root_retry!(self, vol, |root| vol.load_inode_in(root, self.ino).await)?;
        self.cache_inode(inode);
        Ok(inode)
    }

    /// Change mode / owners / timestamps of this inode and refresh the cache
    /// (`btrfs_setattr` -> `btrfs_update_inode`).
    async fn change_attrs(&self, change: crate::write::AttrChange) -> Result<(), FsError> {
        if self.tree_root.is_some() {
            return Err(FsError::ReadOnly);
        }
        let vol = self.volume()?;
        autogrow!(
            vol,
            async {
                let updated = crate::write::set_inode_attrs(&vol, self.ino, change).await?;
                self.cache_inode(updated);
                Ok(())
            }
            .await
        )
    }

    fn volume(&self) -> Result<Arc<BtrfsVolume<B>>, FsError> {
        self.vol.upgrade().ok_or(FsError::NotFound)
    }

    /// The `(fs tree, inode)` key this node's content generation is
    /// tracked under in the shared core — the same key
    /// `mmap_backing_identity` anchors identity under, resolved the
    /// same way (the node's own tree for a pinned subvolume, else the
    /// volume view's fs tree).
    fn generation_key(&self, vol: &BtrfsVolume<B>) -> (u64, u64) {
        (self.tree_id.unwrap_or_else(|| vol.fs_tree_id()), self.ino)
    }

    /// Record a content mutation of this inode (see
    /// `VolCore::bump_cache_generation`).
    fn bump_cache_generation(&self, vol: &BtrfsVolume<B>) {
        let (tree, ino) = self.generation_key(vol);
        vol.bump_cache_generation(tree, ino);
    }

    /// Exact on-disk atime/ctime/mtime for the stat path. The ns→cycles→ns
    /// round trip behind [`Stat::mtime_cycles`] is not exact, so `stat` and
    /// `statx` take `mtime_ns` from here; fontconfig compares a font
    /// directory's `st_mtim` to the nanosecond.
    fn attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::InodeAttrs {
            atime_ns: self.inode().atime_ns(),
            ctime_ns: self.inode().ctime_ns(),
            mtime_ns: self.inode().mtime_ns(),
            ..Default::default()
        }
    }

    fn ioctl_async_impl<'a>(
        &'a self,
        cmd: u32,
        input: &'a [u8],
        out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        Box::pin(async move {
            match cmd {
                BTRFS_IOC_SUBVOL_GETFLAGS if out_size != core::mem::size_of::<u64>() => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_SUBVOL_SETFLAGS
                    if out_size != 0 || input.len() != core::mem::size_of::<u64>() =>
                {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_SUBVOL_CREATE if out_size != 0 || input.len() != 4096 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_SUBVOL_CREATE_V2 if out_size != 0 || input.len() < 4096 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_SNAP_DESTROY | BTRFS_IOC_SNAP_DESTROY_V2
                    if out_size != 0 || input.len() != 4096 =>
                {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QUOTA_CTL if input.len() != 16 || out_size != 16 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QGROUP_ASSIGN if input.len() != 24 || out_size != 0 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QGROUP_CREATE if input.len() != 16 || out_size != 0 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QGROUP_LIMIT if input.len() != 48 || out_size != 48 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QUOTA_RESCAN if input.len() != 64 || out_size != 0 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QUOTA_RESCAN_STATUS if !input.is_empty() || out_size != 64 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_QUOTA_RESCAN_WAIT if !input.is_empty() || out_size != 0 => {
                    return Err(FsError::InvalidData);
                }
                BTRFS_IOC_SUBVOL_GETFLAGS
                | BTRFS_IOC_SUBVOL_SETFLAGS
                | BTRFS_IOC_SUBVOL_CREATE
                | BTRFS_IOC_SUBVOL_CREATE_V2
                | BTRFS_IOC_SNAP_DESTROY
                | BTRFS_IOC_SNAP_DESTROY_V2
                | BTRFS_IOC_QUOTA_CTL
                | BTRFS_IOC_QGROUP_ASSIGN
                | BTRFS_IOC_QGROUP_CREATE
                | BTRFS_IOC_QGROUP_LIMIT
                | BTRFS_IOC_QUOTA_RESCAN
                | BTRFS_IOC_QUOTA_RESCAN_STATUS
                | BTRFS_IOC_QUOTA_RESCAN_WAIT => {}
                _ => return Err(FsError::Unsupported),
            }
            let vol = self.volume()?;
            match cmd {
                BTRFS_IOC_SUBVOL_GETFLAGS => {
                    // Flags operate only on an explicitly mounted subvolume root.
                    if self.tree_root.is_some()
                        || self.ino != format::FIRST_FREE_OBJECTID
                        || self.inode().file_type() != FileType::Dir
                    {
                        return Err(FsError::InvalidData);
                    }
                    let flags = if vol.fs_tree_flags() & format::ROOT_SUBVOL_RDONLY != 0 {
                        BTRFS_SUBVOL_RDONLY
                    } else {
                        0
                    };
                    Ok(FsIoctlReply {
                        result: 0,
                        output: flags.to_ne_bytes().to_vec(),
                    })
                }
                BTRFS_IOC_SUBVOL_SETFLAGS => {
                    if self.tree_root.is_some()
                        || self.ino != format::FIRST_FREE_OBJECTID
                        || self.inode().file_type() != FileType::Dir
                    {
                        return Err(FsError::InvalidData);
                    }
                    let flags =
                        u64::from_ne_bytes(input.try_into().map_err(|_| FsError::InvalidData)?);
                    if flags & !BTRFS_SUBVOL_RDONLY != 0 {
                        return Err(FsError::InvalidData);
                    }
                    let mut disk_flags = vol.fs_tree_flags();
                    if flags & BTRFS_SUBVOL_RDONLY != 0 {
                        disk_flags |= format::ROOT_SUBVOL_RDONLY;
                    } else {
                        disk_flags &= !format::ROOT_SUBVOL_RDONLY;
                    }
                    // Clearing RDONLY is the point of this ioctl, so the
                    // subvolume's own flag cannot gate it; everything else
                    // that makes a filesystem unwritable does.
                    admin_op!(vol, crate::write::set_subvol_flags(&vol, disk_flags).await)?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_SUBVOL_CREATE | BTRFS_IOC_SUBVOL_CREATE_V2 => {
                    // Creation is relative to the directory fd, but only a
                    // directory in the explicitly mounted live tree is mutable.
                    if self.tree_root.is_some() || self.inode().file_type() != FileType::Dir {
                        return Err(FsError::ReadOnly);
                    }
                    let (name_offset, readonly, inherit) = if cmd == BTRFS_IOC_SUBVOL_CREATE_V2 {
                        let flags = u64::from_ne_bytes(
                            input[16..24].try_into().map_err(|_| FsError::InvalidData)?,
                        );
                        if flags & !(BTRFS_SUBVOL_RDONLY | BTRFS_SUBVOL_QGROUP_INHERIT) != 0 {
                            return Err(FsError::InvalidData);
                        }
                        (
                            56usize,
                            flags & BTRFS_SUBVOL_RDONLY != 0,
                            parse_qgroup_inherit(input, flags)?,
                        )
                    } else {
                        (8usize, false, None)
                    };
                    let raw_name = input.get(name_offset..4096).ok_or(FsError::InvalidData)?;
                    let end = raw_name
                        .iter()
                        .position(|&byte| byte == 0)
                        .ok_or(FsError::InvalidData)?;
                    let name =
                        core::str::from_utf8(&raw_name[..end]).map_err(|_| FsError::InvalidData)?;
                    let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
                    autogrow!(
                        vol,
                        crate::write::create_subvolume_with_qgroup(
                            &vol,
                            self.ino,
                            name,
                            readonly,
                            inherit.clone(),
                        )
                        .await
                    )?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_SNAP_DESTROY | BTRFS_IOC_SNAP_DESTROY_V2 => {
                    if self.tree_root.is_some() || self.inode().file_type() != FileType::Dir {
                        return Err(FsError::ReadOnly);
                    }
                    let (name, subvolid) = if cmd == BTRFS_IOC_SNAP_DESTROY_V2 {
                        let flags = u64::from_ne_bytes(
                            input[16..24].try_into().map_err(|_| FsError::InvalidData)?,
                        );
                        if flags & !(1 << 4) != 0 {
                            return Err(FsError::InvalidData);
                        }
                        if flags & (1 << 4) != 0 {
                            let id = u64::from_ne_bytes(
                                input[56..64].try_into().map_err(|_| FsError::InvalidData)?,
                            );
                            (None, Some(id))
                        } else {
                            (Some(parse_subvol_name(&input[56..])?), None)
                        }
                    } else {
                        (Some(parse_subvol_name(&input[8..])?), None)
                    };
                    let _path_mutation = match name.as_deref() {
                        Some(name) => narf_filesystem::begin_path_mutation(self, &[name]),
                        None => narf_filesystem::begin_path_mutation(self, &[]),
                    };
                    autogrow!(
                        vol,
                        crate::write::destroy_subvolume(&vol, self.ino, name.as_deref(), subvolid,)
                            .await
                    )?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_QUOTA_CTL => {
                    if self.tree_root.is_some() || self.inode().file_type() != FileType::Dir {
                        return Err(FsError::ReadOnly);
                    }
                    let command = u64::from_ne_bytes(input[0..8].try_into().unwrap());
                    match command {
                        1 => autogrow!(vol, crate::write::quota_enable(&vol).await)?,
                        2 => admin_op!(vol, crate::write::quota_disable(&vol).await)?,
                        4 => autogrow!(vol, crate::write::quota_enable_simple(&vol).await)?,
                        _ => return Err(FsError::InvalidData),
                    }
                    let status = match crate::write::quota_status(&vol).await {
                        Ok((flags, _)) => flags,
                        Err(FsError::NotFound) if command == 2 => 0,
                        Err(err) => return Err(err),
                    };
                    let mut output = alloc::vec![0u8; 16];
                    output[0..8].copy_from_slice(&command.to_ne_bytes());
                    output[8..16].copy_from_slice(&status.to_ne_bytes());
                    Ok(FsIoctlReply { result: 0, output })
                }
                BTRFS_IOC_QGROUP_CREATE => {
                    let create = u64::from_ne_bytes(input[0..8].try_into().unwrap());
                    let id = u64::from_ne_bytes(input[8..16].try_into().unwrap());
                    match create {
                        0 => admin_op!(vol, crate::write::qgroup_destroy_admin(&vol, id).await)?,
                        1 => autogrow!(vol, crate::write::qgroup_create_admin(&vol, id).await)?,
                        _ => return Err(FsError::InvalidData),
                    }
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_QGROUP_ASSIGN => {
                    let assign = u64::from_ne_bytes(input[0..8].try_into().unwrap());
                    if assign > 1 {
                        return Err(FsError::InvalidData);
                    }
                    let src = u64::from_ne_bytes(input[8..16].try_into().unwrap());
                    let dst = u64::from_ne_bytes(input[16..24].try_into().unwrap());
                    autogrow!(
                        vol,
                        crate::write::qgroup_assign_admin(&vol, assign != 0, src, dst).await
                    )?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_QGROUP_LIMIT => {
                    let id = u64::from_ne_bytes(input[0..8].try_into().unwrap());
                    let mut limit = [0u64; 5];
                    for (idx, value) in limit.iter_mut().enumerate() {
                        let off = 8 + idx * 8;
                        *value = u64::from_ne_bytes(input[off..off + 8].try_into().unwrap());
                    }
                    autogrow!(vol, crate::write::qgroup_limit_admin(&vol, id, limit).await)?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_QUOTA_RESCAN => {
                    if input.iter().any(|byte| *byte != 0) {
                        return Err(FsError::InvalidData);
                    }
                    autogrow!(vol, crate::write::quota_rescan(&vol).await)?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_QUOTA_RESCAN_STATUS => {
                    let (flags, progress) = match crate::write::quota_status(&vol).await {
                        Ok(status) => status,
                        Err(FsError::NotFound) => (0, 0),
                        Err(err) => return Err(err),
                    };
                    let mut output = alloc::vec![0u8; 64];
                    // NARF rescans synchronously, so bit 0 (RESCAN) is clear
                    // once this call can observe the committed status.
                    output[0..8].copy_from_slice(&(flags & 2).to_ne_bytes());
                    output[8..16].copy_from_slice(&progress.to_ne_bytes());
                    Ok(FsIoctlReply { result: 0, output })
                }
                BTRFS_IOC_QUOTA_RESCAN_WAIT => {
                    // Rescans are synchronous; all prior accounting is already
                    // durable when the ioctl returns.
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                _ => unreachable!(),
            }
        })
    }

    fn snapshot_impl<'a>(
        &'a self,
        source: Arc<dyn DirOps>,
        name: &'a str,
        readonly: bool,
        inherit: Option<crate::write::QgroupInherit>,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() || self.inode().file_type() != FileType::Dir {
                return Err(FsError::ReadOnly);
            }
            // NARF's O(1) snapshot shares the source's ROOT block between two
            // root items. Linux never shares a root block (it copies the root
            // and adds a reference to each child, `btrfs_copy_root`) and never
            // treats one as shared (`btrfs_block_can_be_shared`), so a Linux
            // kernel writing either subvolume afterwards would free blocks the
            // other still uses. Never create that shape on a production root:
            // snapper/snap-pac then fail cleanly (EOPNOTSUPP, nothing
            // created) and pacman carries on.
            if !crate::write::SNAPSHOTS_LINUX_SHAPED
                && crate::rw_gate::active_profile() == crate::rw_gate::Profile::RootRw
            {
                return Err(FsError::Unsupported);
            }
            let source = source
                .as_any()
                .and_then(|a| a.downcast_ref::<BtrfsNode<B>>())
                .ok_or(FsError::CrossDevice)?;
            if source.ino != format::FIRST_FREE_OBJECTID
                || source.inode().file_type() != FileType::Dir
            {
                return Err(FsError::InvalidData);
            }
            let vol = self.volume()?;
            let source_vol = source.volume()?;
            if !Arc::ptr_eq(&vol, &source_vol) {
                return Err(FsError::CrossDevice);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let (source_root, source_id) = match (source.tree_root, source.tree_id) {
                (Some(root), Some(id)) => (root, id),
                (None, None) => (vol.fs_tree_root().0, vol.fs_tree_id()),
                _ => return Err(FsError::InvalidData),
            };
            autogrow!(
                vol,
                crate::write::create_snapshot_with_qgroup(
                    &vol,
                    self.ino,
                    source_root,
                    source_id,
                    name,
                    readonly,
                    inherit.clone(),
                )
                .await
            )?;
            Ok(())
        })
    }

    /// The fs-tree root this node reads from: a pinned subvolume root, or the
    /// live default fs-tree root.
    fn root(&self, vol: &BtrfsVolume<B>) -> u64 {
        self.tree_root.unwrap_or_else(|| vol.fs_tree_root().0)
    }

    /// The live root this node reads from, pinned against reallocation
    /// while the pin lives; `None` for a fixed (`tree_root`) root or a
    /// subvolume no mount tracks, which are read unpinned.
    fn pin_root(&self, vol: &BtrfsVolume<B>) -> Option<crate::volume::RootPin<B>> {
        if self.tree_root.is_some() {
            return None;
        }
        vol.pin_live_root(self.tree_id)
    }

    /// The tree's root as of now, for a read that found a block which no
    /// longer belongs to the root it sampled (see [`btree::verify_child`]).
    async fn fresh_root(&self, vol: &BtrfsVolume<B>) -> Result<u64, FsError> {
        match self.tree_id {
            None => Ok(vol.fs_tree_root().0),
            Some(id) => match vol.live_subvol_root(id) {
                Some(root) => Ok(root),
                None => {
                    let (root_tree, _) = vol.root_tree_root();
                    Ok(crate::roots::find_root(vol, root_tree, id).await?.0)
                }
            },
        }
    }

    /// Resolve a name to its directory entry via the CRC32C-hashed `DIR_ITEM`.
    async fn find_child(&self, name: &str) -> Result<BtrfsDirEntry, FsError> {
        let vol = self.volume()?;
        let key = BtrfsKey::new(
            self.ino,
            format::DIR_ITEM_KEY,
            u64::from(name_hash(name.as_bytes())),
        );
        let body = with_root_retry!(self, vol, |root| btree::find_item(&*vol, root, &key).await)?
            .ok_or(FsError::NotFound)?;
        decode_dir_items(&body)?
            .into_iter()
            .find(|e| e.name == name)
            .ok_or(FsError::NotFound)
    }

    /// Load the node named by `entry`. An `INODE_ITEM` location is an inode in
    /// this same tree; a `ROOT_ITEM` location is a nested subvolume — resolve its
    /// tree in the root tree and enter it at its root directory (inode 256).
    async fn load_child(
        &self,
        vol: &Arc<BtrfsVolume<B>>,
        entry: &BtrfsDirEntry,
    ) -> Result<Arc<BtrfsNode<B>>, FsError> {
        match entry.location.item_type {
            format::INODE_ITEM_KEY => {
                let ino = entry.child_objectid();
                let child = with_root_retry!(self, vol, |root| vol.load_inode_in(root, ino).await)?;
                // Inherit this node's tree (default or a pinned subvolume).
                match (self.tree_root, self.tree_id) {
                    (Some(root), Some(id)) => Ok(BtrfsNode::new_in_subvolume(
                        vol.self_weak.clone(),
                        root,
                        id,
                        ino,
                        child,
                    )),
                    (None, None) => Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, child)),
                    _ => Err(FsError::InvalidData),
                }
            }
            format::ROOT_ITEM_KEY => {
                let (root_tree, _) = vol.root_tree_root();
                let (subvol_root, _lvl) =
                    crate::roots::find_root(&**vol, root_tree, entry.location.objectid).await?;
                let ino = format::FIRST_FREE_OBJECTID;
                let child = vol.load_inode_in(subvol_root, ino).await?;
                Ok(BtrfsNode::new_in_subvolume(
                    vol.self_weak.clone(),
                    subvol_root,
                    entry.location.objectid,
                    ino,
                    child,
                ))
            }
            _ => Err(FsError::NotFound),
        }
    }
}

fn parse_subvol_name(raw: &[u8]) -> Result<String, FsError> {
    let end = raw
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(FsError::InvalidData)?;
    let name = core::str::from_utf8(&raw[..end]).map_err(|_| FsError::InvalidData)?;
    if name.is_empty() || name.len() > 255 || name.contains('/') {
        return Err(FsError::InvalidData);
    }
    Ok(name.into())
}

impl<B: BlockDevice + 'static> FileOps for BtrfsNode<B> {
    /// Stored file data: no `.poll`, so `epoll_ctl` refuses it. Decided per
    /// inode — a FIFO or device node living in this filesystem dispatches
    /// elsewhere on open and stays pollable. See `fs_inode_can_poll`.
    fn can_poll(&self) -> bool {
        narf_filesystem::fs_inode_can_poll(self.stat().mode.file_type)
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let vol = self.volume()?;
            let _op = vol.op_lock().lock().await;
            with_root_retry!(self, vol, |root| {
                // The size is re-read from the tree: this node's cached inode
                // predates any write made through it (or through another open
                // file of the same inode).
                match vol.load_inode_in(root, self.ino).await {
                    Ok(inode) => {
                        self.cache_inode(inode);
                        crate::extent::read_file(&vol, root, self.ino, inode.size, offset, buf)
                            .await
                    }
                    Err(error) => Err(error),
                }
            })
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // The mounted subvolume is writable; a pinned child-subvolume root
            // would need its tree id as well as its current root address. The
            // COW write path itself
            // (`write::cow_write_file`) handles overwrite / partial / append /
            // grow of a single-regular-extent file and rejects the rest.
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            // Bump before the bytes move: a partial write that ends
            // in an error must still invalidate retained cache pages
            // (the `mmap_cache_generation` contract; the minix rule).
            self.bump_cache_generation(&vol);
            autogrow!(
                vol,
                async {
                    let result =
                        crate::write::cow_write_file(&vol, self.ino, &self.inode(), offset, buf)
                            .await;
                    self.cache_inode(vol.load_inode(self.ino).await?);
                    result
                }
                .await
            )
        })
    }

    /// `ftruncate`/`O_TRUNC` (`btrfs_setattr` with `ATTR_SIZE`).
    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            if !self.inode().is_regular() {
                return Err(FsError::Unsupported);
            }
            let vol = self.volume()?;
            // Bump before the length moves (see `write`).
            self.bump_cache_generation(&vol);
            let old_size = self
                .anchor
                .live_size
                .load(core::sync::atomic::Ordering::Relaxed);
            if len < old_size {
                // Publish the new EOF, then revoke every installed PTE
                // past it before the extents are retired — the ordering
                // ext2's truncate uses. Without the revoke, an
                // already-mapped page keeps serving its retired extent
                // instead of faulting SIGBUS.
                self.anchor
                    .live_size
                    .store(len, core::sync::atomic::Ordering::Relaxed);
                if let Err(error) = narf_filesystem::unmap_mapping_range(self, len) {
                    self.refresh_inode().await?;
                    return Err(error);
                }
            }
            autogrow!(
                vol,
                async {
                    let result = crate::write::truncate_file(&vol, self.ino, len).await;
                    self.cache_inode(vol.load_inode(self.ino).await?);
                    result
                }
                .await
            )
        })
    }

    /// `fallocate(2)` (`btrfs_fallocate`).
    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            if !self.inode().is_regular() {
                return Err(FsError::Unsupported);
            }
            let vol = self.volume()?;
            // Bump before the range moves: fallocate is staged (a
            // zero-range can commit before the preallocation stage
            // fails), so a fallocate that ends in an error may still
            // have changed bytes or length.
            self.bump_cache_generation(&vol);
            autogrow!(
                vol,
                async {
                    let result =
                        crate::write::fallocate_file(&vol, self.ino, mode, offset, len).await;
                    self.cache_inode(vol.load_inode(self.ino).await?);
                    result
                }
                .await
            )?;
            if mode & (crate::write::FALLOC_FL_PUNCH_HOLE | crate::write::FALLOC_FL_ZERO_RANGE) != 0
            {
                // The range's extents were deallocated or converted to
                // unwritten: revoke installed PTEs from its first page, or
                // a mapped page keeps serving the pre-punch bytes. A fault
                // after this point reads the new (holed/zeroed) state.
                narf_filesystem::unmap_mapping_range(
                    self,
                    (offset / narf_filesystem::PAGE_SIZE as u64)
                        * narf_filesystem::PAGE_SIZE as u64,
                )?;
            }
            Ok(())
        })
    }

    /// `fsync` must leave every write that has already returned durable on
    /// disk. It delegates that to [`BtrfsVolume::sync_to_disk`], which is the
    /// single place the requirement is implemented — it commits the open
    /// batch and then writes the staged superblock, which together are what
    /// "already returned" means once writes are batched.
    ///
    /// (The tree-log is only used to *replay* a crashed volume's log on mount,
    /// not to defer writes, so it plays no part here.)
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move { self.volume()?.sync_to_disk_exclusive().await })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self
                .anchor
                .live_size
                .load(core::sync::atomic::Ordering::Relaxed),
            blocks: self
                .anchor
                .live_size
                .load(core::sync::atomic::Ordering::Relaxed)
                .div_ceil(512),
            mode: Mode {
                file_type: self.inode().file_type(),
                perms: self.inode().perms() & 0o777,
            },
            // The on-disk `btrfs_timespec`, not 0 (every btrfs file claimed
            // 1970). The exact value travels in `InodeAttrs::mtime_ns`.
            mtime_cycles: narf_time::ns_to_cycles(self.inode().mtime_ns()),
        }
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            self.refresh_inode().await?;
            Ok(self.stat())
        })
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs()
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    /// One identity per inode, not per open: two opens of a journal file
    /// (journald writing, `journalctl` reading) must map the same
    /// `MAP_SHARED` pages, as they share one page cache on Linux.
    fn mmap_backing_identity(&self) -> usize {
        Arc::as_ptr(&self.anchor) as *const () as usize
    }

    /// Generic-fallback mmap opt-in for regular files. The mutation
    /// surface is closed (issue #680's enumeration): bytes or length
    /// change only through `write`, `truncate` and `fallocate` on a
    /// node of this volume's trees — each bumps before it mutates —
    /// through the write engine when an inode is destroyed (a final
    /// `unlink`, a rename whose destination is destroyed, both bump
    /// there), or at `create`, which bumps the new inode's key
    /// because inode numbers are issued max+1 and a freed number is
    /// reissued. Snapshots and subvolume creation mint a new tree
    /// (no entries under it; a reissued tree id had its entries
    /// pruned at destruction), and COW guarantees a write never
    /// mutates a shared extent in place, so no path changes one
    /// file's bytes under another file's key. Every node of one
    /// inode reports the same value, so a mutation through any one
    /// open invalidates pages retained through any other.
    /// Non-regular files stay on the conservative `None` behaviour.
    fn mmap_cache_generation(&self) -> Option<u64> {
        if !self.inode().is_regular() {
            return None;
        }
        let vol = self.volume().ok()?;
        let (tree, ino) = self.generation_key(&vol);
        Some(vol.cache_generation(tree, ino))
    }

    fn owners(&self) -> (u32, u32) {
        let inode = self.inode();
        (inode.uid, inode.gid)
    }

    /// `chown`/`fchown` (`btrfs_setattr` with `ATTR_UID|ATTR_GID`): a
    /// non-directory loses `S_ISUID`, and `S_ISGID` when group-executable
    /// (`should_remove_suid`); ctime moves.
    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(self.change_attrs(crate::write::AttrChange {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        }))
    }

    /// `chmod`/`fchmod`: the permission and special bits; the file type in
    /// `S_IFMT` never changes. ctime moves.
    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(self.change_attrs(crate::write::AttrChange {
            perms: Some(perms),
            ..Default::default()
        }))
    }

    /// `utimensat`/`futimens` (`None` = `UTIME_OMIT`). ctime moves.
    fn set_times_async<'a>(
        &'a self,
        atime_ns: Option<u64>,
        mtime_ns: Option<u64>,
    ) -> FsFuture<'a, ()> {
        Box::pin(self.change_attrs(crate::write::AttrChange {
            atime_ns,
            mtime_ns,
            ..Default::default()
        }))
    }

    /// Synchronous callers (overlayfs copy-up) cannot await: drive the
    /// update by spinning, which is safe from inside an executor poll where
    /// `block_on` is not. The update completes without waiting unless
    /// another CPU is mid-operation on this filesystem.
    fn set_times(&self, atime_ns: Option<u64>, mtime_ns: Option<u64>) -> Result<(), FsError> {
        narf_scheduler::block_on_spin(self.set_times_async(atime_ns, mtime_ns))
    }

    fn ioctl_async<'a>(
        &'a self,
        cmd: u32,
        _arg: u64,
        input: &'a [u8],
        out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        self.ioctl_async_impl(cmd, input, out_size)
    }

    fn statx_async<'a>(&'a self, _flags: u32, _mask: u32) -> FsFuture<'a, FsStatx> {
        Box::pin(async move {
            self.refresh_inode().await?;
            let ts = |seconds, nanoseconds| FsStatxTimestamp {
                seconds,
                nanoseconds,
            };
            let (rdev_major, rdev_minor) = self.inode().rdev_major_minor();
            Ok(FsStatx {
                mask: STATX_BASIC_STATS | STATX_BTIME,
                block_size: self.volume().map(|v| v.sectorsize()).unwrap_or(4096),
                nlink: self.inode().nlink,
                uid: self.inode().uid,
                gid: self.inode().gid,
                mode: (self.inode().mode & 0xffff) as u16,
                ino: self.ino,
                size: self
                    .anchor
                    .live_size
                    .load(core::sync::atomic::Ordering::Relaxed),
                blocks: self
                    .anchor
                    .live_size
                    .load(core::sync::atomic::Ordering::Relaxed)
                    .div_ceil(512),
                // `btrfs_getattr`: each timespec as stored, otime as btime.
                atime: ts(self.inode().atime_sec, self.inode().atime_nsec),
                btime: ts(self.inode().otime_sec, self.inode().otime_nsec),
                ctime: ts(self.inode().ctime_sec, self.inode().ctime_nsec),
                mtime: ts(self.inode().mtime_sec, self.inode().mtime_nsec),
                rdev_major,
                rdev_minor,
                ..FsStatx::default()
            })
        })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            autogrow!(
                vol,
                crate::write::set_xattr_item(&vol, self.ino, name, value, flags).await
            )
        })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            autogrow!(
                vol,
                crate::write::remove_xattr_item(&vol, self.ino, name).await
            )
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let vol = self.volume()?;
            // XATTR_ITEM shares the DIR_ITEM key scheme: keyed by the CRC32C
            // hash of the attribute name.
            let key = BtrfsKey::new(
                self.ino,
                format::XATTR_ITEM_KEY,
                u64::from(name_hash(name.as_bytes())),
            );
            let body = with_root_retry!(self, vol, |root| btree::find_item(&*vol, root, &key)
                .await)?
            .ok_or(FsError::NotFound)?;
            decode_dir_items(&body)?
                .into_iter()
                .find(|e| e.name == name)
                .map(|e| e.value)
                .ok_or(FsError::NotFound)
        })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let vol = self.volume()?;
            let items = with_root_retry!(self, vol, |root| {
                btree::collect_for(&*vol, root, self.ino, format::XATTR_ITEM_KEY).await
            })?;
            // Linux listxattr format: NUL-terminated names concatenated.
            let mut out = Vec::new();
            for (_key, body) in &items {
                for entry in decode_dir_items(body)? {
                    out.extend_from_slice(entry.name.as_bytes());
                    out.push(0);
                }
            }
            Ok(out)
        })
    }
}

impl<B: BlockDevice + 'static> DirOps for BtrfsNode<B> {
    fn ino(&self) -> u64 {
        self.ino
    }

    /// A directory's `fsync`/`syncfs` makes every returned write durable, as
    /// a file's does (see [`FileOps::fsync`] above): `sync(2)`, `syncfs` on a
    /// directory fd and `fsync` of a directory after a rename all land here.
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move { self.volume()?.sync_to_disk_exclusive().await })
    }

    /// `syncfs(2)`, and the generic `sync(2)` / pre-shutdown sync of every
    /// mounted filesystem: commit the running transaction, write the
    /// superblock (pre-flush, FUA primary, mirrors), then flush once more so
    /// the mirror copies are durable too before the caller powers off.
    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move { self.volume()?.sync_fs().await })
    }

    fn dcache_identity(&self) -> (usize, u64, u64) {
        (
            self.vol.as_ptr() as *const () as usize,
            self.tree_id.unwrap_or(0),
            self.ino,
        )
    }

    fn rcu_walkable(&self) -> bool {
        true
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Lookups are async (tree reads), but the synchronous VFS API must
        // still resolve real entries: OverlayFS consults its lower layers
        // through it (the session-writable root over a read-only btrfs root),
        // as do bind-mount source resolution and exec path checks. Same
        // bridge as ext's: re-entrancy-safe, never halts, and the block
        // device's completion still arrives.
        match narf_scheduler::block_on_spin(self.lookup_async(name)) {
            Ok(node) => Some(node),
            Err(error) => {
                note_lookup_error(name, error);
                None
            }
        }
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        // See `lookup`.
        match narf_scheduler::block_on_spin(self.lookup_dir_async(name)) {
            Ok(node) => Some(node),
            Err(error) => {
                note_lookup_error(name, error);
                None
            }
        }
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let vol = self.volume()?;
            let _op = vol.op_lock().lock().await;
            let entry = self.find_child(name).await?;
            let node = self.load_child(&vol, &entry).await?;
            Ok(node as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let vol = self.volume()?;
            let _op = vol.op_lock().lock().await;
            let entry = self.find_child(name).await?;
            let node = self.load_child(&vol, &entry).await?;
            if !node.inode().is_dir() {
                return Err(FsError::NotFound);
            }
            Ok(node as Arc<dyn DirOps>)
        })
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let vol = self.volume()?;
            // DIR_INDEX gives stable readdir order.
            let items = with_root_retry!(self, vol, |root| {
                btree::collect_for(&*vol, root, self.ino, format::DIR_INDEX_KEY).await
            })?;
            let mut out = Vec::new();
            for (_key, body) in items.iter().skip(cursor).take(max) {
                for entry in decode_dir_items(body)? {
                    out.push((entry.name.clone(), entry.file_type()));
                }
            }
            Ok(out)
        })
    }

    fn ioctl_async<'a>(
        &'a self,
        cmd: u32,
        _arg: u64,
        input: &'a [u8],
        out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        self.ioctl_async_impl(cmd, input, out_size)
    }

    fn snapshot_async<'a>(
        &'a self,
        source: Arc<dyn DirOps>,
        name: &'a str,
        readonly: bool,
    ) -> FsFuture<'a, ()> {
        self.snapshot_impl(source, name, readonly, None)
    }

    fn snapshot_with_quota_async<'a>(
        &'a self,
        source: Arc<dyn DirOps>,
        name: &'a str,
        readonly: bool,
        quota: FsQuotaInherit,
    ) -> FsFuture<'a, ()> {
        self.snapshot_impl(
            source,
            name,
            readonly,
            Some(crate::write::QgroupInherit {
                flags: quota.flags,
                parents: quota.parents,
                limit: quota.limit,
            }),
        )
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            // Only the mounted subvolume is writable (a pinned child subvolume
            // would need its tree id as well as its current root address).
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            autogrow!(
                vol,
                async {
                    let (ino, inode) = crate::write::create_file(&vol, self.ino, name).await?;
                    vol.bump_cache_generation(vol.fs_tree_id(), ino);
                    // Pin before releasing op_lock: another task may immediately
                    // unlink the new name, but this returned handle must survive.
                    Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
                }
                .await
            )
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            autogrow!(vol, crate::write::unlink_file(&vol, self.ino, name).await)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            autogrow!(
                vol,
                async {
                    let (ino, inode) = crate::write::mkdir_dir(&vol, self.ino, name).await?;
                    Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn DirOps>)
                }
                .await
            )
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            autogrow!(vol, crate::write::rmdir_dir(&vol, self.ino, name).await)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[old_name, new_name]);
            let vol = self.volume()?;
            autogrow!(
                vol,
                crate::write::rename_same_dir(&vol, self.ino, old_name, new_name).await
            )
        })
    }

    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if flags != 0 {
                return Err(FsError::Unsupported); // RENAME_NOREPLACE/EXCHANGE unhandled
            }
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            // The destination must be a btrfs directory on the *same* volume and
            // in the mounted subvolume — else it is a genuine cross-device move.
            let dest = new_dir
                .as_any()
                .and_then(|a| a.downcast_ref::<BtrfsNode<B>>())
                .ok_or(FsError::CrossDevice)?;
            if dest.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            let dest_vol = dest.volume()?;
            if !Arc::ptr_eq(&vol, &dest_vol) {
                return Err(FsError::CrossDevice);
            }
            let _source_path_mutation = narf_filesystem::begin_path_mutation(self, &[old_name]);
            let _destination_path_mutation =
                narf_filesystem::begin_path_mutation(dest, &[new_name]);
            if dest.ino == self.ino {
                autogrow!(
                    vol,
                    crate::write::rename_same_dir(&vol, self.ino, old_name, new_name).await
                )
            } else {
                autogrow!(
                    vol,
                    crate::write::rename_cross_dir(&vol, self.ino, dest.ino, old_name, new_name)
                        .await
                )
            }
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[new_name]);
            let vol = self.volume()?;
            autogrow!(
                vol,
                crate::write::link_node(&vol, self.ino, self.ino, old_name, new_name).await
            )
        })
    }

    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let dest = new_dir
                .as_any()
                .and_then(|a| a.downcast_ref::<BtrfsNode<B>>())
                .ok_or(FsError::CrossDevice)?;
            if dest.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            let dest_vol = dest.volume()?;
            if !Arc::ptr_eq(&vol, &dest_vol) {
                return Err(FsError::CrossDevice);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(dest, &[new_name]);
            autogrow!(
                vol,
                crate::write::link_node(&vol, self.ino, dest.ino, old_name, new_name).await
            )
        })
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            autogrow!(
                vol,
                async {
                    let (ino, inode) =
                        crate::write::symlink_node(&vol, self.ino, name, target).await?;
                    Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
                }
                .await
            )
        })
    }

    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            // Map the VFS file type to the mode's `S_IF*` bits and the on-disk
            // `BTRFS_FT_*` directory-entry type. Default permission bits are 0644
            // (udev sets the final mode afterwards).
            let (mode, ft) = match file_type {
                FileType::Special => (0o020644, format::FT_CHRDEV), // S_IFCHR
                FileType::Block => (0o060644, format::FT_BLKDEV),   // S_IFBLK
                FileType::Fifo => (0o010644, format::FT_FIFO),      // S_IFIFO
                _ => return Err(FsError::Unsupported),
            };
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            // `rdev` arrives as the packed userspace `dev_t`; btrfs stores the raw
            // kernel `dev_t`. FIFOs carry no device number.
            let kdev = if rdev == 0 {
                0
            } else {
                glibc_to_kernel_dev(rdev)
            };
            let vol = self.volume()?;
            autogrow!(
                vol,
                async {
                    let (ino, inode) =
                        crate::write::mknod_node(&vol, self.ino, name, mode, ft, kdev).await?;
                    Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
                }
                .await
            )
        })
    }

    fn create_socket<'a>(&'a self, name: &'a str, perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let vol = self.volume()?;
            // S_IFSOCK | perms; no device number.
            let mode = 0o140000 | u32::from(perms & 0o7777);
            autogrow!(
                vol,
                async {
                    let (ino, inode) =
                        crate::write::mknod_node(&vol, self.ino, name, mode, format::FT_SOCK, 0)
                            .await?;
                    Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
                }
                .await
            )
        })
    }

    fn dir_mode(&self) -> u16 {
        self.inode().perms() & 0o777
    }

    fn dir_owners(&self) -> (u32, u32) {
        (self.inode().uid, self.inode().gid)
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs()
    }

    /// The directory inode's on-disk mtime. Without it every btrfs directory
    /// stat'd as the epoch, so fontconfig judged each font cache stale and
    /// rescanned every font on application start.
    fn dir_mtime_ns(&self) -> u64 {
        self.inode().mtime_ns()
    }
}

impl<B: BlockDevice + 'static> BtrfsVolume<B> {
    async fn reconfigure_impl(
        &self,
        sb_flags: u64,
        sb_mask: u64,
        options: &str,
    ) -> Result<(), FsError> {
        use narf_filesystem::sb_flags::RDONLY;
        let mut want_ro = (sb_mask & RDONLY != 0).then_some(sb_flags & RDONLY != 0);
        for option in options.split(',') {
            match option {
                "ro" => want_ro = Some(true),
                "rw" => want_ro = Some(false),
                _ => {}
            }
        }
        let rest: alloc::vec::Vec<&str> = options
            .split(',')
            .filter(|o| !o.is_empty() && *o != "ro" && *o != "rw")
            .collect();
        let mut parsed = crate::mount_opts::parse(&rest.join(","))?;
        match want_ro {
            Some(true) if !self.is_read_only() => {
                narf_filesystem::fs_registry::mount_wait(self.remount_read_only())?;
            }
            Some(false) if self.is_read_only() => {
                let this = self.self_weak.upgrade().ok_or(FsError::NotFound)?;
                narf_filesystem::fs_registry::mount_wait(this.ensure_sharing_checked())?;
                this.remount_read_write()?;
            }
            _ => {}
        }
        let current = self.mount_options();
        parsed.subvol = current.subvol;
        parsed.read_only = self.is_read_only();
        self.set_mount_options(parsed);
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FsInstance for BtrfsVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let inode = self.root_inode().expect("btrfs root inode cached at mount");
        // `None` = mounted subvolume, resolved dynamically so a COW write's new
        // fs-tree root is observed by subsequent reads.
        BtrfsNode::new(
            self.self_weak.clone(),
            None,
            format::FIRST_FREE_OBJECTID,
            inode,
        ) as Arc<dyn DirOps>
    }

    fn name(&self) -> &str {
        "btrfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move {
            let block_size = self.sectorsize();
            let bs = u64::from(block_size.max(1));
            let blocks = self.total_bytes() / bs;
            // `bytes_used` from the superblock is the allocated (data+metadata)
            // total — a reasonable df approximation for free space.
            let used = self.superblock().bytes_used / bs;
            let free = blocks.saturating_sub(used);
            Ok(FsStat {
                blocks,
                blocks_free: free,
                blocks_available: free,
                files: 0,
                files_free: 0,
                block_size,
                name_len: 255,
                fragment_size: block_size,
            })
        })
    }

    /// A volume the write-safety gate (or the disk policy) made read-only is
    /// read-only for every mount of it: the VFS then refuses writes with
    /// EROFS and reports `ro` in mountinfo.
    fn always_read_only(&self) -> bool {
        self.is_read_only()
    }

    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        self.reconfigure_sb(0, 0, options)
    }

    /// `mount -o remount` (Linux `btrfs_reconfigure`). `systemd-remount-fs`
    /// remounts `/` with its fstab options (`subvol=/@,compress=zstd:1`, ...)
    /// and `systemd-shutdown` remounts it `ro` before poweroff. Accept what a
    /// mount accepts; like Linux, `subvol=`/`subvolid=` cannot change on
    /// remount and are ignored, everything else replaces the recorded run-time
    /// options. `SB_RDONLY` flipping on (in `sb_flags`, or `ro` in the data)
    /// commits and makes the filesystem read-only (`btrfs_remount_ro`);
    /// flipping off makes it writable again (`btrfs_remount_rw`), refused
    /// with `ReadOnly` where a read-write mount would be (disk policy,
    /// write-safety gate, an aborted transaction).
    fn reconfigure_sb(&self, sb_flags: u64, sb_mask: u64, options: &str) -> Result<(), FsError> {
        narf_scheduler::block_on_spin(self.reconfigure_sb_async(sb_flags, sb_mask, options))
    }

    fn reconfigure_sb_async<'a>(
        &'a self,
        sb_flags: u64,
        sb_mask: u64,
        options: &'a str,
    ) -> narf_filesystem::FsFuture<'a, ()> {
        Box::pin(self.reconfigure_impl(sb_flags, sb_mask, options))
    }

    fn show_options(&self) -> alloc::string::String {
        let options = self.mount_options();
        let mut out = options.render();
        let id = self.mounted_subvol_id();
        out.push_str(&alloc::format!(",subvolid={id}"));
        if let Some(crate::volume::Subvol::Name(path)) = &options.subvol {
            out.push_str(&alloc::format!(",subvol=/{path}"));
        } else if id == crate::format::FS_TREE_OBJECTID {
            out.push_str(",subvol=/");
        }
        out
    }
}

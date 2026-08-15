//! VFS nodes: `BtrfsNode` implements both `FileOps` and `DirOps` (a btrfs inode
//! is one or the other by mode), and `BtrfsVolume` implements `FsInstance`.
//!
//! Like the squashfs driver, all real work is async: the sync `lookup`/`iter`
//! surfaces return empty and the VFS drives `*_async` instead.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

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
/// Full-qgroup administration ioctls from Linux `uapi/linux/btrfs.h`.
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
        if !$vol.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        let mut r = $op;
        let mut tries = 0u32;
        while tries < 4 && matches!(r, Err(FsError::NoSpace)) {
            crate::write::grow_add_chunk(&$vol).await?;
            tries += 1;
            r = $op;
        }
        r
    }};
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
    inode: InodeItem,
}

impl<B: BlockDevice + 'static> BtrfsNode<B> {
    pub fn new(
        vol: Weak<BtrfsVolume<B>>,
        tree_root: Option<u64>,
        ino: u64,
        inode: InodeItem,
    ) -> Arc<Self> {
        Arc::new(BtrfsNode {
            vol,
            tree_root,
            tree_id: None,
            ino,
            inode,
        })
    }

    fn new_in_subvolume(
        vol: Weak<BtrfsVolume<B>>,
        tree_root: u64,
        tree_id: u64,
        ino: u64,
        inode: InodeItem,
    ) -> Arc<Self> {
        Arc::new(BtrfsNode {
            vol,
            tree_root: Some(tree_root),
            tree_id: Some(tree_id),
            ino,
            inode,
        })
    }

    fn volume(&self) -> Result<Arc<BtrfsVolume<B>>, FsError> {
        self.vol.upgrade().ok_or(FsError::NotFound)
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
                        || self.inode.file_type() != FileType::Dir
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
                        || self.inode.file_type() != FileType::Dir
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
                    crate::write::set_subvol_flags(&vol, disk_flags).await?;
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                BTRFS_IOC_SUBVOL_CREATE | BTRFS_IOC_SUBVOL_CREATE_V2 => {
                    // Creation is relative to the directory fd, but only a
                    // directory in the explicitly mounted live tree is mutable.
                    if self.tree_root.is_some() || self.inode.file_type() != FileType::Dir {
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
                    if self.tree_root.is_some() || self.inode.file_type() != FileType::Dir {
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
                    if self.tree_root.is_some() || self.inode.file_type() != FileType::Dir {
                        return Err(FsError::ReadOnly);
                    }
                    let command = u64::from_ne_bytes(input[0..8].try_into().unwrap());
                    match command {
                        1 => autogrow!(vol, crate::write::quota_enable(&vol).await)?,
                        2 => crate::write::quota_disable(&vol).await?,
                        // Simple quotas intentionally remain unsupported.
                        4 => return Err(FsError::Unsupported),
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
                        0 => crate::write::qgroup_destroy_admin(&vol, id).await?,
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
            if self.tree_root.is_some() || self.inode.file_type() != FileType::Dir {
                return Err(FsError::ReadOnly);
            }
            let source = source
                .as_any()
                .and_then(|a| a.downcast_ref::<BtrfsNode<B>>())
                .ok_or(FsError::CrossDevice)?;
            if source.ino != format::FIRST_FREE_OBJECTID
                || source.inode.file_type() != FileType::Dir
            {
                return Err(FsError::InvalidData);
            }
            let vol = self.volume()?;
            let source_vol = source.volume()?;
            if !Arc::ptr_eq(&vol, &source_vol) {
                return Err(FsError::CrossDevice);
            }
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

    /// Resolve a name to its directory entry via the CRC32C-hashed `DIR_ITEM`.
    async fn find_child(&self, name: &str) -> Result<BtrfsDirEntry, FsError> {
        let vol = self.volume()?;
        let key = BtrfsKey::new(
            self.ino,
            format::DIR_ITEM_KEY,
            u64::from(name_hash(name.as_bytes())),
        );
        let body = btree::find_item(&*vol, self.root(&vol), &key)
            .await?
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
                let child = vol.load_inode_in(self.root(vol), ino).await?;
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
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let vol = self.volume()?;
            let root = self.root(&vol);
            crate::extent::read_file(&vol, root, self.ino, self.inode.size, offset, buf).await
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
            autogrow!(
                vol,
                crate::write::cow_write_file(&vol, self.ino, &self.inode, offset, buf).await
            )
        })
    }

    /// btrfs commits synchronously here — every `write` already flips the
    /// superblock to a new generation and flushes the device, so a file's data is
    /// durable before `write` returns. `fsync` re-issues a device flush as a
    /// barrier; there is no uncommitted transaction to force out (the tree-log is
    /// only used to *replay* a crashed volume's log on mount, not to defer writes).
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.volume()?.flush().await;
            Ok(())
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.inode.size,
            blocks: self.inode.size.div_ceil(512),
            mode: Mode {
                file_type: self.inode.file_type(),
                perms: self.inode.perms() & 0o777,
            },
            mtime_cycles: 0,
        }
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn owners(&self) -> (u32, u32) {
        (self.inode.uid, self.inode.gid)
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
            let mtime = FsStatxTimestamp {
                seconds: self.inode.mtime_sec,
                nanoseconds: self.inode.mtime_nsec,
            };
            let (rdev_major, rdev_minor) = self.inode.rdev_major_minor();
            Ok(FsStatx {
                mask: STATX_BASIC_STATS,
                block_size: self.volume().map(|v| v.sectorsize()).unwrap_or(4096),
                nlink: self.inode.nlink,
                uid: self.inode.uid,
                gid: self.inode.gid,
                mode: (self.inode.mode & 0xffff) as u16,
                ino: self.ino,
                size: self.inode.size,
                blocks: self.inode.size.div_ceil(512),
                // btrfs stores a single mtime; surface it for atime/ctime too.
                atime: mtime,
                ctime: mtime,
                mtime,
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
            let body = btree::find_item(&*vol, self.root(&vol), &key)
                .await?
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
            let root = self.root(&vol);
            let items = btree::collect_for(&*vol, root, self.ino, format::XATTR_ITEM_KEY).await?;
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

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let vol = self.volume()?;
            let entry = self.find_child(name).await?;
            let node = self.load_child(&vol, &entry).await?;
            Ok(node as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let vol = self.volume()?;
            let entry = self.find_child(name).await?;
            let node = self.load_child(&vol, &entry).await?;
            if !node.inode.is_dir() {
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
            let root = self.root(&vol);
            // DIR_INDEX gives stable readdir order.
            let items = btree::collect_for(&*vol, root, self.ino, format::DIR_INDEX_KEY).await?;
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
            let vol = self.volume()?;
            let (ino, inode) =
                autogrow!(vol, crate::write::create_file(&vol, self.ino, name).await)?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            autogrow!(vol, crate::write::unlink_file(&vol, self.ino, name).await)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            let (ino, inode) = autogrow!(vol, crate::write::mkdir_dir(&vol, self.ino, name).await)?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn DirOps>)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            autogrow!(vol, crate::write::rmdir_dir(&vol, self.ino, name).await)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
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
            let vol = self.volume()?;
            let (ino, inode) = autogrow!(
                vol,
                crate::write::symlink_node(&vol, self.ino, name, target).await
            )?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
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
            // `rdev` arrives as the packed userspace `dev_t`; btrfs stores the raw
            // kernel `dev_t`. FIFOs carry no device number.
            let kdev = if rdev == 0 {
                0
            } else {
                glibc_to_kernel_dev(rdev)
            };
            let vol = self.volume()?;
            let (ino, inode) = autogrow!(
                vol,
                crate::write::mknod_node(&vol, self.ino, name, mode, ft, kdev).await
            )?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
        })
    }

    fn create_socket<'a>(&'a self, name: &'a str, perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            // S_IFSOCK | perms; no device number.
            let mode = 0o140000 | u32::from(perms & 0o7777);
            let (ino, inode) = autogrow!(
                vol,
                crate::write::mknod_node(&vol, self.ino, name, mode, format::FT_SOCK, 0).await
            )?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
        })
    }

    fn dir_mode(&self) -> u16 {
        self.inode.perms() & 0o777
    }

    fn dir_owners(&self) -> (u32, u32) {
        (self.inode.uid, self.inode.gid)
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

    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        // Read-only volume: accept only `ro`/empty option tokens.
        for opt in options.split(',').filter(|s| !s.is_empty()) {
            if opt != "ro" {
                return Err(FsError::Unsupported);
            }
        }
        Ok(())
    }
}

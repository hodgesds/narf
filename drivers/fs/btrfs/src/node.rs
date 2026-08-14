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
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, FsStat, FsStatx,
    FsStatxTimestamp, Mode, Stat,
};

use crate::btree;
use crate::checksum::name_hash;
use crate::dir::{decode_dir_items, DirEntry as BtrfsDirEntry};
use crate::format::{self, BtrfsKey};
use crate::inode::InodeItem;
use crate::volume::BtrfsVolume;

/// Linux `STATX_BASIC_STATS` — the fields this driver populates.
const STATX_BASIC_STATS: u32 = 0x7ff;

/// Convert a packed userspace `dev_t` (as `mknod` delivers it) to the raw kernel
/// `dev_t` btrfs stores on disk — Linux `new_decode_dev` followed by `MKDEV`
/// (`(major << 20) | minor`). Keeps NARF-created device nodes readable by a real
/// kernel with the right major/minor.
fn glibc_to_kernel_dev(dev: u64) -> u64 {
    let major = (dev >> 8) & 0xfff;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xf_ff00);
    (major << 20) | (minor & 0xf_ffff)
}

/// One btrfs inode presented to the VFS. A node records the fs tree it lives in:
/// `None` is the default subvolume (resolved dynamically from the live volume, so
/// a COW write's new root is observed), `Some(root)` pins a nested subvolume's
/// fs-tree root reached by descending a `ROOT_ITEM` directory entry.
#[derive(Debug)]
pub struct BtrfsNode<B: BlockDevice + 'static> {
    vol: Weak<BtrfsVolume<B>>,
    tree_root: Option<u64>,
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
            ino,
            inode,
        })
    }

    fn volume(&self) -> Result<Arc<BtrfsVolume<B>>, FsError> {
        self.vol.upgrade().ok_or(FsError::NotFound)
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
                Ok(BtrfsNode::new(
                    vol.self_weak.clone(),
                    self.tree_root,
                    ino,
                    child,
                ))
            }
            format::ROOT_ITEM_KEY => {
                let (root_tree, _) = vol.root_tree_root();
                let (subvol_root, _lvl) =
                    crate::roots::find_root(&**vol, root_tree, entry.location.objectid).await?;
                let ino = format::FIRST_FREE_OBJECTID;
                let child = vol.load_inode_in(subvol_root, ino).await?;
                Ok(BtrfsNode::new(
                    vol.self_weak.clone(),
                    Some(subvol_root),
                    ino,
                    child,
                ))
            }
            _ => Err(FsError::NotFound),
        }
    }
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
            // Only the default subvolume is writable (a pinned subvolume root
            // would need its own ROOT_ITEM COW). The COW write path itself
            // (`write::cow_write_file`) handles overwrite / partial / append /
            // grow of a single-regular-extent file and rejects the rest.
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::cow_write_file(&vol, self.ino, &self.inode, offset, buf).await
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
            crate::write::set_xattr_item(&vol, self.ino, name, value, flags).await
        })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::remove_xattr_item(&vol, self.ino, name).await
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

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            // Only the default subvolume is writable (a pinned subvolume would
            // need its own ROOT_ITEM COW).
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            let (ino, inode) = crate::write::create_file(&vol, self.ino, name).await?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn FileOps>)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::unlink_file(&vol, self.ino, name).await
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            let (ino, inode) = crate::write::mkdir_dir(&vol, self.ino, name).await?;
            Ok(BtrfsNode::new(vol.self_weak.clone(), None, ino, inode) as Arc<dyn DirOps>)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::rmdir_dir(&vol, self.ino, name).await
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::rename_same_dir(&vol, self.ino, old_name, new_name).await
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
            // in the default subvolume — else it is a genuine cross-device move.
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
                crate::write::rename_same_dir(&vol, self.ino, old_name, new_name).await
            } else {
                crate::write::rename_cross_dir(&vol, self.ino, dest.ino, old_name, new_name).await
            }
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::link_node(&vol, self.ino, self.ino, old_name, new_name).await
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
            crate::write::link_node(&vol, self.ino, dest.ino, old_name, new_name).await
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
            let (ino, inode) = crate::write::symlink_node(&vol, self.ino, name, target).await?;
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
            let (ino, inode) =
                crate::write::mknod_node(&vol, self.ino, name, mode, ft, kdev).await?;
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
            let (ino, inode) =
                crate::write::mknod_node(&vol, self.ino, name, mode, format::FT_SOCK, 0).await?;
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
        // `None` = default subvolume, resolved dynamically so a COW write's new
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

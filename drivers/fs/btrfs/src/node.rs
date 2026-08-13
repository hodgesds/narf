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
            // The basic COW path supports only a full, same-size overwrite of an
            // existing regular file in the default subvolume (see
            // `write::cow_overwrite_file`). Anything else — a partial write, an
            // append, a seek'd write, or a write into a nested subvolume — is
            // rejected rather than silently corrupting the file.
            if offset != 0 || buf.len() as u64 != self.inode.size {
                return Err(FsError::ReadOnly);
            }
            // Only the default subvolume is writable (a pinned subvolume root
            // would need its own ROOT_ITEM COW).
            if self.tree_root.is_some() {
                return Err(FsError::ReadOnly);
            }
            let vol = self.volume()?;
            crate::write::cow_overwrite_file(&vol, self.ino, &self.inode, buf).await
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
            let blocks = self.total_bytes() / u64::from(block_size.max(1));
            Ok(FsStat {
                blocks,
                blocks_free: 0,
                blocks_available: 0,
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

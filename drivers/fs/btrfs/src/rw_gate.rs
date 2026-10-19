//! Mount-time read-write safety gate.
//!
//! The analogue of Linux's `fs/btrfs/disk-io.c` `open_ctree` /
//! `btrfs_check_features` refusals, applied before NARF performs a single
//! write: a volume that fails any check is mounted read-only with a logged
//! refusal instead of being written by a writer that cannot keep it
//! consistent. Under `narf.disks=root-rw` the stricter [`Profile::RootRw`]
//! applies — the narrow, tested shape of an installed distro root — and the
//! root mount turns a refusal into a visible boot failure
//! ([`narf_filesystem::FsInstance::always_read_only`] on the refused volume).
//!
//! One filesystem has one writer: every mount of an fsid is a view over the
//! single shared core ([`crate::registry`]), so the gate runs once per core
//! and its verdict covers every subvolume mount of it. A read-write mount of
//! a refused core fails with EROFS ([`crate::volume::BtrfsVolume::make_writable`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;

use narf_block::BlockDevice;
use narf_lib::sync::IrqSafeSpinLock;

use crate::format::{self, BtrfsKey, Superblock};
use crate::volume::BtrfsVolume;

// ── On-disk constants the gate reads (Linux uapi `btrfs_tree.h`) ────

/// `BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE` (named in refusals).
pub const COMPAT_RO_BLOCK_GROUP_TREE: u64 = format::COMPAT_RO_BLOCK_GROUP_TREE;

/// Superblock `flags` field offset (`struct btrfs_super_block::flags`).
pub const OFF_SUPER_FLAGS: usize = 56;
/// `BTRFS_HEADER_FLAG_WRITTEN`: set on every superblock Linux writes.
pub const SUPER_FLAG_WRITTEN: u64 = 1 << 0;
pub const SUPER_FLAG_RELOC: u64 = 1 << 1;
/// `BTRFS_SUPER_FLAG_ERROR`: the filesystem hit an error and went read-only.
pub const SUPER_FLAG_ERROR: u64 = 1 << 2;
pub const SUPER_FLAG_SEEDING: u64 = 1 << 32;
pub const SUPER_FLAG_METADUMP: u64 = 1 << 33;
pub const SUPER_FLAG_METADUMP_V2: u64 = 1 << 34;
pub const SUPER_FLAG_CHANGING_FSID: u64 = 1 << 35;
pub const SUPER_FLAG_CHANGING_FSID_V2: u64 = 1 << 36;
pub const SUPER_FLAG_CHANGING_BG_TREE: u64 = 1 << 38;
pub const SUPER_FLAG_CHANGING_DATA_CSUM: u64 = 1 << 39;
pub const SUPER_FLAG_CHANGING_META_CSUM: u64 = 1 << 40;
/// Superblock flags a writable mount accepts: only "written".
pub const WRITABLE_SUPER_FLAGS: u64 = SUPER_FLAG_WRITTEN;

/// `BTRFS_BALANCE_OBJECTID` — the paused/running balance item's objectid.
const BALANCE_OBJECTID: u64 = (-4i64) as u64;
/// `BTRFS_TEMPORARY_ITEM_KEY` (the balance item's key type).
const TEMPORARY_ITEM_KEY: u8 = 248;
/// `BTRFS_TREE_RELOC_OBJECTID` — an interrupted relocation's reloc roots.
const TREE_RELOC_OBJECTID: u64 = (-8i64) as u64;
/// `BTRFS_DEV_REPLACE_KEY`, keyed `(0, DEV_REPLACE, 0)` in the dev tree.
const DEV_REPLACE_KEY: u8 = 250;
/// `struct btrfs_dev_replace_item::replace_state` offset.
const DEV_REPLACE_STATE: usize = 32;
const REPLACE_STARTED: u64 = 1;
const REPLACE_SUSPENDED: u64 = 4;

// ── Supported feature sets ──────────────────────────────────────────

/// Incompat bits the COW writer fully implements, read off `write.rs`: it
/// emits mixed backrefs and skinny `METADATA_ITEM`s, honours big metadata
/// nodes, no-holes, the default-subvolume `DIR_ITEM`, mixed block groups,
/// all RAID profiles including RAID5/6 and RAID1C3/4, metadata_uuid, and
/// simple-quota owner refs; it rewrites LZO/zstd extents it touches as
/// uncompressed COW (zlib-only windows stay zlib) and never emits LZO/zstd.
/// Extended irefs are decoded by the reader; the writer refuses (rather
/// than mis-edits) a link whose name lives only in an `INODE_EXTREF`.
pub const WRITER_INCOMPAT: u64 = format::SUPPORTED_INCOMPAT_FLAGS;

/// Compat-ro bits the writer maintains — [`format::WRITE_SUPPORTED_COMPAT_RO_FLAGS`]:
/// the free-space tree, its valid bit, and the block-group tree.
pub const WRITER_COMPAT_RO: u64 = format::WRITE_SUPPORTED_COMPAT_RO_FLAGS;

/// `narf.disks=root-rw`: the narrow incompat set a production root may
/// carry — what `mkfs.btrfs` and a CachyOS install produce. Multi-device,
/// RAID56/1C34, mixed groups, metadata_uuid and simple quotas stay off.
pub const ROOT_RW_INCOMPAT: u64 = format::INCOMPAT_MIXED_BACKREF
    | format::INCOMPAT_DEFAULT_SUBVOL
    | format::INCOMPAT_COMPRESS_LZO
    | format::INCOMPAT_COMPRESS_ZSTD
    | format::INCOMPAT_BIG_METADATA
    | format::INCOMPAT_EXTENDED_IREF
    | format::INCOMPAT_SKINNY_METADATA
    | format::INCOMPAT_NO_HOLES;

/// `narf.disks=root-rw` compat-ro bits that must all be present
/// (`space_cache=v2`, valid).
pub const ROOT_RW_REQUIRED_COMPAT_RO: u64 =
    format::COMPAT_RO_FREE_SPACE_TREE | format::COMPAT_RO_FREE_SPACE_TREE_VALID;

/// Which rule set applies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Every RW mount: refuse what the writer cannot keep consistent.
    Default,
    /// `narf.disks=root-rw`: additionally the narrow production-root shape.
    RootRw,
}

/// The profile for mounts under the active disk policy.
pub fn active_profile() -> Profile {
    if narf_block::disk_policy::policy() == narf_block::disk_policy::DiskPolicy::RootRw {
        Profile::RootRw
    } else {
        Profile::Default
    }
}

/// Why a read-write mount was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Incompat bits outside the writer's set (the offending bits).
    Incompat(u64),
    /// Compat-ro bits outside the writer's set (the offending bits).
    CompatRo(u64),
    /// A free-space tree without its valid bit, or a block-group tree
    /// without a free-space tree: Linux rebuilds/refuses; NARF cannot.
    FreeSpaceTreeInvalid,
    /// No free-space tree: required under `root-rw`, and on any volume whose
    /// block groups are not mixed (the fallback allocator cannot keep data
    /// and metadata apart there).
    NoFreeSpaceTree,
    /// A non-empty fsync log tree that Linux would replay first.
    LogTree(u64),
    /// Checksum algorithm the profile does not write.
    ChecksumType(u16),
    /// Sector size the profile does not write.
    SectorSize(u32),
    /// Node size the profile does not write.
    NodeSize(u32),
    /// `BTRFS_SUPER_FLAG_ERROR`: the filesystem recorded an error.
    ErrorState,
    /// Other superblock flags (seeding, metadump, fsid/csum change...).
    SuperFlags(u64),
    /// A zero generation: not a committed filesystem.
    Generation,
    /// More than one device (`num_devices`).
    MultiDevice(u64),
    /// A balance item: Linux resumes the balance on a RW mount.
    BalanceInProgress,
    /// A started or suspended device replace.
    ReplaceInProgress,
    /// Reloc roots of an interrupted relocation.
    RelocationInProgress,
    /// A subvolume has been snapshotted (`last_snapshot != 0`): its tree
    /// blocks may be shared with a snapshot, and the writer would have to
    /// follow Linux `update_ref_for_cow` to COW them without freeing blocks
    /// the snapshot still uses.
    Snapshotted {
        /// The subvolume's tree id.
        root: u64,
        /// Its `btrfs_root_item::last_snapshot` generation.
        last_snapshot: u64,
    },
    /// A deleted subvolume whose tree Linux has not finished dropping (an
    /// orphan root item, `refs == 0`, or a `drop_progress` key).
    DeadRoot(u64),
    /// A tree block whose backrefs the writer does not maintain: more than
    /// one reference, `FULL_BACKREF`, a shared-block or keyed backref.
    SharedTreeBlock {
        bytenr: u64,
        refs: u64,
        flags: u64,
        why: &'static str,
    },
}

fn push_bits(out: &mut String, bits: u64, name: fn(u32) -> Option<&'static str>) {
    let mut first = true;
    for bit in 0..64 {
        if bits & (1u64 << bit) == 0 {
            continue;
        }
        if !first {
            out.push('|');
        }
        first = false;
        match name(bit) {
            Some(n) => out.push_str(n),
            None => {
                let _ = write!(out, "bit{bit}");
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bits = String::new();
        match self {
            Refusal::Incompat(b) => {
                push_bits(&mut bits, *b, incompat_name);
                write!(f, "unsupported incompat feature(s) for writing: {bits}")
            }
            Refusal::CompatRo(b) => {
                push_bits(&mut bits, *b, compat_ro_name);
                write!(f, "unsupported compat_ro feature(s) for writing: {bits}")
            }
            Refusal::FreeSpaceTreeInvalid => f.write_str(
                "free-space tree not marked valid (or block-group tree without free-space tree)",
            ),
            Refusal::NoFreeSpaceTree => f.write_str(
                "no free-space tree (space_cache=v2 required unless every block group is mixed)",
            ),
            Refusal::LogTree(at) => write!(
                f,
                "non-empty fsync log tree at {at:#x} (needs Linux log replay; mount it once on Linux)"
            ),
            Refusal::ChecksumType(c) => write!(f, "checksum type {c} not written in this mode"),
            Refusal::SectorSize(s) => write!(f, "sectorsize {s} not written in this mode"),
            Refusal::NodeSize(n) => write!(f, "nodesize {n} not written in this mode"),
            Refusal::ErrorState => f.write_str("superblock carries BTRFS_SUPER_FLAG_ERROR"),
            Refusal::SuperFlags(b) => {
                push_bits(&mut bits, *b, super_flag_name);
                write!(f, "superblock flags {bits}")
            }
            Refusal::Generation => f.write_str("superblock generation is 0"),
            Refusal::MultiDevice(n) => write!(f, "{n}-device filesystem (single device only)"),
            Refusal::BalanceInProgress => f.write_str("a balance is paused or running"),
            Refusal::ReplaceInProgress => f.write_str("a device replace is started or suspended"),
            Refusal::RelocationInProgress => f.write_str("an interrupted relocation is pending"),
            Refusal::Snapshotted {
                root,
                last_snapshot,
            } => write!(
                f,
                "subvolume {root} has snapshots (last_snapshot gen {last_snapshot}); \
                 its tree blocks may be shared and the writer does not yet maintain \
                 shared-block backrefs"
            ),
            Refusal::DeadRoot(root) => write!(
                f,
                "deleted subvolume {root} is still being dropped (mount it once on Linux)"
            ),
            Refusal::SharedTreeBlock {
                bytenr,
                refs,
                flags,
                why,
            } => write!(
                f,
                "tree block {bytenr:#x} refs {refs} flags {flags:#x}: {why}; \
                 the writer does not yet maintain shared-block backrefs"
            ),
        }
    }
}

/// Linux's name for an incompat bit.
pub fn incompat_name(bit: u32) -> Option<&'static str> {
    Some(match bit {
        0 => "MIXED_BACKREF",
        1 => "DEFAULT_SUBVOL",
        2 => "MIXED_GROUPS",
        3 => "COMPRESS_LZO",
        4 => "COMPRESS_ZSTD",
        5 => "BIG_METADATA",
        6 => "EXTENDED_IREF",
        7 => "RAID56",
        8 => "SKINNY_METADATA",
        9 => "NO_HOLES",
        10 => "METADATA_UUID",
        11 => "RAID1C34",
        12 => "ZONED",
        13 => "EXTENT_TREE_V2",
        14 => "RAID_STRIPE_TREE",
        16 => "SIMPLE_QUOTA",
        _ => return None,
    })
}

/// Linux's name for a compat-ro bit.
pub fn compat_ro_name(bit: u32) -> Option<&'static str> {
    Some(match bit {
        0 => "FREE_SPACE_TREE",
        1 => "FREE_SPACE_TREE_VALID",
        2 => "VERITY",
        3 => "BLOCK_GROUP_TREE",
        _ => return None,
    })
}

fn super_flag_name(bit: u32) -> Option<&'static str> {
    Some(match bit {
        0 => "WRITTEN",
        1 => "RELOC",
        2 => "ERROR",
        32 => "SEEDING",
        33 => "METADUMP",
        34 => "METADUMP_V2",
        35 => "CHANGING_FSID",
        36 => "CHANGING_FSID_V2",
        38 => "CHANGING_BG_TREE",
        39 => "CHANGING_DATA_CSUM",
        40 => "CHANGING_META_CSUM",
        _ => return None,
    })
}

/// The feature names a profile writes, `(incompat, compat_ro)`.
pub fn supported_features(profile: Profile) -> (Vec<&'static str>, Vec<&'static str>) {
    let (incompat, compat_ro) = match profile {
        Profile::Default => (WRITER_INCOMPAT, WRITER_COMPAT_RO),
        Profile::RootRw => (ROOT_RW_INCOMPAT, WRITER_COMPAT_RO),
    };
    let names = |bits: u64, name: fn(u32) -> Option<&'static str>| {
        (0..64)
            .filter(|b| bits & (1u64 << b) != 0)
            .filter_map(name)
            .collect::<Vec<_>>()
    };
    (
        names(incompat, incompat_name),
        names(compat_ro, compat_ro_name),
    )
}

/// The superblock checks, from the selected superblock and its raw `flags`
/// word. Pure: the unit of the refusal-reason tests.
pub fn check_superblock(
    sb: &Superblock,
    super_flags: u64,
    profile: Profile,
) -> Result<(), Refusal> {
    let (incompat_ok, compat_ro_ok) = match profile {
        Profile::Default => (WRITER_INCOMPAT, WRITER_COMPAT_RO),
        Profile::RootRw => (ROOT_RW_INCOMPAT, WRITER_COMPAT_RO),
    };
    if super_flags & SUPER_FLAG_ERROR != 0 {
        return Err(Refusal::ErrorState);
    }
    let odd_flags = super_flags & !WRITABLE_SUPER_FLAGS;
    if odd_flags != 0 {
        return Err(Refusal::SuperFlags(odd_flags));
    }
    if sb.generation == 0 {
        return Err(Refusal::Generation);
    }
    let incompat = sb.incompat_flags & !incompat_ok;
    if incompat != 0 {
        return Err(Refusal::Incompat(incompat));
    }
    let compat_ro = sb.compat_ro_flags & !compat_ro_ok;
    if compat_ro != 0 {
        return Err(Refusal::CompatRo(compat_ro));
    }
    let fst = sb.compat_ro_flags & format::COMPAT_RO_FREE_SPACE_TREE != 0;
    let fst_valid = sb.compat_ro_flags & format::COMPAT_RO_FREE_SPACE_TREE_VALID != 0;
    let bgt = sb.compat_ro_flags & COMPAT_RO_BLOCK_GROUP_TREE != 0;
    if fst != fst_valid || (bgt && !fst) {
        return Err(Refusal::FreeSpaceTreeInvalid);
    }
    // Without a free-space tree the allocator only appends past the extent
    // tree's high-water mark, which keeps data and tree blocks in their own
    // block groups only when every group is mixed.
    if !fst && sb.incompat_flags & format::INCOMPAT_MIXED_GROUPS == 0 {
        return Err(Refusal::NoFreeSpaceTree);
    }
    if profile == Profile::RootRw {
        if sb.compat_ro_flags & ROOT_RW_REQUIRED_COMPAT_RO != ROOT_RW_REQUIRED_COMPAT_RO {
            return Err(Refusal::NoFreeSpaceTree);
        }
        if sb.log_root != 0 {
            return Err(Refusal::LogTree(sb.log_root));
        }
        if sb.csum_type != format::CSUM_TYPE_CRC32 {
            return Err(Refusal::ChecksumType(sb.csum_type));
        }
        if sb.sectorsize != 4096 {
            return Err(Refusal::SectorSize(sb.sectorsize));
        }
        if !sb.nodesize.is_power_of_two() || !(4096..=65536).contains(&sb.nodesize) {
            return Err(Refusal::NodeSize(sb.nodesize));
        }
        if sb.num_devices != 1 {
            return Err(Refusal::MultiDevice(sb.num_devices));
        }
    }
    Ok(())
}

/// The tree checks (balance, replace, relocation), which need the chunk map.
pub async fn check_trees<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<(), Refusal> {
    let (root_tree, _) = vol.root_tree_root();
    // A read error is a refusal too: the gate fails closed.
    let balance = crate::btree::find_item(
        vol,
        root_tree,
        &BtrfsKey::new(BALANCE_OBJECTID, TEMPORARY_ITEM_KEY, 0),
    )
    .await;
    if !matches!(balance, Ok(None)) {
        return Err(Refusal::BalanceInProgress);
    }
    match crate::btree::collect_for(vol, root_tree, TREE_RELOC_OBJECTID, format::ROOT_ITEM_KEY)
        .await
    {
        Ok(items) if items.is_empty() => {}
        _ => return Err(Refusal::RelocationInProgress),
    }
    let dev_tree = crate::roots::find_root(vol, root_tree, format::DEV_TREE_OBJECTID).await;
    if let Ok((dev_root, _)) = dev_tree {
        match crate::btree::find_item(vol, dev_root, &BtrfsKey::new(0, DEV_REPLACE_KEY, 0)).await {
            Ok(None) => {}
            Ok(Some(body)) => {
                let state = format::le64(&body, DEV_REPLACE_STATE).unwrap_or(REPLACE_STARTED);
                if matches!(state, REPLACE_STARTED | REPLACE_SUSPENDED) {
                    return Err(Refusal::ReplaceInProgress);
                }
            }
            Err(_) => return Err(Refusal::ReplaceInProgress),
        }
    }
    check_sharing(vol).await
}

// ── Shared tree blocks ──────────────────────────────────────────────

/// `BTRFS_ORPHAN_OBJECTID`: orphan items in the root tree name deleted
/// subvolumes whose trees are still being dropped.
const ORPHAN_OBJECTID: u64 = (-5i64) as u64;
/// `BTRFS_ORPHAN_ITEM_KEY`.
const ORPHAN_ITEM_KEY: u8 = 48;
/// `btrfs_root_item` field offsets.
const ROOT_ITEM_BYTENR: usize = 176;
pub(crate) const ROOT_ITEM_LAST_SNAPSHOT: usize = 200;
const ROOT_ITEM_REFS: usize = 216;
const ROOT_ITEM_DROP_PROGRESS: usize = 220;
const ROOT_ITEM_DROP_LEVEL: usize = 237;
/// Extent-item flags (`BTRFS_EXTENT_FLAG_*`, `BTRFS_BLOCK_FLAG_FULL_BACKREF`).
pub const EXTENT_FLAG_DATA: u64 = 1 << 0;
pub const EXTENT_FLAG_TREE_BLOCK: u64 = 1 << 1;
pub const BLOCK_FLAG_FULL_BACKREF: u64 = 1 << 8;
/// Backref key types (inline type bytes and keyed item types).
pub const TREE_BLOCK_REF_KEY: u8 = 176;
pub const EXTENT_DATA_REF_KEY: u8 = 178;
pub const SHARED_BLOCK_REF_KEY: u8 = 182;
pub const SHARED_DATA_REF_KEY: u8 = 184;

/// Whether the writer maintains Linux's shared-tree-block backrefs
/// (`update_ref_for_cow`). Until it does, any sharing is refused here.
pub const WRITER_HANDLES_SHARED_TREES: bool = true;

pub(crate) fn is_fs_tree(id: u64) -> bool {
    id == format::FS_TREE_OBJECTID
        || (format::FIRST_FREE_OBJECTID..=format::LAST_FREE_OBJECTID).contains(&id)
}

/// What one subvolume ROOT_ITEM says about sharing. Pure: the unit of the
/// root-item refusal tests.
pub fn check_root_item(id: u64, body: &[u8]) -> Result<(), Refusal> {
    if !is_fs_tree(id) {
        return Ok(());
    }
    let le64 = |off: usize| format::le64(body, off).unwrap_or(u64::MAX);
    if body.len() <= ROOT_ITEM_DROP_LEVEL {
        // An old (pre-v2) root item is still long enough for these fields;
        // anything shorter is not a root item NARF can judge.
        return Err(Refusal::DeadRoot(id));
    }
    let refs = format::le32(body, ROOT_ITEM_REFS).unwrap_or(0);
    if refs == 0 || le64(ROOT_ITEM_DROP_PROGRESS) != 0 || body[ROOT_ITEM_DROP_LEVEL] != 0 {
        return Err(Refusal::DeadRoot(id));
    }
    let last_snapshot = le64(ROOT_ITEM_LAST_SNAPSHOT);
    if last_snapshot != 0 && !WRITER_HANDLES_SHARED_TREES {
        return Err(Refusal::Snapshotted {
            root: id,
            last_snapshot,
        });
    }
    Ok(())
}

/// What one tree-block extent item says about sharing. `inline` is the body
/// after `btrfs_extent_item` (and `tree_block_info` for a non-skinny item);
/// `root_holders` is how many ROOT_ITEMs name this block as their root
/// (NARF's own O(1) snapshot shares a root block between root items, which
/// the writer privatises before the first mutation). Pure.
pub fn check_tree_block_item(
    bytenr: u64,
    refs: u64,
    flags: u64,
    inline: &[u8],
    root_holders: u64,
) -> Result<(), Refusal> {
    let refuse = |why| {
        Err(Refusal::SharedTreeBlock {
            bytenr,
            refs,
            flags,
            why,
        })
    };
    if WRITER_HANDLES_SHARED_TREES {
        return Ok(());
    }
    if flags & BLOCK_FLAG_FULL_BACKREF != 0 {
        return refuse("FULL_BACKREF");
    }
    let mut pos = 0usize;
    let mut counted = 0u64;
    while pos < inline.len() {
        let size = match inline[pos] {
            TREE_BLOCK_REF_KEY => 9,
            SHARED_BLOCK_REF_KEY => return refuse("shared-block backref"),
            _ => return refuse("unexpected inline backref"),
        };
        if pos + size > inline.len() {
            return refuse("truncated inline backref");
        }
        counted += 1;
        pos += size;
    }
    if counted != refs {
        return refuse("keyed backref");
    }
    if refs > 1 && refs != root_holders {
        return refuse("shared below a subvolume root");
    }
    Ok(())
}

/// Refuse a read-write mount while any tree block is (or may be) shared in a
/// way the writer does not maintain. Linux `btrfs_block_can_be_shared` /
/// `update_ref_for_cow` decide per COW whether a block is shared with a
/// snapshot; until NARF follows them, the gate fails closed on every sign of
/// sharing: a snapshotted or half-deleted subvolume, and any tree block in a
/// metadata block group with more than one reference (other than NARF's own
/// shared subvolume root), `FULL_BACKREF`, or a shared/keyed backref.
pub async fn check_sharing<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<(), Refusal> {
    let fail = |_| Refusal::SharedTreeBlock {
        bytenr: 0,
        refs: 0,
        flags: 0,
        why: "extent/root tree unreadable",
    };
    let (root_tree, _) = vol.root_tree_root();
    let mut holders: alloc::collections::BTreeMap<u64, u64> = alloc::collections::BTreeMap::new();
    {
        let mut cursor = crate::btree::Cursor::seek(vol, root_tree, &BtrfsKey::new(0, 0, 0))
            .await
            .map_err(fail)?;
        while let Some((key, body)) = cursor.current().map_err(fail)? {
            if key.objectid == ORPHAN_OBJECTID && key.item_type == ORPHAN_ITEM_KEY {
                return Err(Refusal::DeadRoot(key.offset));
            }
            if key.item_type == format::ROOT_ITEM_KEY {
                check_root_item(key.objectid, body)?;
                if is_fs_tree(key.objectid) {
                    let at = format::le64(body, ROOT_ITEM_BYTENR).map_err(fail)?;
                    *holders.entry(at).or_insert(0) += 1;
                }
            }
            cursor.advance().await.map_err(fail)?;
        }
    }
    let (extent_root, _) = crate::roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await
        .map_err(fail)?;
    let bg_tree = crate::block_group::bg_home(vol, root_tree)
        .await
        .map_err(fail)?
        .scan_root(extent_root);
    let groups = crate::block_group::read_block_groups(vol, bg_tree)
        .await
        .map_err(fail)?;
    for (start, len, body) in groups {
        let bg_flags = format::le64(&body, 16).map_err(fail)?;
        if bg_flags & (format::BLOCK_GROUP_METADATA | format::BLOCK_GROUP_SYSTEM) == 0 {
            continue;
        }
        let end = start.saturating_add(len);
        let mut cursor = crate::btree::Cursor::seek(vol, extent_root, &BtrfsKey::new(start, 0, 0))
            .await
            .map_err(fail)?;
        while let Some((key, body)) = cursor.current().map_err(fail)? {
            if key.objectid >= end {
                break;
            }
            match key.item_type {
                format::METADATA_ITEM_KEY | format::EXTENT_ITEM_KEY => {
                    let refs = format::le64(body, 0).map_err(fail)?;
                    let flags = format::le64(body, 16).map_err(fail)?;
                    if flags & EXTENT_FLAG_TREE_BLOCK != 0
                        && key.item_type == format::EXTENT_ITEM_KEY
                    {
                        // A pre-skinny tree-block record: the writer only
                        // keeps skinny `METADATA_ITEM`s.
                        return Err(Refusal::SharedTreeBlock {
                            bytenr: key.objectid,
                            refs,
                            flags,
                            why: "non-skinny tree-block extent item",
                        });
                    }
                    if flags & EXTENT_FLAG_TREE_BLOCK != 0 {
                        // A non-skinny item carries `tree_block_info` (key + level).
                        let inline_at = if key.item_type == format::EXTENT_ITEM_KEY {
                            24 + format::DISK_KEY_SIZE + 1
                        } else {
                            24
                        };
                        let inline = body.get(inline_at..).unwrap_or(&[]);
                        let held = holders.get(&key.objectid).copied().unwrap_or(0);
                        check_tree_block_item(key.objectid, refs, flags, inline, held)?;
                    }
                }
                TREE_BLOCK_REF_KEY | SHARED_BLOCK_REF_KEY if !WRITER_HANDLES_SHARED_TREES => {
                    return Err(Refusal::SharedTreeBlock {
                        bytenr: key.objectid,
                        refs: 0,
                        flags: 0,
                        why: "keyed tree-block backref",
                    });
                }
                _ => {}
            }
            cursor.advance().await.map_err(fail)?;
        }
    }
    Ok(())
}

// ── Refusal record ──────────────────────────────────────────────────

static LAST_REFUSAL: IrqSafeSpinLock<Option<String>> = IrqSafeSpinLock::new(None);

/// The most recent refusal message (for the root mount's failure banner).
pub fn last_refusal() -> Option<String> {
    LAST_REFUSAL.lock().clone()
}

/// Log a refusal (the volume is mounted read-only instead) and remember it.
pub(crate) fn report(fsid: &[u8; 16], profile: Profile, why: &Refusal) {
    report_with(fsid, profile, why, "mounting READ-ONLY");
}

/// Log a refusal of a read-write mount request that fails outright (Linux's
/// `btrfs_check_features` -EINVAL for an unwritable compat_ro feature; the
/// caller may retry read-only) and remember it.
pub(crate) fn report_refused_mount(fsid: &[u8; 16], profile: Profile, why: &Refusal) {
    report_with(
        fsid,
        profile,
        why,
        "the read-write mount fails (read-only is allowed)",
    );
}

fn report_with(fsid: &[u8; 16], profile: Profile, why: &Refusal, outcome: &str) {
    let fsid = narf_block::partition::format_uuid_bytes(fsid);
    let mut line = alloc::format!("btrfs {fsid}: REFUSING read-write mount: {why}; {outcome}");
    if profile == Profile::RootRw {
        let (incompat, compat_ro) = supported_features(profile);
        let _ = write!(
            line,
            " (narf.disks=root-rw writes only incompat [{}] compat_ro [{}])",
            incompat.join(","),
            compat_ro.join(",")
        );
    }
    let _ = writeln!(narf_console::Writer, "{line}");
    *LAST_REFUSAL.lock() = Some(line);
}

//! Extent-tree backreference maintenance: Linux's delayed-ref semantics for
//! tree blocks and data extents that may be shared with snapshots.
//!
//! A snapshot shares everything below its root with the subvolume it was taken
//! of. Linux does not record that sharing eagerly; it records it lazily, at the
//! moment one of the trees copies-on-write a shared block
//! (`fs/btrfs/ctree.c::update_ref_for_cow`):
//!
//! * a block referenced more than once is never freed by a COW; the COWing
//!   tree only drops its own reference (`btrfs_free_tree_block`), after first
//!   giving every child of the block a reference of its own
//!   (`btrfs_inc_ref`) — a `TREE_BLOCK_REF`/`EXTENT_DATA_REF` naming the
//!   COWing tree, or, when that tree owns the block, a
//!   `SHARED_BLOCK_REF`/`SHARED_DATA_REF` naming the old block as parent
//!   (the block then becomes `FULL_BACKREF`);
//! * a `FULL_BACKREF` block referenced once moves its children back from
//!   parent refs to tree refs (`btrfs_inc_ref(cow)`, `btrfs_dec_ref(buf)`)
//!   and is then freed.
//!
//! [`RefOverlay`] is the transaction's view of the extent tree's reference
//! state: every extent item and keyed backref item the transaction rewrote,
//! over the committed extent tree. Reference changes are applied to it
//! eagerly and in order (so a later COW in the same transaction sees the refs
//! an earlier one added, exactly as Linux's delayed-ref heads do), with
//! Linux's inline-ref ordering and its rules for when a reference goes into a
//! keyed item instead (`lookup_inline_extent_backref`). The commit then turns
//! the overlay into ordinary extent-tree edits.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree;
use crate::format::{self, le32, le64, BtrfsKey};
use crate::volume::BtrfsVolume;

/// Inline/keyed backref types (`btrfs_tree.h`).
pub(crate) const TREE_BLOCK_REF_KEY: u8 = 176;
pub(crate) const EXTENT_DATA_REF_KEY: u8 = 178;
pub(crate) const SHARED_BLOCK_REF_KEY: u8 = 182;
pub(crate) const SHARED_DATA_REF_KEY: u8 = 184;
/// Simple-quota owner ref: inline only, carries no reference count.
pub(crate) const EXTENT_OWNER_REF_KEY: u8 = 172;

/// `btrfs_extent_item.flags`.
pub(crate) const EXTENT_FLAG_TREE_BLOCK: u64 = 1 << 1;
pub(crate) const BLOCK_FLAG_FULL_BACKREF: u64 = 1 << 8;

/// Size of `btrfs_extent_item` (refs, generation, flags).
const EXTENT_ITEM_SIZE: usize = 24;
/// `sizeof(struct btrfs_item)` in a leaf.
const LEAF_ITEM_SIZE: usize = format::DISK_KEY_SIZE + 8;

/// One reference to an extent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefKind {
    /// `TREE_BLOCK_REF`: tree `root` references this tree block.
    Tree { root: u64 },
    /// `SHARED_BLOCK_REF`: the `FULL_BACKREF` block at `parent` points here.
    SharedBlock { parent: u64 },
    /// `EXTENT_DATA_REF`: `objectid`'s file item at `offset` (key offset
    /// minus extent offset) in tree `root`.
    Data {
        root: u64,
        objectid: u64,
        offset: u64,
    },
    /// `SHARED_DATA_REF`: a file item in the `FULL_BACKREF` leaf `parent`.
    SharedData { parent: u64 },
}

impl RefKind {
    fn type_byte(self) -> u8 {
        match self {
            RefKind::Tree { .. } => TREE_BLOCK_REF_KEY,
            RefKind::SharedBlock { .. } => SHARED_BLOCK_REF_KEY,
            RefKind::Data { .. } => EXTENT_DATA_REF_KEY,
            RefKind::SharedData { .. } => SHARED_DATA_REF_KEY,
        }
    }

    fn inline_size(self) -> usize {
        match self {
            RefKind::Tree { .. } | RefKind::SharedBlock { .. } => 9,
            RefKind::Data { .. } => 29,
            RefKind::SharedData { .. } => 13,
        }
    }

    /// Linux `hash_extent_data_ref`.
    fn data_hash(root: u64, objectid: u64, offset: u64) -> u64 {
        let high = crate::checksum::crc32c(!0u32, &root.to_le_bytes());
        let mut low = crate::checksum::crc32c(!0u32, &objectid.to_le_bytes());
        low = crate::checksum::crc32c(low, &offset.to_le_bytes());
        (u64::from(high) << 31) ^ u64::from(low)
    }

    /// The key offset that orders this ref among its type (and keys its
    /// keyed item, before collision probing for data refs).
    fn order(self) -> u64 {
        match self {
            RefKind::Tree { root } => root,
            RefKind::SharedBlock { parent } | RefKind::SharedData { parent } => parent,
            RefKind::Data {
                root,
                objectid,
                offset,
            } => Self::data_hash(root, objectid, offset),
        }
    }

    /// The inline encoding with a count of one.
    fn encode_inline(self) -> Vec<u8> {
        let mut v = alloc::vec![self.type_byte()];
        match self {
            RefKind::Tree { root } => v.extend_from_slice(&root.to_le_bytes()),
            RefKind::SharedBlock { parent } => v.extend_from_slice(&parent.to_le_bytes()),
            RefKind::Data {
                root,
                objectid,
                offset,
            } => {
                v.extend_from_slice(&root.to_le_bytes());
                v.extend_from_slice(&objectid.to_le_bytes());
                v.extend_from_slice(&offset.to_le_bytes());
                v.extend_from_slice(&1u32.to_le_bytes());
            }
            RefKind::SharedData { parent } => {
                v.extend_from_slice(&parent.to_le_bytes());
                v.extend_from_slice(&1u32.to_le_bytes());
            }
        }
        v
    }

    /// Whether the inline ref at `body[at..]` (of this kind's type) is this
    /// reference.
    fn matches_inline(self, body: &[u8], at: usize) -> Result<bool, FsError> {
        Ok(match self {
            RefKind::Tree { root } => le64(body, at + 1)? == root,
            RefKind::SharedBlock { parent } | RefKind::SharedData { parent } => {
                le64(body, at + 1)? == parent
            }
            RefKind::Data {
                root,
                objectid,
                offset,
            } => {
                le64(body, at + 1)? == root
                    && le64(body, at + 9)? == objectid
                    && le64(body, at + 17)? == offset
            }
        })
    }

    /// The ordering offset of the inline ref of this kind's type at `at`.
    fn inline_order(self, body: &[u8], at: usize) -> Result<u64, FsError> {
        Ok(match self {
            RefKind::Data { .. } => Self::data_hash(
                le64(body, at + 1)?,
                le64(body, at + 9)?,
                le64(body, at + 17)?,
            ),
            _ => le64(body, at + 1)?,
        })
    }
}

/// Size and reference count of the inline ref of type `kind` at `body[at..]`.
pub(crate) fn inline_ref_shape(body: &[u8], at: usize) -> Result<(usize, u64), FsError> {
    let kind = *body.get(at).ok_or(FsError::InvalidData)?;
    let (size, count) = match kind {
        TREE_BLOCK_REF_KEY | SHARED_BLOCK_REF_KEY => (9, 1),
        EXTENT_OWNER_REF_KEY => (9, 0),
        EXTENT_DATA_REF_KEY => (29, u64::from(le32(body, at + 25)?)),
        SHARED_DATA_REF_KEY => (13, u64::from(le32(body, at + 9)?)),
        _ => return Err(FsError::Unsupported),
    };
    if at + size > body.len() {
        return Err(FsError::InvalidData);
    }
    Ok((size, count))
}

/// Offset of the first inline ref in an extent item body.
fn inline_start(body: &[u8], key: &BtrfsKey) -> Result<usize, FsError> {
    let flags = le64(body, 16)?;
    if key.item_type == format::EXTENT_ITEM_KEY && flags & EXTENT_FLAG_TREE_BLOCK != 0 {
        // Non-skinny tree block: `btrfs_tree_block_info` (key + level).
        Ok(EXTENT_ITEM_SIZE + format::DISK_KEY_SIZE + 1)
    } else {
        Ok(EXTENT_ITEM_SIZE)
    }
}

/// Sum of the inline refs' counts (the rest of `refs` lives in keyed items).
fn inline_count(body: &[u8], key: &BtrfsKey) -> Result<u64, FsError> {
    let mut at = inline_start(body, key)?;
    let mut total = 0u64;
    while at < body.len() {
        let (size, count) = inline_ref_shape(body, at)?;
        total = total.checked_add(count).ok_or(FsError::InvalidData)?;
        at += size;
    }
    Ok(total)
}

/// Where `want` is (`Ok(at)`) or would be inserted (`Err(at)`) among the
/// inline refs: type ascending, then (for one type) ordering offset
/// descending — Linux `lookup_inline_extent_backref`.
fn find_inline(
    body: &[u8],
    key: &BtrfsKey,
    want: RefKind,
) -> Result<Result<usize, usize>, FsError> {
    let want_type = want.type_byte();
    let want_order = want.order();
    let mut at = inline_start(body, key)?;
    while at < body.len() {
        let kind = body[at];
        let (size, _) = inline_ref_shape(body, at)?;
        if kind == EXTENT_OWNER_REF_KEY {
            at += size;
            continue;
        }
        if want_type < kind {
            return Ok(Err(at));
        }
        if want_type == kind {
            if want.matches_inline(body, at)? {
                return Ok(Ok(at));
            }
            if want.inline_order(body, at)? < want_order {
                return Ok(Err(at));
            }
        }
        at += size;
    }
    Ok(Err(body.len()))
}

/// Linux `BTRFS_MAX_EXTENT_ITEM_SIZE`: an extent item that would reach this
/// size takes further references as keyed items.
pub(crate) fn max_extent_item_size(nodesize: usize) -> usize {
    ((nodesize - btree::HEADER_SIZE) >> 4) - LEAF_ITEM_SIZE
}

fn set_refs(body: &mut [u8], refs: u64) {
    body[0..8].copy_from_slice(&refs.to_le_bytes());
}

/// Which extent an operation addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// A tree block, by its skinny `METADATA_ITEM` key.
    TreeBlock { bytenr: u64, level: u8 },
    /// A data extent, by its `EXTENT_ITEM` key.
    Data { bytenr: u64, len: u64 },
}

impl Target {
    fn bytenr(self) -> u64 {
        match self {
            Target::TreeBlock { bytenr, .. } | Target::Data { bytenr, .. } => bytenr,
        }
    }

    fn key(self) -> BtrfsKey {
        match self {
            Target::TreeBlock { bytenr, level } => {
                BtrfsKey::new(bytenr, format::METADATA_ITEM_KEY, u64::from(level))
            }
            Target::Data { bytenr, len } => BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, len),
        }
    }
}

/// The result of dropping a reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dropped {
    /// Other references remain.
    Remaining,
    /// That was the last one: the extent item is gone from the overlay.
    Last,
}

/// A transaction's rewritten extent-tree reference state (see the module
/// docs). Cloned with the path-COW state it belongs to, so a rolled-back
/// operation rolls its reference changes back too.
#[derive(Clone, Debug, Default)]
pub(crate) struct RefOverlay {
    /// Extent items and keyed backref items this transaction rewrote:
    /// `Some(body)` replaces (or inserts), `None` deletes.
    items: BTreeMap<BtrfsKey, Option<Vec<u8>>>,
    /// `FULL_BACKREF` blocks whose children's parent refs this transaction
    /// moved onto their COW (`update_ref_for_cow`, `refs == 1`); only those
    /// may be freed.
    pub(crate) full_released: BTreeSet<u64>,
    /// The extent item of every tree block this overlay freed, as it stood
    /// just before its last reference went, for the pre-write audit.
    pub(crate) freed_bodies: BTreeMap<u64, Vec<u8>>,
}

impl RefOverlay {
    /// Fold `other` (another tree's overlay from the same transaction) in.
    /// Two trees of one transaction touching the same extent would each have
    /// decided from a view without the other's changes, so that is refused
    /// rather than guessed at.
    pub(crate) fn merge(&mut self, other: &RefOverlay) -> Result<(), FsError> {
        for (key, body) in &other.items {
            if self.items.insert(*key, body.clone()).is_some() {
                return Err(FsError::Unsupported);
            }
        }
        self.full_released
            .extend(other.full_released.iter().copied());
        for (addr, body) in &other.freed_bodies {
            self.freed_bodies.insert(*addr, body.clone());
        }
        Ok(())
    }

    /// The overlay as extent-tree edits: `(key, Some(body))` upserts and
    /// `(key, None)` deletes.
    pub(crate) fn edits(&self) -> impl Iterator<Item = (&BtrfsKey, &Option<Vec<u8>>)> {
        self.items.iter()
    }

    /// Forget whatever the overlay holds for `key` (the caller accounts for
    /// the item another way, e.g. a freed tree block's delete).
    pub(crate) fn forget(&mut self, key: &BtrfsKey) {
        self.items.remove(key);
    }

    /// Record a brand-new extent item.
    pub(crate) fn insert_new(&mut self, key: BtrfsKey, body: Vec<u8>) -> Result<(), FsError> {
        if matches!(self.items.get(&key), Some(Some(_))) {
            return Err(FsError::InvalidData);
        }
        self.items.insert(key, Some(body));
        Ok(())
    }

    /// The current body of `key`: the overlay's, else the committed tree's.
    pub(crate) async fn get<B: BlockDevice + 'static>(
        &self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        key: &BtrfsKey,
    ) -> Result<Option<Vec<u8>>, FsError> {
        match self.items.get(key) {
            Some(body) => Ok(body.clone()),
            None => btree::find_item(vol, extent_root, key).await,
        }
    }

    /// The extent item of a target, failing if it does not exist. A tree
    /// block recorded with a non-skinny `EXTENT_ITEM` is refused
    /// (`Unsupported`): every filesystem the writer accepts is skinny, and
    /// such a block would come from a conversion it does not model.
    async fn item<B: BlockDevice + 'static>(
        &self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        target: Target,
    ) -> Result<(BtrfsKey, Vec<u8>), FsError> {
        let key = target.key();
        if let Some(body) = self.get(vol, extent_root, &key).await? {
            if body.len() < EXTENT_ITEM_SIZE {
                return Err(FsError::InvalidData);
            }
            return Ok((key, body));
        }
        if let Target::TreeBlock { bytenr, .. } = target {
            let fat = BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, vol.nodesize() as u64);
            if self.get(vol, extent_root, &fat).await?.is_some() {
                return Err(FsError::Unsupported);
            }
        }
        Err(FsError::InvalidData)
    }

    /// `(refs, flags)` of a target extent (`btrfs_lookup_extent_info`).
    pub(crate) async fn info<B: BlockDevice + 'static>(
        &self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        target: Target,
    ) -> Result<(u64, u64), FsError> {
        let (_, body) = self.item(vol, extent_root, target).await?;
        Ok((le64(&body, 0)?, le64(&body, 16)?))
    }

    /// The current body of a target's extent item.
    pub(crate) async fn body<B: BlockDevice + 'static>(
        &self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        target: Target,
    ) -> Result<Vec<u8>, FsError> {
        Ok(self.item(vol, extent_root, target).await?.1)
    }

    /// Set `FULL_BACKREF` on a tree block (`btrfs_set_disk_extent_flags`).
    pub(crate) async fn set_full_backref<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        bytenr: u64,
        level: u8,
    ) -> Result<(), FsError> {
        let target = Target::TreeBlock { bytenr, level };
        let (key, mut body) = self.item(vol, extent_root, target).await?;
        let flags = le64(&body, 16)? | BLOCK_FLAG_FULL_BACKREF;
        body[16..24].copy_from_slice(&flags.to_le_bytes());
        self.items.insert(key, Some(body));
        Ok(())
    }

    /// The keyed item holding `kind` for `bytenr`, if any: `(key, body)`.
    /// Data refs are keyed by their hash with collisions probed upward
    /// (`insert_extent_data_ref`), so the matching one may sit a few offsets
    /// past the hash.
    /// Test hook: find the keyed data ref `(root, objectid, offset)` of
    /// `bytenr` in an overlay seeded with `(offset past the hash, body)`
    /// items; the matching item's distance past the hash.
    #[cfg(feature = "kernel-test")]
    pub(crate) async fn __test_find_data_ref<B: BlockDevice + 'static>(
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        bytenr: u64,
        (root, objectid, offset): (u64, u64, u64),
        seeded: &[(u64, Option<Vec<u8>>)],
    ) -> Result<Option<u64>, FsError> {
        let kind = RefKind::Data {
            root,
            objectid,
            offset,
        };
        let hash = kind.order();
        let mut overlay = RefOverlay::default();
        for (delta, body) in seeded {
            overlay.items.insert(
                BtrfsKey::new(bytenr, EXTENT_DATA_REF_KEY, hash.wrapping_add(*delta)),
                body.clone(),
            );
        }
        Ok(overlay
            .find_keyed(vol, extent_root, bytenr, kind)
            .await?
            .map(|(key, _)| key.offset.wrapping_sub(hash)))
    }

    async fn find_keyed<B: BlockDevice + 'static>(
        &self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        bytenr: u64,
        kind: RefKind,
    ) -> Result<Option<(BtrfsKey, Vec<u8>)>, FsError> {
        match kind {
            RefKind::Data {
                root,
                objectid,
                offset,
            } => {
                // Linux `lookup_extent_data_ref`: from the hash, scan every
                // EXTENT_DATA_REF item of the extent (collisions go to the
                // next free offset, and deletions can leave holes in a run),
                // the overlay's view of a key overriding the tree's.
                let matches = |body: &[u8]| -> Result<bool, FsError> {
                    Ok(body.len() >= 28
                        && le64(body, 0)? == root
                        && le64(body, 8)? == objectid
                        && le64(body, 16)? == offset)
                };
                let start = BtrfsKey::new(bytenr, EXTENT_DATA_REF_KEY, kind.order());
                let end = BtrfsKey::new(bytenr, EXTENT_DATA_REF_KEY, u64::MAX);
                for (key, body) in self.items.range(start..=end) {
                    if let Some(body) = body {
                        if matches(body)? {
                            return Ok(Some((*key, body.clone())));
                        }
                    }
                }
                let mut cursor = btree::Cursor::seek(vol, extent_root, &start).await?;
                while let Some((key, body)) = cursor.current()? {
                    if key.objectid != bytenr || key.item_type != EXTENT_DATA_REF_KEY {
                        break;
                    }
                    if !self.items.contains_key(&key) && matches(body)? {
                        return Ok(Some((key, body.to_vec())));
                    }
                    cursor.advance().await?;
                }
                Ok(None)
            }
            _ => {
                let key = BtrfsKey::new(bytenr, kind.type_byte(), kind.order());
                Ok(self
                    .get(vol, extent_root, &key)
                    .await?
                    .map(|body| (key, body)))
            }
        }
    }

    /// Add one reference (`btrfs_inc_extent_ref` / `insert_inline_extent_backref`
    /// / `insert_extent_backref`).
    pub(crate) async fn add<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        target: Target,
        kind: RefKind,
    ) -> Result<(), FsError> {
        let is_data = matches!(kind, RefKind::Data { .. } | RefKind::SharedData { .. });
        if is_data != matches!(target, Target::Data { .. }) {
            return Err(FsError::InvalidData);
        }
        let (key, mut body) = self.item(vol, extent_root, target).await?;
        let refs = le64(&body, 0)?;
        let next = refs.checked_add(1).ok_or(FsError::InvalidData)?;
        let keyed_exist = inline_count(&body, &key)? != refs;
        match find_inline(&body, &key, kind)? {
            Ok(at) => match kind {
                RefKind::Data { .. } => {
                    let c = le32(&body, at + 25)?
                        .checked_add(1)
                        .ok_or(FsError::InvalidData)?;
                    body[at + 25..at + 29].copy_from_slice(&c.to_le_bytes());
                }
                RefKind::SharedData { .. } => {
                    let c = le32(&body, at + 9)?
                        .checked_add(1)
                        .ok_or(FsError::InvalidData)?;
                    body[at + 9..at + 13].copy_from_slice(&c.to_le_bytes());
                }
                // One tree, one parent: a second identical tree ref is
                // corruption (Linux BUGs on it).
                _ => return Err(FsError::InvalidData),
            },
            Err(at) => {
                let keyed = self
                    .find_keyed(vol, extent_root, target.bytenr(), kind)
                    .await?;
                let too_big =
                    body.len() + kind.inline_size() >= max_extent_item_size(vol.nodesize());
                if keyed.is_some() || keyed_exist || too_big {
                    self.add_keyed(vol, extent_root, target.bytenr(), kind, keyed)
                        .await?;
                } else {
                    body.splice(at..at, kind.encode_inline());
                }
            }
        }
        set_refs(&mut body, next);
        self.items.insert(key, Some(body));
        Ok(())
    }

    async fn add_keyed<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        bytenr: u64,
        kind: RefKind,
        existing: Option<(BtrfsKey, Vec<u8>)>,
    ) -> Result<(), FsError> {
        match (kind, existing) {
            (RefKind::Tree { .. } | RefKind::SharedBlock { .. }, Some(_)) => {
                Err(FsError::InvalidData)
            }
            (RefKind::Tree { .. } | RefKind::SharedBlock { .. }, None) => {
                let key = BtrfsKey::new(bytenr, kind.type_byte(), kind.order());
                self.items.insert(key, Some(Vec::new()));
                Ok(())
            }
            (RefKind::Data { .. }, Some((key, mut body))) => {
                let c = le32(&body, 24)?
                    .checked_add(1)
                    .ok_or(FsError::InvalidData)?;
                body[24..28].copy_from_slice(&c.to_le_bytes());
                self.items.insert(key, Some(body));
                Ok(())
            }
            (RefKind::SharedData { .. }, Some((key, mut body))) => {
                let c = le32(&body, 0)?.checked_add(1).ok_or(FsError::InvalidData)?;
                body[0..4].copy_from_slice(&c.to_le_bytes());
                self.items.insert(key, Some(body));
                Ok(())
            }
            (
                RefKind::Data {
                    root,
                    objectid,
                    offset,
                },
                None,
            ) => {
                // Linux `insert_extent_data_ref`: the first free offset from
                // the hash.
                let hash = kind.order();
                for probe in 0..4096u64 {
                    let key = BtrfsKey::new(bytenr, EXTENT_DATA_REF_KEY, hash.wrapping_add(probe));
                    if self.get(vol, extent_root, &key).await?.is_none() {
                        let mut body = Vec::with_capacity(28);
                        body.extend_from_slice(&root.to_le_bytes());
                        body.extend_from_slice(&objectid.to_le_bytes());
                        body.extend_from_slice(&offset.to_le_bytes());
                        body.extend_from_slice(&1u32.to_le_bytes());
                        self.items.insert(key, Some(body));
                        return Ok(());
                    }
                }
                Err(FsError::Unsupported)
            }
            (RefKind::SharedData { parent }, None) => {
                let key = BtrfsKey::new(bytenr, SHARED_DATA_REF_KEY, parent);
                self.items.insert(key, Some(1u32.to_le_bytes().to_vec()));
                Ok(())
            }
        }
    }

    /// Drop one reference (`__btrfs_free_extent` short of freeing space).
    /// Dropping a reference that does not exist is corruption (`InvalidData`)
    /// and fails the transaction before anything is written.
    pub(crate) async fn drop_ref<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        extent_root: u64,
        target: Target,
        kind: RefKind,
    ) -> Result<Dropped, FsError> {
        let (key, mut body) = self.item(vol, extent_root, target).await?;
        let refs = le64(&body, 0)?;
        if refs == 0 {
            return Err(FsError::InvalidData);
        }
        match find_inline(&body, &key, kind)? {
            Ok(at) => {
                let (size, count) = inline_ref_shape(&body, at)?;
                if count > 1 {
                    let (off, next) = match kind {
                        RefKind::Data { .. } => (at + 25, count - 1),
                        _ => (at + 9, count - 1),
                    };
                    body[off..off + 4].copy_from_slice(&(next as u32).to_le_bytes());
                } else {
                    body.drain(at..at + size);
                }
            }
            Err(_) => {
                let (kkey, mut kbody) = self
                    .find_keyed(vol, extent_root, target.bytenr(), kind)
                    .await?
                    .ok_or(FsError::InvalidData)?;
                let count_at = match kind {
                    RefKind::Data { .. } => Some(24),
                    RefKind::SharedData { .. } => Some(0),
                    _ => None,
                };
                match count_at {
                    Some(off) if le32(&kbody, off)? > 1 => {
                        let c = le32(&kbody, off)? - 1;
                        kbody[off..off + 4].copy_from_slice(&c.to_le_bytes());
                        self.items.insert(kkey, Some(kbody));
                    }
                    _ => {
                        self.items.insert(kkey, None);
                    }
                }
            }
        }
        if refs == 1 {
            if inline_count(&body, &key)? != 0 {
                return Err(FsError::InvalidData);
            }
            self.items.insert(key, None);
            Ok(Dropped::Last)
        } else {
            set_refs(&mut body, refs - 1);
            self.items.insert(key, Some(body));
            Ok(Dropped::Remaining)
        }
    }
}

/// The references a tree block's contents hold (`__btrfs_mod_ref`): one per
/// child pointer of an internal node, one per regular/prealloc file extent of
/// a leaf (inline extents and holes reference nothing). With `full_backref`
/// they name `parent_addr` (`SHARED_*_REF`); otherwise tree `root`.
pub(crate) fn child_refs(
    buf: &[u8],
    parent_addr: u64,
    root: u64,
    full_backref: bool,
) -> Result<Vec<(Target, RefKind)>, FsError> {
    let n = btree::nritems(buf)? as usize;
    let lvl = btree::level(buf)?;
    let mut out = Vec::with_capacity(n);
    if lvl > 0 {
        for i in 0..n {
            let child = btree::internal_blockptr(buf, i)?;
            let kind = if full_backref {
                RefKind::SharedBlock {
                    parent: parent_addr,
                }
            } else {
                RefKind::Tree { root }
            };
            out.push((
                Target::TreeBlock {
                    bytenr: child,
                    level: lvl - 1,
                },
                kind,
            ));
        }
        return Ok(out);
    }
    for i in 0..n {
        let key = btree::leaf_item_key(buf, i)?;
        if key.item_type != format::EXTENT_DATA_KEY {
            continue;
        }
        let body = btree::leaf_item_data(buf, i)?;
        // `btrfs_file_extent_item`: type at 20; disk_bytenr, disk_num_bytes,
        // offset follow for regular and prealloc extents.
        let kind_byte = *body.get(20).ok_or(FsError::InvalidData)?;
        if kind_byte == 0 {
            continue; // inline
        }
        let disk_bytenr = le64(body, 21)?;
        if disk_bytenr == 0 {
            continue; // hole
        }
        let disk_len = le64(body, 29)?;
        let extent_offset = le64(body, 37)?;
        let kind = if full_backref {
            RefKind::SharedData {
                parent: parent_addr,
            }
        } else {
            RefKind::Data {
                root,
                objectid: key.objectid,
                offset: key.offset.wrapping_sub(extent_offset),
            }
        };
        out.push((
            Target::Data {
                bytenr: disk_bytenr,
                len: disk_len,
            },
            kind,
        ));
    }
    Ok(out)
}

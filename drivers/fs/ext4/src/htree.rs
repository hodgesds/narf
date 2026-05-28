//! ext4 HTREE directory index — re-exports the shared decoders
//! from `drivers/fs/ext2/htree.rs`.
//!
//! HTREE was introduced as an ext3 optional feature and became
//! effectively mandatory for ext4 deployments at scale (mkfs.ext4
//! sets `EXT4_FEATURE_COMPAT_DIR_INDEX`). The on-disk format is
//! identical between ext3 and ext4 — the dx_root, dx_node, and
//! dx_entry shapes match byte-for-byte — so this is a pure
//! re-export.
//!
//! The TEA hash function used for the index keys is the canonical
//! algorithm from `fs/ext4/hash.c`; the shared module implements
//! both the signed (`LEGACY` / `TEA`) and unsigned (`*_UNSIGNED`)
//! variants since e2fsprogs has shipped both depending on the
//! `mke2fs` version that built the volume.
//!
//! Sources:
//! - Linux `fs/ext4/namei.c` — `struct dx_root`, `dx_node`,
//!   `dx_entry`, `dx_probe`.
//! - Linux `fs/ext4/hash.c` — `__ext4fs_dirhash`, the TEA hash.
//! - Linux `include/uapi/linux/ext4_fs.h::DX_HASH_*` constants.

pub use narf_drivers_fs_ext2::htree::{
    hash_version, DxRoot, DxEntry, DirHash,
    DX_ROOT_INFO_OFF, DX_ROOT_HEAD_OFF, DX_ROOT_ENTRIES_OFF,
    DX_NODE_HEAD_OFF, DX_NODE_ENTRIES_OFF,
    dx_node_head, dx_node_entry,
    dx_find_entry_root, dx_find_entry_node,
    name_hash,
};

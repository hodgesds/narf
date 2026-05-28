//! ext4 directory entries — re-exports the shared decoder from
//! `drivers/fs/ext2/dir.rs`.
//!
//! ext4 inherits ext2's dirent format unchanged — the only
//! difference is that ext4 dirents almost always have `file_type`
//! filled in (the `FILETYPE` incompat bit is on by default), where
//! ext2 left the field zero on rev-0 volumes. The decoder accepts
//! either layout because the field is a single byte that's safe to
//! read regardless.
//!
//! Sources:
//! - Linux `fs/ext4/dir.c` — `ext4_readdir`, `ext4_dx_readdir`.
//! - Linux `fs/ext4/ext4.h::struct ext4_dir_entry_2` — the
//!   "filetype-byte" dirent variant (`s_feature_incompat::FILETYPE`).
//! - Linux `include/uapi/linux/ext4_fs.h::EXT4_FT_*` — the
//!   file-type discriminator.

pub use narf_drivers_fs_ext2::dir::{ftype, DirEntry, parse_entry};

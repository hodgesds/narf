//! JBD2, the ext3/ext4 journal: the shared implementation in
//! `drivers/fs/ext2/src/journal.rs` (the on-disk format, superblock
//! validation and Linux's three-pass recovery), under the ext4 crate's name.
//! The recovery and journal-load tests are in
//! `drivers/fs/ext2/src/journal_tests.rs`.

pub use narf_drivers_fs_ext2::journal::{
    block_type, feature, tag_flag, IoFuture, Journal, JournalError, JournalIo, JournalSuperblock,
    RecoveryInfo, JBD2_MAGIC_NUMBER, JBD2_MIN_JOURNAL_BLOCKS,
};

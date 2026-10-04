//! Byte-built ext2 images for kernel tests in this crate and in the syscall
//! layer. Not used by the driver itself.

use alloc::vec;
use alloc::vec::Vec;

use super::dir::ftype;

/// Block size of every image built here.
pub const BLOCK_SIZE: usize = 1024;
/// Inode number of the regular file in [`hard_link_image`].
pub const FILE_INO: u32 = 12;
/// First data block of the regular file in [`hard_link_image`]; its data
/// occupies consecutive direct blocks from here.
pub const FILE_FIRST_BLOCK: u32 = 24;
/// Most file bytes [`hard_link_image`] can hold (twelve direct blocks).
pub const MAX_FILE_BYTES: usize = 12 * BLOCK_SIZE;

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn set_bit(bitmap: &mut [u8], bit: usize) {
    bitmap[bit / 8] |= 1 << (bit % 8);
}

/// A one-group, 1 KiB-block ext2 volume whose root directory names ONE
/// regular file (inode [`FILE_INO`], `i_links_count` 2) twice: `data` and
/// `link` — a hard link, the way distro images ship them. The file holds
/// `file_data` (at most [`MAX_FILE_BYTES`]) in direct blocks starting at
/// [`FILE_FIRST_BLOCK`]. Free block/inode counts are real, so writes that
/// allocate work.
///
/// Layout: 0 boot, 1 superblock, 2 group descriptors, 3 block bitmap,
/// 4 inode bitmap, 5..=8 inode table (32 × 128-byte inodes), 9 root
/// directory, 24.. file data.
pub fn hard_link_image(file_data: &[u8]) -> Vec<u8> {
    const TOTAL_BLOCKS: u32 = 256;
    const INODES: u32 = 32;
    const INODE_SIZE: usize = 128;
    assert!(file_data.len() <= MAX_FILE_BYTES, "test file too large");
    let bs = BLOCK_SIZE;
    let mut img = vec![0u8; bs * TOTAL_BLOCKS as usize];
    let data_blocks = file_data.len().div_ceil(bs);

    // Used blocks of the group (which starts at block 1): 1..=9 metadata +
    // root directory, then the file's data blocks.
    let used_blocks = 9 + data_blocks as u32;
    let free_blocks = TOTAL_BLOCKS - 1 - used_blocks;
    let used_inodes = 12u32; // 1..=11 reserved, 12 the file

    // ── Superblock ──
    {
        let sb = &mut img[1024..2048];
        put_u32(sb, 0, INODES);
        put_u32(sb, 4, TOTAL_BLOCKS);
        put_u32(sb, 12, free_blocks); // s_free_blocks_count
        put_u32(sb, 16, INODES - used_inodes); // s_free_inodes_count
        put_u32(sb, 20, 1); // s_first_data_block (1 KiB blocks)
        put_u32(sb, 24, 0); // s_log_block_size → 1024
        put_u32(sb, 32, TOTAL_BLOCKS); // blocks_per_group
        put_u32(sb, 40, INODES); // inodes_per_group
        put_u16(sb, 56, 0xEF53);
        put_u32(sb, 76, 1); // rev 1
        put_u32(sb, 84, 11); // s_first_ino
        put_u16(sb, 88, INODE_SIZE as u16);
    }
    // ── Group descriptor ──
    let gdt = 2 * bs;
    put_u32(&mut img, gdt, 3);
    put_u32(&mut img, gdt + 4, 4);
    put_u32(&mut img, gdt + 8, 5);
    put_u16(&mut img, gdt + 12, free_blocks as u16);
    put_u16(&mut img, gdt + 14, (INODES - used_inodes) as u16);
    put_u16(&mut img, gdt + 16, 1);
    // ── Bitmaps (block bit N = block N + s_first_data_block) ──
    {
        let bitmap = &mut img[3 * bs..4 * bs];
        for block in 1..=9usize {
            set_bit(bitmap, block - 1);
        }
        for i in 0..data_blocks {
            set_bit(bitmap, FILE_FIRST_BLOCK as usize + i - 1);
        }
        // Blocks past the end of the volume are permanently "used".
        for bit in (TOTAL_BLOCKS as usize - 1)..(bs * 8) {
            set_bit(bitmap, bit);
        }
    }
    {
        let bitmap = &mut img[4 * bs..5 * bs];
        for ino in 1..=used_inodes as usize {
            set_bit(bitmap, ino - 1);
        }
        for bit in INODES as usize..(bs * 8) {
            set_bit(bitmap, bit);
        }
    }
    // ── Inodes ──
    let itab = 5 * bs;
    let root = itab + INODE_SIZE; // inode 2
    put_u16(&mut img, root, 0x4000 | 0o755);
    put_u32(&mut img, root + 4, bs as u32);
    put_u16(&mut img, root + 26, 2);
    put_u32(&mut img, root + 28, (bs / 512) as u32);
    put_u32(&mut img, root + 40, 9);
    let file = itab + (FILE_INO as usize - 1) * INODE_SIZE;
    put_u16(&mut img, file, 0x8000 | 0o644);
    put_u32(&mut img, file + 4, file_data.len() as u32);
    put_u16(&mut img, file + 26, 2); // two names
    put_u32(&mut img, file + 28, (data_blocks * bs / 512) as u32);
    for i in 0..data_blocks {
        put_u32(&mut img, file + 40 + i * 4, FILE_FIRST_BLOCK + i as u32);
    }
    // ── Root directory: ".", "..", "data", "link" ──
    let dir = 9 * bs;
    let mut cursor = 0usize;
    let mut entry = |img: &mut Vec<u8>, ino: u32, name: &[u8], kind: u8, last: bool| {
        let off = dir + cursor;
        let rec_len = if last {
            bs - cursor
        } else {
            (8 + name.len()).div_ceil(4) * 4
        };
        put_u32(img, off, ino);
        put_u16(img, off + 4, rec_len as u16);
        img[off + 6] = name.len() as u8;
        img[off + 7] = kind;
        img[off + 8..off + 8 + name.len()].copy_from_slice(name);
        cursor += rec_len;
    };
    entry(&mut img, 2, b".", ftype::DIR, false);
    entry(&mut img, 2, b"..", ftype::DIR, false);
    entry(&mut img, FILE_INO, b"data", ftype::REGULAR, false);
    entry(&mut img, FILE_INO, b"link", ftype::REGULAR, true);
    // ── File data ──
    let start = FILE_FIRST_BLOCK as usize * bs;
    img[start..start + file_data.len()].copy_from_slice(file_data);
    img
}

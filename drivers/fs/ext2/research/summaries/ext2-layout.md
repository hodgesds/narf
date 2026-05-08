# Analysis: ext2 On-Disk Layout

**Sources:**
- Card, Ts'o, Tweedie. _Design and Implementation of the Second
  Extended Filesystem_. <https://web.mit.edu/tytso/www/linux/ext2intro.html>
- Rusling, _The Second Extended File System: Internal Layout_
  (kernelnewbies.org).
- OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

## Volume layout

An ext2 volume is divided into **block groups**, each containing a
fixed run of blocks. The first 1024 bytes of the volume are reserved
for the boot record and are unused by ext2 itself. Group 0 begins at
byte 0, but the meaningful data — the superblock — starts at byte
1024.

Each group's contents (in order):

1. (Group 0 only) Superblock (1 block, but only 1024 bytes used).
2. Block group descriptor table (one or more blocks, replicated in
   group 0 with classic non-sparse layouts; sparse-superblock
   variants only replicate in groups 0, 1, 3, 5, 7 …).
3. Block bitmap (1 block).
4. Inode bitmap (1 block).
5. Inode table (`s_inode_size * s_inodes_per_group / blocksize`
   blocks).
6. Data blocks (the rest of the group).

## Superblock fields used by this driver

The fields the driver reads from the superblock — all little-endian:

| offset | size | name                  | meaning                              |
| -----: | ---: | :-------------------- | :----------------------------------- |
|      0 |    4 | `s_inodes_count`      | total inodes in the volume           |
|      4 |    4 | `s_blocks_count`      | total blocks in the volume           |
|     20 |    4 | `s_first_data_block`  | block-no of group 0's superblock     |
|     24 |    4 | `s_log_block_size`    | block size = 1024 << this            |
|     32 |    4 | `s_blocks_per_group`  | blocks per block group               |
|     40 |    4 | `s_inodes_per_group`  | inodes per block group               |
|     56 |    2 | `s_magic`             | must be `0xEF53`                     |
|     76 |    4 | `s_rev_level`         | 0 = good-old, 1 = dynamic            |
|     88 |    4 | `s_inode_size`        | inode size (bytes); rev_level >= 1   |

Block size is `1024 << s_log_block_size`. Inode size on rev-0 volumes
is fixed at 128; on rev-1+ volumes it's `s_inode_size`.

## Block group descriptor

Each descriptor is 32 bytes; the fields the driver uses:

| offset | size | name                  | meaning                          |
| -----: | ---: | :-------------------- | :------------------------------- |
|      0 |    4 | `bg_block_bitmap`     | block holding block bitmap       |
|      4 |    4 | `bg_inode_bitmap`     | block holding inode bitmap       |
|      8 |    4 | `bg_inode_table`      | first block of inode table       |
|     12 |    2 | `bg_free_blocks_count`| free-blocks accounting           |
|     14 |    2 | `bg_free_inodes_count`| free-inodes accounting           |
|     16 |    2 | `bg_used_dirs_count`  | directory accounting             |

The descriptor table starts at block `s_first_data_block + 1`.

## Inode

The on-disk inode is 128 bytes (rev-0) or `s_inode_size` bytes
(rev-1+). The fields this driver reads:

| offset | size | name             | meaning                                 |
| -----: | ---: | :--------------- | :-------------------------------------- |
|      0 |    2 | `i_mode`         | file type + perms                       |
|      4 |    4 | `i_size`         | file size (low 32 bits)                 |
|     28 |    4 | `i_blocks`       | 512-byte sectors held by this inode     |
|     40 |   60 | `i_block[15]`    | block pointers — 12 direct + 1+1+1     |
|    104 |    4 | `i_generation`   | (unused here)                           |

`i_block[12]` is the single-indirect pointer, `i_block[13]` the
double-indirect, `i_block[14]` the triple-indirect.

## Directory entry

Variable-length, four-byte aligned. Each entry starts on a
four-byte boundary; the `rec_len` field is what advances the cursor.

| offset | size | name        | meaning                                      |
| -----: | ---: | :---------- | :------------------------------------------- |
|      0 |    4 | `inode`     | inode number (0 = unused slot)               |
|      4 |    2 | `rec_len`   | total bytes occupied by this dirent          |
|      6 |    1 | `name_len`  | name length in bytes                         |
|      7 |    1 | `file_type` | rev-1+ entries — 0 unknown, 1 file, 2 dir … |
|      8 |  ≤255 | `name[]`   | UTF-8 name, NOT null-terminated              |

Iteration stops when the cursor passes the directory's `i_size`.

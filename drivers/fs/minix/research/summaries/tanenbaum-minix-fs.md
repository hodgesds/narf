# Tanenbaum — MINIX filesystem layout (clean-room notes)

Distilled from *Operating Systems: Design and Implementation*
(Tanenbaum, 1987 / 3rd ed. 2006) and *Modern Operating Systems*
(Tanenbaum & Bos, 4th ed. 2014). No code consulted.

## Volume layout

A MINIX volume is a sequence of fixed-size blocks. The block size
is an integer multiple of 1024 bytes (V1/V2 always = 1024; V3 may
be 1024 / 2048 / 4096). Region order:

```
block 0          boot block (signed image, always 1024 bytes)
block 1          superblock (also 1024 bytes; lives at byte
                 offset 1024 unconditionally regardless of
                 block size)
block 2..        inode bitmap, s_imap_blocks blocks
                 zone bitmap,  s_zmap_blocks blocks
                 inode table   (size = ceil(s_ninodes * sz) / bs)
                 data zones    starting at s_firstdatazone
```

## Superblock fields used

- `s_ninodes`        — total number of inodes (V1 u16; V2/V3 u32 via `s_zones`).
- `s_imap_blocks`    — inode bitmap size in blocks.
- `s_zmap_blocks`    — zone bitmap size in blocks.
- `s_firstdatazone`  — first zone of the data region.
- `s_log_zone_size`  — log2 of (zone_size / block_size). Always 0
                       in practice; we still respect the field.
- `s_max_size`       — max file size, advisory.
- `s_magic`          — version + name-length discriminator.
- `s_block_size`     — V3 only; explicit block size in bytes.

## Inode layout

V1 (`d1_inode`, 32 bytes):
```
i_mode    u16
i_uid     u16
i_size    u32
i_time    u32
i_gid     u8
i_nlinks  u8
i_zone    u16[9]  // 7 direct, 1 indirect, 1 double-indirect
```

V2 / V3 (`d2_inode`, 64 bytes):
```
i_mode    u16
i_nlinks  u16
i_uid     u16
i_gid     u16
i_size    u32
i_atime   u32
i_mtime   u32
i_ctime   u32
i_zone    u32[10] // 7 direct, 1 ind, 1 dbl-ind, 1 tri-ind
```

## Zone indexing

`block_in_file` → zone number is a tree:

- 0..6           : `i_zone[0..7]`             (direct)
- 7..7+ZP_PER_Z  : `i_zone[7] -> u32[ZP]`     (single indirect)
- next ZP*ZP     : `i_zone[8] -> u32[ZP][ZP]` (double indirect)
- next ZP*ZP*ZP  : `i_zone[9] -> u32[ZP^3]`   (triple, V2/V3 only)

Where `ZP = block_size / sizeof(zone_ptr)`. A zero zone pointer is
a hole (sparse file). For our read-only first cut a hole reads
back as zeros.

## Directory entries

Fixed-size, packed:
```
d_ino   u16
d_name  char[N]   // N = 14 (short) or 30 (long), magic-controlled
```
A zero `d_ino` marks an unused slot (do NOT stop scanning — the
slot may be reused). Names end at the first NUL or at byte N.

## Root inode

Root is **inode #1**. Inode #0 is reserved (never used as a real
file inode in MINIX; the bitmap also reserves it).

## Magic table

```
0x137F  V1, 14-byte name
0x138F  V1, 30-byte name
0x2468  V2, 14-byte name
0x2478  V2, 30-byte name
0x4D5A  V3                         // V3 always uses 60-byte names
```

The lower byte of the V1/V2 magics flips between 0x7F/0x8F (V1) or
0x68/0x78 (V2) as the long-name discriminator.

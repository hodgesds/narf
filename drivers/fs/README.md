# drivers/fs — Filesystem drivers

Filesystem drivers: each crate implements one on-disk (or network)
filesystem over the block layer and plugs into NARF's `filesystem/`
VFS as a persistent, block-backed filesystem. Each child crate has its
own README with the details.

| crate | what it is |
|---|---|
| [`9p/`](9p/README.md) | Clean-room 9P2000 protocol driver (with 9P2000.u Unix extensions), async transaction manager over a generic `P9Transport`. |
| [`btrfs/`](btrfs/README.md) | Clean-room read-write btrfs: Linux-interoperable COW file and namespace mutations, all four checksum types, compressed reads, SINGLE/DUP and RAID0/1/1C3/1C4/10/5/6 profiles. |
| [`exfat/`](exfat/README.md) | Clean-room exFAT driver for large removable media (SDXC cards, USB sticks) where the FAT32 4 GiB file-size ceiling is a problem. |
| [`ext2/`](ext2/README.md) | Clean-room ext2 driver: mount via the superblock, block-group descriptors, inode lookup, variable-length directory entries, direct/indirect block pointers. |
| [`ext4/`](ext4/README.md) | ext4 driver, the flagship layout of the Linux ext family and the default root filesystem of most Linux distributions. |
| [`fat/`](fat/README.md) | Clean-room FAT driver: FAT12/16/32 with automatic version detection, UTF-16 long file names, FAT32 FSInfo free-cluster tracking, async I/O. |
| [`iso9660/`](iso9660/README.md) | Clean-room ISO 9660 (ECMA-119) driver for CD-ROM, DVD, and bootable installer media. |
| [`minix/`](minix/README.md) | Clean-room MINIX driver; read-only first cut (V1/V2/V3 superblock detection, inode lookup, directory walk, file reads). |
| [`squashfs/`](squashfs/README.md) | Read-only SquashFS 4.0 driver for Linux-produced immutable images; decodes zlib and LZ4. |
| [`udf/`](udf/README.md) | Clean-room UDF (Universal Disk Format) driver; read-only mount for DVD-Video, BD-ROM, and archival media. |

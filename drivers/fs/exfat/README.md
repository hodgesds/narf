# drivers/fs/exfat — exFAT On-Disk Filesystem Driver

A clean-room driver for the exFAT (Extended FAT) on-disk filesystem, the
layout Microsoft defined for large removable media — SDXC cards, USB sticks,
and other flash where the classic FAT32 4 GiB file-size ceiling is a problem.
It plugs into NARF's `filesystem/` VFS as a persistent, block-backed
filesystem: the VFS owns path resolution, the mount tree, and the
capability-addressed node abstraction, and this crate realizes that contract
over a block device supplied by `block/` and `drivers/storage`. It is
discovered and attached through `drivers/runtime` like the other on-disk
drivers.

The driver is organized along the structure of the exFAT format itself. The
`boot` module parses the boot sector and derives the volume geometry (sector
and cluster sizes, FAT and cluster-heap offsets, root-directory start). `fat`
walks the single File Allocation Table that chains clusters together. `volume`
is the sector/cluster I/O layer over the block device and also carries the
write-side primitives — sector and cluster writes, the §7.1 bitmap cluster
allocator, free-chain reclamation, and FAT-entry updates. `dir` understands
exFAT's directory-entry sets: the primary file entry plus its stream-extension
and file-name secondary entries, including the §6.3.3 set-checksum logic used
to validate and finalize an entry group. `upcase` loads and applies the
on-disk up-case table (and its §7.2.3 checksum) that drives exFAT's
case-insensitive-but-case-preserving name comparison. `node` is the bridge to
the VFS, presenting mounted files and directories as VFS nodes with the
file-read and directory-walk operations.

The consumption side — mount, directory walk, and file read — is the working
path. Write support is partially scaffolded: the allocation, checksum, and
FAT-mutation primitives exist in `volume`/`dir`/`upcase`, but the full
directory-entry edit path (creating a new entry group, updating the enclosing
primary's cluster counts, and scanning the parent cluster chain for a free
slot) is not yet wired into the VFS mutator operations.

Every layout detail, magic value, and algorithm traces to the public Microsoft
exFAT specification (opened for implementation in 2019) and the OSDev Wiki
narrative; no GPL/LGPL exFAT source was consulted. The crate is `#![no_std]`
and hardware-independent above the block-device interface, so it runs the same
on x86_64 and aarch64.

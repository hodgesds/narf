# drivers/fs/iso9660 — ISO 9660 (ECMA-119) Optical Media Driver

A clean-room driver for ISO 9660, the standard on-disc filesystem of CD-ROM,
DVD, and bootable installer media, defined normatively by ECMA-119. It plugs
into NARF's `filesystem/` VFS as a persistent, block-backed filesystem,
realizing the VFS node/`FileOps`/`DirOps` contract over a block device from
`block/` and `drivers/storage` and attaching through `drivers/runtime`. Its
primary role in the kernel is reading optical and installer images — exactly
the media a system boots and installs from.

ISO 9660 is read-only by design: discs are authored offline by tools such as
mkisofs and xorriso, and there is no in-place mutation model, so every
mutating VFS operation returns a read-only error. The layout is built around a
fixed 2048-byte logical sector (ECMA-119 §6.1.2); the driver requires the
underlying block device to report a 2048-byte logical block size for a 1:1
sector mapping and rejects the mount otherwise. The modules mirror the
standard's structure. `descriptor` parses the volume-descriptor region that
begins at sector 16 (the "CD001" primary volume descriptor and friends).
`volume` is the mounted-volume object: it caches the primary volume
descriptor, owns a per-mount DMA scratch buffer minted as a capability at
mount time, and performs capability-bound sector I/O. `dir` walks on-disc
directory records, and `node` presents files and directories to the VFS,
carrying each entry's extent location and length plus its cached stat.

Every magic byte and algorithm traces to the gratis ECMA-119 (3rd edition)
PDF and the OSDev Wiki narrative; no GPL Linux `fs/isofs`, libcdio, GRUB, or
FreeBSD cd9660 source was consulted. The crate is `#![no_std]` and
hardware-independent above the block-device interface, so it behaves
identically on x86_64 and aarch64.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 4 (needed for bootable installer media).

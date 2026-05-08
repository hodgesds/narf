# narf-drivers-fs-fat

Clean room FAT filesystem driver for NARF.

## Features

- **FAT12/16/32 Support**: Automatic version detection based on cluster counts.
- **LFN (Long File Names)**: Full support for UTF-16 long names with checksum validation.
- **FAT32 FSInfo**: Optimized free cluster tracking via the FSInfo sector.
- **Async I/O**: Fully integrated with NARF's async `BlockDevice` and `DmaBuffer`.
- **Clean Room**: Derived strictly from public Microsoft and UEFI specifications.

## Status: Stage 4 (Complete)

- [x] Volume Mounting
- [x] BPB / FAT / Directory Structure Parsing
- [x] Cluster Chain Walking
- [x] Directory Scanning (SFN/LFN)
- [x] File Reading
- [x] File/Directory Creation
- [x] File Writing
- [x] File Truncation (Shrink/Grow)
- [x] Object Deletion (unlink/rmdir)
- [x] Object Renaming
- [x] Timestamp Updates

## References

- [Microsoft FAT Gen1 Specification (v1.03)](https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf)
- [UEFI Specification (v2.10, §13.3)](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format)
- [OSDev Wiki (FAT)](https://wiki.osdev.org/FAT)

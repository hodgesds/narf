# Specification: FAT Filesystem Driver

## 1. Purpose & scope

This driver provides a clean-room implementation of the FAT (File Allocation Table) filesystem family (FAT12, FAT16, FAT32) for NARF.

- **Scope:** Read/write access to FAT volumes, support for long file names (LFN), integration with NARF VFS and Page Cache.
- **Out of Scope:** exFAT support (separate driver), on-disk repair (fsck), compression/encryption.

## 2. Assumptions

- The underlying block device provides `BlockCap` with 512-byte or 4096-byte sector support.
- The VFS handles path resolution and capability derivation; this driver handles the on-disk format mapping.
- Memory for metadata and data buffers is managed via NARF's DMA/Page Cache abstractions.

## 3. Public interface

The driver implements the `FileSystem` trait from `narf-filesystem`.

### Key Structs

- `FatFileSystem`: Root structure representing a mounted FAT volume.
- `FatNode`: Implementation of `VNode` for FAT files and directories.

## 4. Invariants

- **FAT Chain Integrity:** No cluster chain shall contain cycles. Any detected cycle results in an `EIO`.
- **Atomic Metadata Updates:** Directory entry updates and FAT chain allocations must be ordered to prevent data loss on crash (as much as the format allows).
- **Concurrency:** Multiple readers allowed; single writer per file/directory (gated by VFS caps).

## 5. Architecture notes

- **Async-First:** All I/O operations are async and integrated with the NARF executor.
- **Zero-Copy:** Directory entries are parsed directly from DMA-mapped sectors when possible.
- **LFN Handling:** Long file names are supported using the "hidden" directory entry sequence described in the Microsoft spec.

## 6. Dependencies

- `narf-block`: For low-level block I/O.
- `narf-filesystem`: For VFS traits and types.
- `narf-lib`: For basic primitives.

## 7. Stage assignment

- **Stage 4:** "Compatibility" - FAT is required for interoperability with external media and UEFI boot partitions.

## 8. Open questions

- **Write Caching:** Should we implement a write-through or write-back policy for the FAT table? (Initial implementation: write-through for safety).
- **Character Encoding:** How to handle UTF-16 in LFNs relative to NARF's UTF-8 internal strings?

## References

This implementation is derived solely from the following public documentation:

1. [Microsoft FAT Gen1 Specification (v1.03)](https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf)
2. [UEFI Specification (v2.10, §13.3)](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format)
3. [OSDev Wiki (FAT)](https://wiki.osdev.org/FAT)

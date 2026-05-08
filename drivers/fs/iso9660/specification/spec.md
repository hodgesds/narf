# Specification: ISO 9660 Filesystem Driver

## 1. Purpose & scope

This driver provides a clean-room implementation of the ISO 9660 (ECMA-119) filesystem standard for NARF.

- **Scope:** Read-only access to ISO 9660 volumes, support for Joliet and Rock Ridge extensions, integration with NARF VFS.
- **Out of Scope:** Multi-session discs (initial implementation), CD-audio, UDF support (separate driver).

## 2. Assumptions

- Underlying block device provides `BlockCap` with 2048-byte sector support (standard for ISO 9660).
- The system recognizes the "CD001" signature at sector 16.

## 3. Public interface

The driver implements the `FileSystem` trait from `narf-filesystem`.

### Key Structs

- `Iso9660FileSystem`: Root structure representing a mounted ISO volume.
- `Iso9660Node`: Implementation of `VNode` (FileOps/DirOps) for ISO files and directories.

## 4. Invariants

- **Read-Only:** All mutation operations (write, create, unlink) return `FsError::ReadOnly` or `Unsupported`.
- **Descriptor Sequence:** The driver must correctly follow the Volume Descriptor sequence until the Volume Descriptor Set Terminator is reached.

## 5. Architecture notes

- **Async-First:** Leverages NARF's async I/O for non-blocking directory traversal.
- **Extension Discovery:** The driver automatically detects Joliet/Rock Ridge extensions during mount via SVD and System Use fields.

## 6. Dependencies

- `narf-block`: For block I/O.
- `narf-filesystem`: For VFS traits.
- `narf-lib`: For base primitives.

## 7. Stage assignment

- **Stage 4:** Necessary for bootable installer media.

## 8. Open questions

- **Suspense (Rock Ridge):** Should we implement full RRIP parsing in the first wave? (Target: basic RRIP support for filenames).

## References

This implementation is derived solely from the following public documentation:

1. [ECMA-119 Standard (ISO 9660)](https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf)
2. [OSDev Wiki: ISO 9660](https://wiki.osdev.org/ISO_9660)

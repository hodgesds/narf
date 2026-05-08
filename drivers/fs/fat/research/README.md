# Research: FAT Filesystem

Clean-room implementation references for the FAT filesystem family (FAT12, FAT16, FAT32).

## Primary Sources

1. **Microsoft FAT Gen1 Specification**
   - Title: FAT: FAT12, FAT16, and FAT32 File System Specification
   - Version: 1.03
   - Date: December 6, 2000
   - URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf
   - Role: Definitive reference for on-disk structures and cluster calculation logic.

2. **UEFI Specification**
   - Version: 2.10
   - Section: 13.3 File System Format (FAT)
   - URL: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format
   - Role: Modern interpretation and requirements for UEFI-compatible FAT implementations.

3. **OSDev Wiki: FAT**
   - URL: https://wiki.osdev.org/FAT
   - Role: Community-vetted edge cases, common pitfalls, and architectural patterns for OS implementations.

## Secondary Sources

- **The Design and Implementation of the 4.4BSD Operating System** (McKusick et al.)
  - Section: 7.9 MS-DOS File System
  - URL: https://www.mckusick.com/books/bsdbook.html
  - Role: Structural inspiration for integration into a VFS.

## Summaries

- [summaries/microsoft-fat-gen1.md](summaries/microsoft-fat-gen1.md) - Analysis of cluster chaining and BPB fields.

# Research: ISO 9660 (ECMA-119)

Clean-room implementation references for the ISO 9660 filesystem standard.

## Primary Sources

1. **ECMA-119 Standard**
   - Title: Volume and File Structure of CD-ROM for Information Interchange
   - Edition: 3rd Edition (December 2017)
   - URL: https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf
   - Role: Definitive standard for volume descriptors, directory records, and path tables.

2. **OSDev Wiki: ISO 9660**
   - URL: https://wiki.osdev.org/ISO_9660
   - Role: Technical overview of Volume Descriptors and Directory Record layout.

## Common Extensions

- **Joliet (Microsoft)**
  - URL: https://web.archive.org/web/20161028135848/https://www.microsoft.com/en-us/download/details.aspx?id=30491
  - Role: Long filename and Unicode support.

- **Rock Ridge (IEEE P1282)**
  - Role: POSIX semantics (permissions, symlinks, owners).

## Summaries

- [summaries/volume-descriptors.md](summaries/volume-descriptors.md) - Analysis of VVD, PVD, and SVD sequences.

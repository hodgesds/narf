# Research: UDF (ECMA-167 / OSTA UDF 2.60)

Clean-room implementation references for the UDF (Universal Disk
Format) filesystem standard.

## Primary Sources

1. **ECMA-167 Standard**
   - Title: Volume and File Structure of Read-Only and Write-Once
     and Rewritable Media using Non-Sequential Recording for
     Information Interchange.
   - Edition: 3rd Edition (June 1997).
   - URL: https://ecma-international.org/publications-and-standards/standards/ecma-167/
   - Role: Definitive standard for the Anchor Volume Descriptor
     Pointer, Volume Descriptor Sequence, Logical Volume
     Descriptor, Partition Descriptor, File Set Descriptor,
     Information Control Blocks (File Entry / Extended File
     Entry), Allocation Descriptors (`short_ad` / `long_ad` /
     `ext_ad`), and File Identifier Descriptors.

2. **OSTA UDF 2.60 Specification**
   - Title: Universal Disk Format Specification (Revision 2.60).
   - URL: https://www.osta.org/specs/index.htm
   - Role: Disc-format profiles layered on top of ECMA-167. Adds
     the Logical Volume Integrity Descriptor format, Domain
     identifier conventions, the recommended AVDP locations, and
     the OSTA-specific Implementation Use payloads.

3. **ECMA-119 (ISO 9660)**
   - Role: Bridge format context. The first 32 sectors of every
     UDF disc may carry an ISO 9660 PVD so legacy systems can read
     a single ISO directory; the UDF descriptors live further into
     the medium. Already implemented in `drivers/fs/iso9660`.

## Summaries

- [summaries/descriptors.md](summaries/descriptors.md) — Anchor
  Volume Descriptor Pointer, Volume Descriptor Sequence, and
  Descriptor Tag header layout.
- [summaries/icb-fid.md](summaries/icb-fid.md) — ICB / File Entry
  / File Identifier Descriptor walk.

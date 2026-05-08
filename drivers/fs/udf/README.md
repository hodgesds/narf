# narf-drivers-fs-udf

Clean room UDF (Universal Disk Format) filesystem driver for NARF.

## Features

- **Read-only mount** for UDF volumes (DVD-Video, BD-ROM, archival media).
- **Anchor Volume Descriptor Pointer** lookup at sector 256 / last / last-256.
- **Volume Descriptor Sequence walk** — Primary VD, Partition Descriptor,
  Logical Volume Descriptor, Unallocated Space Descriptor, Terminating
  Descriptor.
- **File Set Descriptor** decode → root directory ICB.
- **Information Control Block** (File Entry / Extended File Entry)
  decode.
- **File Identifier Descriptors** (UDF directory format) walk.
- **`long_ad`** allocation descriptors as the default extent format
  (most common on DVD/BD authoring).
- **Async I/O** via NARF's cap-bound DMA layer (one
  `Cap<DmaBuffer, Write>` minted at mount, derived to `Read` per op).
- **Clean Room** — derived strictly from public ECMA-167 / OSTA UDF
  specifications. No GPL/LGPL UDF code consulted.

## Status: Stage 4 (read-only MVP)

- [x] AVDP recognition + VDS walk
- [x] LVD decode (Type-1 partition map only)
- [x] File Set Descriptor decode
- [x] ICB / File Entry / Extended File Entry decode
- [x] FID directory walk
- [x] long_ad / short_ad extent decode
- [x] File data read via single contiguous extent
- [ ] Sparable / virtual / metadata partition maps (deferred)
- [ ] Translation Tables / Named Streams (deferred)
- [ ] Unicode CS0 / CS1 long-name decode (ASCII fast path only)
- [ ] Write paths (deferred — UDF on read-only media)

## References

- [ECMA-167 (3rd edition, June 1997)](https://ecma-international.org/publications-and-standards/standards/ecma-167/)
  — base normative spec ("Volume and File Structure of Read-Only and
  Write-Once and Rewritable Media using Non-Sequential Recording for
  Information Interchange").
- [OSTA UDF 2.60 specification](https://www.osta.org/specs/index.htm)
  — disc-format profiles layered on top of ECMA-167.
- ECMA-119 (ISO 9660) for the Bridge format context (already
  implemented in `drivers/fs/iso9660`).

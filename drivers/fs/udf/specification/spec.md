# Specification: UDF Filesystem Driver

## 1. Purpose & scope

This driver provides a clean-room implementation of the UDF
(Universal Disk Format) standard for NARF. UDF is the native FS
of DVD-Video, BD-ROM, and most read-only optical media; it is
specified by ECMA-167 (the base) and OSTA UDF (the
profile-on-top).

- **Scope:** Read-only access to UDF volumes (the dominant mode);
  Type-1 partition maps; long_ad / short_ad allocation descriptors;
  CS0 ASCII fast-path for file identifiers; integration with the
  NARF VFS via `FsInstance` / `DirOps` / `FileOps`.
- **Out of scope (MVP):** Writes. Sparable / virtual / metadata
  partition maps. Translation Tables. Named Streams. Full Unicode
  CS0 / CS1 decode beyond the 8-bit ASCII subset.

## 2. Assumptions

- Underlying block device reports `logical_block_size() == 2048`
  (the standard UDF sector size for optical media). Devices with a
  smaller LBS need an aggregator wrapper.
- The on-disc image carries an Anchor Volume Descriptor Pointer at
  sector 256 (the canonical OSTA UDF location). The fall-back AVDP
  positions (last sector, last - 256) are recognised at decode time
  but the test fixtures use only sector 256.

## 3. Public interface

The driver implements `narf_filesystem::FsInstance`, with per-node
`FileOps` and `DirOps`.

### Key Structs

- `UdfVolume<B: BlockDevice>`: mounted volume. Owns the cached
  Logical Volume Descriptor, Partition Descriptor, File Set
  Descriptor, root ICB extent, `DomainId`, and the per-mount
  registered DMA scratch buffer. Constructed via
  `UdfVolume::mount(device, domain) -> Arc<Self>`.
- `UdfNode<B: BlockDevice>`: combined file/dir node returned by
  `root()` / `lookup_async` / `lookup_dir_async`. Carries the
  on-disc extent LBA + length + cached `Stat`.

### DMA / cap-bound I/O

A single `Cap<DmaBuffer, Write>` is minted at `mount()` via
`narf_io::register_with_cap` and stored on the volume. Every
sector op derives a `Read` cap from it (no `Cap::bootstrap()` in
hot paths). Sector size is fixed at 2048; the driver requires the
underlying `BlockDevice::logical_block_size()` to be 2048 and
rejects the mount with `FsError::Unsupported` otherwise.

## 4. Invariants

- **Read-Only:** All mutation operations (write, create, unlink)
  return `FsError::ReadOnly` or `Unsupported`.
- **Descriptor tag validation:** Every UDF descriptor begins with a
  16-byte Descriptor Tag (ECMA-167 §3/7.2). Mount validates the tag
  identifier on each descriptor; the test fixture also fills in
  TagChecksum + DescriptorCRC + DescriptorCRCLength so a future
  hardening pass can require those.

## 5. Architecture notes

- **AVDP lookup (ECMA-167 §3/8.4.2.1, OSTA UDF 2.60 §2.2.3):** the
  Anchor Volume Descriptor Pointer is at sector 256; if absent, try
  the last sector and (last - 256).
- **VDS walk (ECMA-167 §3/8.4.2):** Each AVDP carries a Main VDS
  extent (location + length in bytes). Walk the descriptors stored
  in that extent until a Terminating Descriptor (tag 8) appears.
- **Type-1 partition maps only:** ECMA-167 §3/10.7.2. Type-2
  variants (sparable, virtual, metadata) cover rewritable / packet
  media we do not yet target.
- **Allocation descriptors (ECMA-167 §4/14.14):** `long_ad` (16
  bytes — `extent_length` + `LB_addr` + `ImplementationUse`) is
  the default. `short_ad` (8 bytes — `extent_length` + LBN) is
  recognised in the test surface for completeness.
- **FIDs (ECMA-167 §4/14.4):** A directory is a stream of File
  Identifier Descriptors. Each FID has a Descriptor Tag, an `icb`
  (long_ad pointing at the child's File Entry), file
  characteristics (incl. "is directory"), and a length-prefixed
  identifier. FIDs pad to a 4-byte boundary.

## 5a. Deferred extensions

- **Writes:** UDF is overwhelmingly used on read-only media; the
  write path requires a far larger Logical Volume Integrity
  Descriptor + space-bitmap surface that this MVP skips.
- **Sparable / Virtual / Metadata partition maps (UDF 2.60 §2.2.10):**
  These are the rewritable / packet-media partition map types. The
  MVP rejects mounts whose LVD partition map is not Type-1.
- **Unicode CS0 / CS1 names (UDF 2.60 §2.1.1):** UDF identifiers
  are stored either as 8-bit ("compression ID 8") or 16-bit
  ("compression ID 16") CS0 strings. The MVP decodes the 8-bit form
  directly to ASCII and returns 16-bit identifiers as their
  raw-byte fallback (every byte mapped to a placeholder `?` if
  outside ASCII). Real Unicode is a Stage-5 hardening pass.
- **Translation Tables / Named Streams:** Out of scope for the MVP.

## 6. Dependencies

- `narf-block`: For block I/O.
- `narf-filesystem`: For VFS traits.
- `narf-lib`: For base primitives.
- `narf-io`: For cap-bound DMA buffers.
- `narf-capabilities`: For `Cap<DmaBuffer, Write/Read>`.

## 7. Stage assignment

- **Stage 4:** Necessary for DVD / BD installer media support.

## 8. Open questions

- **AVDP fallback locations:** Should we exhaust all three OSTA
  positions on every mount, or accept the first that decodes?
  (MVP: try sector 256, then last, then last - 256, in that order.)
- **Multi-extent files:** ECMA-167 allows a File Entry to list
  several extents in its allocation descriptor area. The MVP walks
  every long_ad in the AD area and treats them as sequential.

## References

This implementation is derived solely from the following public
documentation:

1. [ECMA-167 — Volume and File Structure of Read-Only and Write-Once
   and Rewritable Media using Non-Sequential Recording for
   Information Interchange (3rd edition, June 1997)](https://ecma-international.org/publications-and-standards/standards/ecma-167/)
2. [OSTA UDF 2.60 specification](https://www.osta.org/specs/index.htm)
3. ECMA-119 (ISO 9660) for the Bridge format context.

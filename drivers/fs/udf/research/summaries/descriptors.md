# Summary: UDF Descriptors

## Descriptor Tag (ECMA-167 §3/7.2)

Every UDF descriptor on the medium begins with a 16-byte
Descriptor Tag:

```
offset  size  field
   0      2   TagIdentifier        (u16, LE)
   2      2   DescriptorVersion    (u16, LE; usually 2 or 3)
   4      1   TagChecksum          (u8 — sum of bytes 0..16 except byte 4, mod 256)
   5      1   Reserved             (zero)
   6      2   TagSerialNumber      (u16, LE)
   8      2   DescriptorCRC        (u16, LE — CCITT-CRC over the body)
  10      2   DescriptorCRCLength  (u16, LE)
  12      4   TagLocation          (u32, LE — sector containing this descriptor)
```

Recognised TagIdentifier values used by this driver:

| ID | Descriptor                      | Section            |
|----|---------------------------------|--------------------|
| 1  | Primary Volume Descriptor       | ECMA-167 §3/10.1   |
| 2  | Anchor Volume Descriptor Pointer| ECMA-167 §3/10.2   |
| 3  | Volume Descriptor Pointer       | ECMA-167 §3/10.3   |
| 4  | Implementation Use VD           | ECMA-167 §3/10.4   |
| 5  | Partition Descriptor            | ECMA-167 §3/10.5   |
| 6  | Logical Volume Descriptor       | ECMA-167 §3/10.6   |
| 7  | Unallocated Space Descriptor    | ECMA-167 §3/10.8   |
| 8  | Terminating Descriptor          | ECMA-167 §3/10.9   |
| 9  | Logical Volume Integrity Desc   | ECMA-167 §3/10.10  |
| 256 | File Set Descriptor            | ECMA-167 §4/14.1   |
| 257 | File Identifier Descriptor     | ECMA-167 §4/14.4   |
| 261 | File Entry                     | ECMA-167 §4/14.9   |
| 266 | Extended File Entry            | ECMA-167 §4/14.17  |

## Anchor Volume Descriptor Pointer (ECMA-167 §3/10.2)

Three canonical positions per OSTA UDF 2.60 §2.2.3:

1. Sector 256 (preferred — present on every UDF disc).
2. Last sector of the volume.
3. Last sector minus 256.

Body layout after the 16-byte tag:

```
offset  size  field
   16     8   MainVolumeDescriptorSequenceExtent  (extent_ad)
   24     8   ReserveVolumeDescriptorSequenceExtent (extent_ad)
   32   480   Reserved
```

`extent_ad` (ECMA-167 §3/7.1) is `extent_length: u32 (bytes)` +
`extent_location: u32 (LBA)`.

## Volume Descriptor Sequence walk

Starting at the Main VDS extent's `extent_location`, read
sector-aligned descriptors until either:

- A Terminating Descriptor (tag 8) is read.
- The Main VDS extent is exhausted (`extent_length` bytes
  consumed).

Capture along the way:

- The first Primary Volume Descriptor (tag 1) — for volume
  identifier surface only.
- The first Logical Volume Descriptor (tag 6) — yields the File
  Set Descriptor location and the partition map array.
- The first Partition Descriptor (tag 5) — yields the partition
  starting LBA.

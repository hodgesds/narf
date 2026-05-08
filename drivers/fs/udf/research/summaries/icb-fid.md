# Summary: ICB and File Identifier Descriptor

## Information Control Block (ECMA-167 §4/14.6)

UDF stores per-file metadata in an "ICB" — a sector containing
either a File Entry (tag 261) or an Extended File Entry (tag 266).
The owning Logical Volume names the ICB's logical block address;
allocation descriptors elsewhere reach files by `(partition_ref,
LBN)` pairs.

Both File Entry shapes carry an `icb_tag` block right after the
Descriptor Tag (ECMA-167 §4/14.6):

```
offset   size  field
   16    4    PriorRecordedNumberOfDirectEntries  (u32)
   20    2    StrategyType                        (u16; usually 4 = "default")
   22    2    StrategyParameter                   (u16)
   24    2    NumberOfEntries                     (u16; usually 1)
   26    1    Reserved                            (zero)
   27    1    FileType                            (u8)
   28    6    ParentICBLocation                   (lb_addr)
   34    2    Flags                               (u16)
```

`FileType` byte values used by this driver:

| Value | Meaning                       | Section          |
|------:|-------------------------------|------------------|
|     4 | Directory                     | ECMA-167 §4/14.6.6|
|     5 | Regular file                  | ECMA-167 §4/14.6.6|
|    10 | Symbolic link                 | ECMA-167 §4/14.6.6|

## File Entry layout (ECMA-167 §4/14.9)

After the icb_tag (offset 36):

```
offset  size  field
   36    4   Uid
   40    4   Gid
   44    4   Permissions
   48    2   FileLinkCount
   50    1   RecordFormat
   51    1   RecordDisplayAttributes
   52    4   RecordLength
   56    8   InformationLength       (u64 — file body byte length)
   64    8   LogicalBlocksRecorded   (u64)
   72   12   AccessTime              (timestamp)
   84   12   ModificationTime        (timestamp)
   96   12   AttributeTime           (timestamp)
  108    4   Checkpoint
  112   16   ExtendedAttributeICB    (long_ad)
  128   32   ImplementationIdentifier
  160    8   UniqueId                (u64)
  168    4   LengthOfExtendedAttributes (L_EA)
  172    4   LengthOfAllocationDescriptors (L_AD)
  176  L_EA Extended Attributes
  176+L_EA  L_AD Allocation Descriptors
```

The Extended File Entry is the same shape with extra timestamp
+ stream-related fields between offset 168 and the AD area
(see ECMA-167 §4/14.17 — the relevant offsets used here are
`InformationLength` at 56 and the equivalent L_EA / L_AD just
before the AD area).

## Allocation Descriptors (ECMA-167 §4/14.14)

`short_ad` (8 bytes) — same partition implied:

```
0  4  ExtentLength       (u32; high 2 bits = type)
4  4  ExtentPosition     (u32; LBN within the partition)
```

`long_ad` (16 bytes) — full partition reference:

```
0  4  ExtentLength       (u32; high 2 bits = type)
4  4  LBN                (u32)
8  2  PartitionRef       (u16)
10 6  ImplementationUse  (or AD UseFlags)
```

`extent_length` high 2 bits: 0 = recorded + allocated, 1 =
allocated but unrecorded, 2 = unallocated, 3 = next extent
pointer (continuation).

## File Identifier Descriptor (ECMA-167 §4/14.4)

A directory's data is a stream of FIDs. Each FID:

```
offset  size  field
   0    16   Descriptor Tag (TagId = 257)
  16     2   FileVersionNumber           (u16; usually 1)
  18     1   FileCharacteristics         (bits — 0x02 = directory,
                                                 0x04 = deleted,
                                                 0x08 = parent,
                                                 0x10 = metadata)
  19     1   LengthOfFileIdentifier  (L_FI)
  20    16   ICB                         (long_ad)
  36     2   LengthOfImplementationUse   (L_IU)
  38   L_IU ImplementationUse
  ...    L_FI File Identifier (preceded by 1-byte compression ID;
                                actual chars start at offset
                                `38 + L_IU + 1`).
  ...        Padding to a 4-byte boundary.
```

CompressionID:

| ID | Meaning                                      |
|----|----------------------------------------------|
|  8 | Each subsequent byte is a single 8-bit char  |
| 16 | Each subsequent pair is a UTF-16BE codepoint |

The MVP decoder honours ID 8 directly (treats bytes as ASCII)
and substitutes a `?` placeholder for any non-ASCII byte under
ID 16; full UCS-2 decoding is deferred per the spec doc.

## Total FID length on disc

```
record_length = round_up_4( 38 + L_IU + 1 + L_FI )
```

(when L_FI > 0 — otherwise the compression-ID byte is also
absent and `record_length = round_up_4(38 + L_IU)`).

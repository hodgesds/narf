# Analysis: Microsoft FAT Gen1 Specification

**Source:** FAT: FAT12, FAT16, and FAT32 File System Specification (v1.03)  
**Date:** December 6, 2000  
**URL:** https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

## Key Learnings

### 1. BIOS Parameter Block (BPB)
The BPB is located in the first sector (LBA 0). It contains essential volume parameters. The specification distinguishes between the "Standard" BPB (common to all versions) and the version-specific extensions.

- **Standard BPB (Offset 0-35):** Includes sector size, sectors per cluster, reserved sectors, and number of FATs.
- **FAT12/16 Extension (Offset 36-61):** Includes drive number, boot signature, volume ID, and labels.
- **FAT32 Extension (Offset 36-90):** Includes FAT size (32-bit), root cluster, FSInfo sector location, and backup boot sector.

### 2. FAT Version Detection
The definitive method to determine the FAT version is by calculating the number of clusters in the data region (page 14):

```
RootDirSectors = ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec;
DataSectors = TotalSectors - (BPB_RsvdSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors);
CountOfClusters = DataSectors / BPB_SecPerClus;

if(CountOfClusters < 4085) {
   // Volume is FAT12
} else if(CountOfClusters < 65525) {
   // Volume is FAT16
} else {
   // Volume is FAT32
}
```

### 3. File Allocation Table (FAT) Logic
- **FAT12:** 12 bits per entry. Complex bit-packing where every 3 bytes hold 2 entries.
- **FAT16:** 16 bits per entry (2 bytes).
- **FAT32:** 32 bits per entry, but only the low 28 bits are used. High 4 bits are reserved and must be preserved during writes.

### 4. Directory Structure
- Each entry is exactly 32 bytes.
- **SFN (Short File Name):** 8.3 format. Base and extension are space-padded. Case is typically converted to uppercase.
- **LFN (Long File Name):** Utilizes a sequence of "hidden" entries with the `ATTR_LONG_NAME` bitmask. These entries contain UTF-16 characters and a checksum of the associated SFN.

### 5. FAT32 FSInfo Sector
Located at the sector index specified in `BPB_FSInfo`. It contains hints for the next free cluster and total free clusters to avoid a full FAT scan during allocation. Must be synchronized during write operations.

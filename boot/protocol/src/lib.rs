//! Byte-oriented boot image validation and handoff construction.
//!
//! This crate has no kernel or firmware dependencies. Addresses remain integers;
//! parsing a valid image does not authorize dereferencing its load addresses.

#![no_std]
#![forbid(unsafe_code)]

pub const PAGE_SIZE: u64 = 4096;
pub const MULTIBOOT2_MAGIC: u32 = 0x36d7_6289;
pub const MAX_MEMORY_REGIONS: usize = 64;
pub const CMDLINE_CAP: usize = 2048;
pub const BUNDLE_MAGIC: &[u8; 16] = b"NARF_EFI_BUNDLE\0";
pub const BUNDLE_HEADER_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidElf,
    UnsupportedElf,
    InvalidSegment,
    Overlap,
    Overflow,
    InvalidMemoryMap,
    TooManyRegions,
    BufferTooSmall,
    InvalidCommandLine,
    InvalidModule,
    InvalidBundle,
}

/// The `.narf` PE section is a versioned, inspectable container. The outer PE
/// signature authenticates this section; SHA-256 digests detect input/binding
/// mistakes and are verified by the loader before parsing the kernel ELF.
#[derive(Debug)]
pub struct BootBundle<'a> {
    pub kernel: &'a [u8],
    pub initramfs: &'a [u8],
    pub cmdline: &'a str,
    pub hashes: [[u8; 32]; 3],
}

impl<'a> BootBundle<'a> {
    pub fn parse(source: &'a [u8]) -> Result<Self, Error> {
        if source.get(..16) != Some(BUNDLE_MAGIC)
            || u32_at(source, 16)? != 1
            || u32_at(source, 20)? != BUNDLE_HEADER_SIZE as u32
        {
            return Err(Error::InvalidBundle);
        }
        let total = usize::try_from(u64_at(source, 24)?).map_err(|_| Error::Overflow)?;
        if total > source.len()
            || total < BUNDLE_HEADER_SIZE
            || source[176..BUNDLE_HEADER_SIZE]
                .iter()
                .any(|&byte| byte != 0)
        {
            return Err(Error::InvalidBundle);
        }
        let mut parts = [&[][..]; 3];
        let mut cursor = BUNDLE_HEADER_SIZE;
        for (i, part) in parts.iter_mut().enumerate() {
            let offset =
                usize::try_from(u64_at(source, 32 + i * 16)?).map_err(|_| Error::Overflow)?;
            let length =
                usize::try_from(u64_at(source, 40 + i * 16)?).map_err(|_| Error::Overflow)?;
            if offset != cursor {
                return Err(Error::InvalidBundle);
            }
            let end = offset.checked_add(length).ok_or(Error::Overflow)?;
            *part = source
                .get(offset..end)
                .filter(|_| end <= total)
                .ok_or(Error::InvalidBundle)?;
            cursor = end.checked_add(7).ok_or(Error::Overflow)? & !7;
        }
        if cursor != total
            || parts[0].is_empty()
            || !parts[1].starts_with(b"070701")
            || parts[2].len() >= CMDLINE_CAP
            || parts[2].contains(&0)
        {
            return Err(Error::InvalidBundle);
        }
        Ok(Self {
            kernel: parts[0],
            initramfs: parts[1],
            cmdline: core::str::from_utf8(parts[2]).map_err(|_| Error::InvalidCommandLine)?,
            hashes: [bytes(source, 80)?, bytes(source, 112)?, bytes(source, 144)?],
        })
    }
}

fn bytes<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Overflow)?;
    input
        .get(offset..end)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}

fn u16_at(input: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes(input, offset)?))
}

fn u32_at(input: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes(input, offset)?))
}

fn u64_at(input: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(bytes(input, offset)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub offset: usize,
    pub physical: u64,
    pub file_size: usize,
    pub memory_size: usize,
    pub flags: u32,
}

/// Validated fixed-address x86_64 ELF64 image with a physical 32-bit entry.
#[derive(Debug)]
pub struct ElfImage<'a> {
    source: &'a [u8],
    table: usize,
    count: usize,
    pub entry: u32,
    /// Page-aligned reservation containing every PT_LOAD, including BSS.
    pub load_start: u64,
    pub load_end: u64,
}

impl<'a> ElfImage<'a> {
    pub fn parse(source: &'a [u8]) -> Result<Self, Error> {
        if source.get(..7) != Some(b"\x7fELF\x02\x01\x01") {
            return Err(Error::InvalidElf);
        }
        if u16_at(source, 16)? != 2 || u16_at(source, 18)? != 62 || u32_at(source, 20)? != 1 {
            return Err(Error::UnsupportedElf);
        }
        if u16_at(source, 52)? != 64 || u16_at(source, 54)? != 56 {
            return Err(Error::UnsupportedElf);
        }
        let entry = u32::try_from(u64_at(source, 24)?).map_err(|_| Error::UnsupportedElf)?;
        let table = usize::try_from(u64_at(source, 32)?).map_err(|_| Error::Overflow)?;
        let count = usize::from(u16_at(source, 56)?);
        if count == 0 || count > 64 || table < 64 {
            return Err(Error::UnsupportedElf);
        }
        let table_end = table
            .checked_add(count.checked_mul(56).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        if table_end > source.len() {
            return Err(Error::Truncated);
        }
        let mut image = Self {
            source,
            table,
            count,
            entry,
            load_start: u64::MAX,
            load_end: 0,
        };
        let mut executable_entry = false;
        for i in 0..count {
            let Some(segment) = image.segment(i)? else {
                continue;
            };
            if segment.memory_size == 0 {
                return Err(Error::InvalidSegment);
            }
            let file_end = segment
                .offset
                .checked_add(segment.file_size)
                .ok_or(Error::Overflow)?;
            let end = segment
                .physical
                .checked_add(segment.memory_size as u64)
                .ok_or(Error::Overflow)?;
            if segment.file_size > segment.memory_size
                || file_end > source.len()
                || segment.physical < 0x10_0000
                || end > 0x1_0000_0000
            {
                return Err(Error::InvalidSegment);
            }
            let ph = table + i * 56;
            let alignment = u64_at(source, ph + 48)?;
            if alignment > 1
                && (!alignment.is_power_of_two()
                    || segment.physical % alignment != segment.offset as u64 % alignment
                    || u64_at(source, ph + 16)? % alignment != segment.offset as u64 % alignment)
            {
                return Err(Error::InvalidSegment);
            }
            for j in 0..i {
                if let Some(other) = image.segment(j)? {
                    let other_end = other
                        .physical
                        .checked_add(other.memory_size as u64)
                        .ok_or(Error::Overflow)?;
                    if segment.physical < other_end && other.physical < end {
                        return Err(Error::Overlap);
                    }
                }
            }
            // The EFI bridge uses a physical entry, not the higher-half Rust
            // entry. Require file-backed executable bytes with matching VMA.
            let entry64 = u64::from(entry);
            executable_entry |= segment.flags & 1 != 0
                && entry64 >= segment.physical
                && entry64 < segment.physical + segment.file_size as u64
                && u64_at(source, ph + 16)? == segment.physical;
            image.load_start = image.load_start.min(segment.physical & !(PAGE_SIZE - 1));
            image.load_end = image
                .load_end
                .max(end.checked_add(PAGE_SIZE - 1).ok_or(Error::Overflow)? & !(PAGE_SIZE - 1));
        }
        if !executable_entry
            || image.load_end <= image.load_start
            || image.load_end - image.load_start > 1024 * 1024 * 1024
        {
            return Err(Error::InvalidSegment);
        }
        Ok(image)
    }

    fn segment(&self, index: usize) -> Result<Option<Segment>, Error> {
        let ph = self.table + index * 56;
        if u32_at(self.source, ph)? != 1 {
            return Ok(None);
        }
        Ok(Some(Segment {
            flags: u32_at(self.source, ph + 4)?,
            offset: usize::try_from(u64_at(self.source, ph + 8)?).map_err(|_| Error::Overflow)?,
            physical: u64_at(self.source, ph + 24)?,
            file_size: usize::try_from(u64_at(self.source, ph + 32)?)
                .map_err(|_| Error::Overflow)?,
            memory_size: usize::try_from(u64_at(self.source, ph + 40)?)
                .map_err(|_| Error::Overflow)?,
        }))
    }

    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        // All program headers were validated by parse.
        (0..self.count).filter_map(|i| self.segment(i).ok().flatten())
    }

    pub fn segment_bytes(&self, segment: Segment) -> Option<&'a [u8]> {
        self.source
            .get(segment.offset..segment.offset.checked_add(segment.file_size)?)
    }
}

/// Multiboot2 memory kind: 1 usable, 2 reserved, 3 ACPI reclaimable, 4 NVS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub kind: u32,
}

/// Sort, validate, and merge adjacent regions of the same kind. No advertised
/// region may disappear to satisfy the kernel's bounded memory-map storage.
pub fn normalize_memory_map(
    input: &mut [MemoryRegion],
    out: &mut [MemoryRegion],
) -> Result<usize, Error> {
    input.sort_unstable_by_key(|region| region.start);
    let mut count = 0;
    for region in input.iter().copied() {
        let end = region
            .start
            .checked_add(region.len)
            .ok_or(Error::Overflow)?;
        if region.len == 0 || !(1..=4).contains(&region.kind) {
            return Err(Error::InvalidMemoryMap);
        }
        if count != 0 {
            let previous: &mut MemoryRegion = &mut out[count - 1];
            let previous_end = previous
                .start
                .checked_add(previous.len)
                .ok_or(Error::Overflow)?;
            if region.start < previous_end {
                return Err(Error::Overlap);
            }
            if region.start == previous_end && region.kind == previous.kind {
                previous.len = end - previous.start;
                continue;
            }
        }
        let slot = out.get_mut(count).ok_or(Error::TooManyRegions)?;
        *slot = region;
        count += 1;
    }
    if !out[..count]
        .iter()
        .any(|region| region.kind == 1 && region.len >= 1024 * 1024)
    {
        return Err(Error::InvalidMemoryMap);
    }
    Ok(count)
}

/// Builds a little-endian Multiboot2 information block in caller-owned storage.
/// The caller must place that storage on an eight-byte-aligned physical address
/// below 4 GiB and keep it reserved while the kernel consumes its tags.
#[derive(Debug)]
pub struct Multiboot2Builder<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> Multiboot2Builder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Result<Self, Error> {
        buffer.get_mut(..8).ok_or(Error::BufferTooSmall)?.fill(0);
        Ok(Self { buffer, cursor: 8 })
    }

    fn reserve_tag(&mut self, kind: u32, payload_len: usize) -> Result<&mut [u8], Error> {
        let size = payload_len.checked_add(8).ok_or(Error::Overflow)?;
        let size32 = u32::try_from(size).map_err(|_| Error::Overflow)?;
        let padded = size.checked_add(7).ok_or(Error::Overflow)? & !7;
        let end = self.cursor.checked_add(padded).ok_or(Error::Overflow)?;
        let tag = self
            .buffer
            .get_mut(self.cursor..end)
            .ok_or(Error::BufferTooSmall)?;
        tag.fill(0);
        tag[..4].copy_from_slice(&kind.to_le_bytes());
        tag[4..8].copy_from_slice(&size32.to_le_bytes());
        self.cursor = end;
        Ok(&mut tag[8..size])
    }

    /// Add a protocol-defined tag (for example ACPI, GOP, or SMBIOS).
    pub fn tag(&mut self, kind: u32, payload: &[u8]) -> Result<(), Error> {
        if kind == 0 {
            return Err(Error::InvalidModule);
        }
        self.reserve_tag(kind, payload.len())?
            .copy_from_slice(payload);
        Ok(())
    }

    pub fn command_line(&mut self, command_line: &str) -> Result<(), Error> {
        if command_line.len() >= CMDLINE_CAP || command_line.as_bytes().contains(&0) {
            return Err(Error::InvalidCommandLine);
        }
        let payload = self.reserve_tag(1, command_line.len() + 1)?;
        payload[..command_line.len()].copy_from_slice(command_line.as_bytes());
        Ok(())
    }

    pub fn initramfs(&mut self, start: u64, len: u64) -> Result<(), Error> {
        let end = start.checked_add(len).ok_or(Error::Overflow)?;
        if len == 0 || start % PAGE_SIZE != 0 || end > u32::MAX as u64 {
            return Err(Error::InvalidModule);
        }
        let payload = self.reserve_tag(3, 18)?;
        payload[..4].copy_from_slice(&(start as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&(end as u32).to_le_bytes());
        payload[8..].copy_from_slice(b"initramfs\0");
        Ok(())
    }

    pub fn memory_map(&mut self, map: &[MemoryRegion]) -> Result<(), Error> {
        if map.is_empty() || map.len() > MAX_MEMORY_REGIONS {
            return Err(Error::TooManyRegions);
        }
        let payload = self.reserve_tag(6, 8 + map.len() * 24)?;
        payload[..4].copy_from_slice(&24u32.to_le_bytes());
        for (entry, region) in payload[8..].chunks_exact_mut(24).zip(map) {
            entry[..8].copy_from_slice(&region.start.to_le_bytes());
            entry[8..16].copy_from_slice(&region.len.to_le_bytes());
            entry[16..20].copy_from_slice(&region.kind.to_le_bytes());
        }
        Ok(())
    }

    /// Retain the complete final EFI map, including descriptor attributes and
    /// extension bytes. Runtime-service consumers must use this map rather
    /// than reconstructing it from the coalesced Multiboot2 map.
    pub fn efi_memory_map(
        &mut self,
        descriptor_size: u32,
        version: u32,
        map: &[u8],
    ) -> Result<(), Error> {
        if descriptor_size < 40 || map.is_empty() || map.len() % descriptor_size as usize != 0 {
            return Err(Error::InvalidMemoryMap);
        }
        let payload =
            self.reserve_tag(17, 8usize.checked_add(map.len()).ok_or(Error::Overflow)?)?;
        payload[..4].copy_from_slice(&descriptor_size.to_le_bytes());
        payload[4..8].copy_from_slice(&version.to_le_bytes());
        payload[8..].copy_from_slice(map);
        Ok(())
    }

    pub fn finish(mut self) -> Result<usize, Error> {
        self.reserve_tag(0, 0)?;
        let size = u32::try_from(self.cursor).map_err(|_| Error::Overflow)?;
        self.buffer[..4].copy_from_slice(&size.to_le_bytes());
        Ok(self.cursor)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    fn elf() -> Vec<u8> {
        let mut image = vec![0; 0x2000];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[24..32].copy_from_slice(&0x100000u64.to_le_bytes());
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[52..54].copy_from_slice(&64u16.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());
        image[64..68].copy_from_slice(&1u32.to_le_bytes());
        image[68..72].copy_from_slice(&5u32.to_le_bytes());
        image[72..80].copy_from_slice(&0x1000u64.to_le_bytes());
        image[80..88].copy_from_slice(&0x100000u64.to_le_bytes());
        image[88..96].copy_from_slice(&0x100000u64.to_le_bytes());
        image[96..104].copy_from_slice(&16u64.to_le_bytes());
        image[104..112].copy_from_slice(&8192u64.to_le_bytes());
        image[112..120].copy_from_slice(&4096u64.to_le_bytes());
        image
    }

    #[test]
    fn elf_reserves_bss_and_requires_file_backed_physical_entry() {
        let mut source = elf();
        let parsed = ElfImage::parse(&source).unwrap();
        assert_eq!(
            (parsed.entry, parsed.load_start, parsed.load_end),
            (0x100000, 0x100000, 0x102000)
        );
        assert_eq!(parsed.segments().count(), 1);
        source[24..32].copy_from_slice(&0x100010u64.to_le_bytes());
        assert!(matches!(
            ElfImage::parse(&source),
            Err(Error::InvalidSegment)
        ));
        source[24..32].copy_from_slice(&0xffffffff80000000u64.to_le_bytes());
        assert!(matches!(
            ElfImage::parse(&source),
            Err(Error::UnsupportedElf)
        ));
    }

    #[test]
    fn elf_rejects_truncation_overflow_overlap_and_wrong_arch() {
        let original = elf();
        for len in 0..120 {
            assert!(ElfImage::parse(&original[..len]).is_err());
        }
        let mut source = original.clone();
        source[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert!(matches!(
            ElfImage::parse(&source),
            Err(Error::UnsupportedElf)
        ));
        let mut source = original.clone();
        source[104..112].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ElfImage::parse(&source).is_err());
        let mut source = original.clone();
        source[96..104].copy_from_slice(&8193u64.to_le_bytes());
        assert!(matches!(
            ElfImage::parse(&source),
            Err(Error::InvalidSegment)
        ));
        let mut source = original;
        source.copy_within(64..120, 120);
        source[56..58].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(ElfImage::parse(&source), Err(Error::Overlap)));
    }

    #[test]
    fn map_merges_only_adjacent_equal_regions_and_rejects_overflow() {
        let mut regions = [
            MemoryRegion {
                start: 0x200000,
                len: 0x100000,
                kind: 1,
            },
            MemoryRegion {
                start: 0,
                len: 0x100000,
                kind: 2,
            },
            MemoryRegion {
                start: 0x100000,
                len: 0x100000,
                kind: 1,
            },
        ];
        let mut out = [MemoryRegion::default(); 3];
        assert_eq!(normalize_memory_map(&mut regions, &mut out), Ok(2));
        assert_eq!(
            out[1],
            MemoryRegion {
                start: 0x100000,
                len: 0x200000,
                kind: 1
            }
        );
        assert_eq!(
            normalize_memory_map(&mut regions, &mut out[..1]),
            Err(Error::TooManyRegions)
        );
        regions[2].start = 0x180000;
        assert_eq!(
            normalize_memory_map(&mut regions, &mut out),
            Err(Error::Overlap)
        );
        regions[2].start = u64::MAX;
        assert_eq!(
            normalize_memory_map(&mut regions, &mut out),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn handoff_has_literal_wire_tags_and_nul_terminated_names() {
        let mut buffer = [0xa5; 256];
        let mut builder = Multiboot2Builder::new(&mut buffer).unwrap();
        builder.command_line("quiet").unwrap();
        builder.initramfs(0x200000, 4096).unwrap();
        let count = builder.finish().unwrap();
        assert_eq!(count, 64);
        assert_eq!(&buffer[..8], &[64, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&buffer[8..16], &[1, 0, 0, 0, 14, 0, 0, 0]);
        assert_eq!(&buffer[16..24], b"quiet\0\0\0");
        assert_eq!(&buffer[24..32], &[3, 0, 0, 0, 26, 0, 0, 0]);
        assert_eq!(&buffer[32..40], &[0, 0, 32, 0, 0, 16, 32, 0]);
        assert_eq!(&buffer[40..50], b"initramfs\0");
        assert_eq!(&buffer[56..64], &[0, 0, 0, 0, 8, 0, 0, 0]);
    }

    #[test]
    fn handoff_rejects_truncation_command_line_loss_and_unrepresentable_modules() {
        let mut buffer = [0; 64];
        let mut builder = Multiboot2Builder::new(&mut buffer).unwrap();
        assert_eq!(
            builder.command_line("foo\0bar"),
            Err(Error::InvalidCommandLine)
        );
        assert_eq!(
            builder.command_line(&"x".repeat(CMDLINE_CAP)),
            Err(Error::InvalidCommandLine)
        );
        assert_eq!(
            builder.initramfs(0x1_0000_0000, 4096),
            Err(Error::InvalidModule)
        );
        assert_eq!(builder.initramfs(1, 4096), Err(Error::InvalidModule));
        assert_eq!(builder.initramfs(4096, 0), Err(Error::InvalidModule));
        assert_eq!(builder.tag(15, &[0; 64]), Err(Error::BufferTooSmall));
        assert!(Multiboot2Builder::new(&mut [0; 7]).is_err());
    }

    #[test]
    fn efi_map_preserves_descriptor_extension_bytes() {
        let mut buffer = [0; 96];
        let mut builder = Multiboot2Builder::new(&mut buffer).unwrap();
        assert_eq!(
            builder.efi_memory_map(39, 1, &[0; 39]),
            Err(Error::InvalidMemoryMap)
        );
        assert_eq!(
            builder.efi_memory_map(48, 1, &[0; 47]),
            Err(Error::InvalidMemoryMap)
        );
        builder.efi_memory_map(48, 1, &[0x5a; 48]).unwrap();
        assert_eq!(builder.finish(), Ok(80));
        assert_eq!(&buffer[8..16], &[17, 0, 0, 0, 64, 0, 0, 0]);
        assert_eq!(&buffer[16..24], &[48, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&buffer[24..72], &[0x5a; 48]);
    }

    fn bundle_fixture() -> std::vec::Vec<u8> {
        let mut data = std::vec![0; 296];
        data[..16].copy_from_slice(BUNDLE_MAGIC);
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[20..24].copy_from_slice(&256u32.to_le_bytes());
        data[24..32].copy_from_slice(&296u64.to_le_bytes());
        for (i, (offset, length)) in [(256u64, 1u64), (264, 6), (272, 20)].iter().enumerate() {
            data[32 + i * 16..40 + i * 16].copy_from_slice(&offset.to_le_bytes());
            data[40 + i * 16..48 + i * 16].copy_from_slice(&length.to_le_bytes());
        }
        data[256] = 0x7f;
        data[264..270].copy_from_slice(b"070701");
        data[272..292].copy_from_slice(b"narf.disks=boot-only");
        data
    }

    #[test]
    fn bundle_rejects_every_truncation_and_invalid_layout() {
        let data = bundle_fixture();
        let parsed = BootBundle::parse(&data).unwrap();
        assert_eq!(parsed.kernel, &[0x7f]);
        assert_eq!(parsed.cmdline, "narf.disks=boot-only");
        for end in 0..data.len() {
            assert!(BootBundle::parse(&data[..end]).is_err(), "length {end}");
        }
        for offset in [0, 16, 20, 24, 32, 40, 48, 56, 64, 72, 176, 264] {
            let mut corrupt = data.clone();
            corrupt[offset] = 0xff;
            assert!(BootBundle::parse(&corrupt).is_err(), "offset {offset}");
        }
        for byte in [0, 0xff] {
            let mut corrupt = data.clone();
            corrupt[272] = byte;
            assert!(BootBundle::parse(&corrupt).is_err());
        }
    }
}

//! Place QEMU's manually loaded initrd after actual ELF physical/BSS extents.
//! The dumpdtb kernel stub remains separate; only chosen initrd bounds change.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const FLOOR: u64 = 0x4800_0000;
const ALIGN: u64 = 1024 * 1024;
const DTB_MAX: usize = 2 * 1024 * 1024;
const PH_MAX: usize = 4096;

pub(crate) fn place(
    kernel: &Path,
    dtb: &Path,
    initrd: &Path,
    dtb_load: u64,
) -> Result<(PathBuf, u64)> {
    let memory_end = kernel_end(kernel)?;
    let start = memory_end
        .max(FLOOR)
        .checked_add(ALIGN - 1)
        .context("initrd alignment overflow")?
        & !(ALIGN - 1);
    let file = File::open(initrd).with_context(|| format!("opening {}", initrd.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() != 0,
        "initrd must be a nonempty regular file"
    );
    let length = metadata.len();
    let end = start.checked_add(length).context("initrd end overflow")?;
    ensure!(
        end <= dtb_load,
        "initrd {start:#x}..{end:#x} overlaps DTB at {dtb_load:#x}"
    );

    let mut bytes = read_dtb(dtb)?;
    let digest = Sha256::digest(&bytes);
    let (first, last) = initrd_properties(&bytes)?;
    patch(&mut bytes, first, start)?;
    patch(&mut bytes, last, end)?;
    let mut name = dtb
        .file_name()
        .context("DTB path has no filename")?
        .to_os_string();
    name.push(format!(
        ".initrd-{start:016x}-{length:016x}-{:016x}.dtb",
        u64::from_be_bytes(digest[..8].try_into()?)
    ));
    let output = dtb.with_file_name(name);
    write_clone(&output, &bytes)?;
    Ok((output, start))
}

fn kernel_end(path: &Path) -> Result<u64> {
    let mut file =
        File::open(path).with_context(|| format!("opening kernel {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "kernel ELF must be a regular file");
    let mut header = [0; 64];
    file.read_exact(&mut header)
        .context("truncated ELF64 header")?;
    ensure!(
        &header[..7] == b"\x7fELF\x02\x01\x01",
        "kernel must be ELF64 little-endian version1"
    );
    ensure!(
        matches!(le16(&header, 16)?, 2 | 3) && le16(&header, 18)? == 183 && le32(&header, 20)? == 1,
        "kernel ELF type/machine/version is not AArch64 executable"
    );
    ensure!(
        le16(&header, 52)? == 64 && le16(&header, 54)? == 56,
        "unsupported ELF header/program-header extent"
    );
    let offset = le64(&header, 32)?;
    let count = usize::from(le16(&header, 56)?);
    ensure!(
        (1..=PH_MAX).contains(&count) && offset >= 64,
        "unsupported ELF program-header count/offset"
    );
    let length = count
        .checked_mul(56)
        .context("program-header table overflow")?;
    ensure!(
        offset
            .checked_add(length as u64)
            .is_some_and(|end| end <= metadata.len()),
        "truncated ELF program-header table"
    );
    // At most 224 KiB. Do not read giant debug sections or sparse ELF tails.
    let mut table = vec![0; length];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut table)
        .context("truncated ELF program headers")?;
    let mut maximum = None;
    for entry in table.chunks_exact(56) {
        if le32(entry, 0)? != 1 {
            continue;
        }
        let physical = le64(entry, 24)?;
        let file_offset = le64(entry, 8)?;
        let file_size = le64(entry, 32)?;
        let memory_size = le64(entry, 40)?;
        ensure!(
            file_size <= memory_size,
            "ELF PT_LOAD file size exceeds memory size"
        );
        ensure!(
            file_offset
                .checked_add(file_size)
                .is_some_and(|end| end <= metadata.len()),
            "ELF PT_LOAD file extent is truncated/overflowing"
        );
        let end = physical
            .checked_add(memory_size)
            .context("ELF PT_LOAD physical memory extent overflow")?;
        if memory_size != 0 {
            maximum = Some(maximum.map_or(end, |prior: u64| prior.max(end)));
        }
    }
    maximum.context("kernel ELF has no nonempty PT_LOAD memory extent")
}

fn read_dtb(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening DTB {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "DTB must be a regular file");
    let mut bytes = Vec::new();
    file.take((DTB_MAX + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= DTB_MAX, "DTB exceeds2MiB bound");
    Ok(bytes)
}
#[derive(Clone, Copy, Debug)]
struct Property {
    offset: usize,
    length: usize,
}
fn span(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    bytes
        .get(offset..offset.checked_add(length).context("wire extent overflow")?)
        .context("truncated wire field")
}
fn le16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(bytes, at, 2)?.try_into()?))
}
fn le32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(bytes, at, 4)?.try_into()?))
}
fn le64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(bytes, at, 8)?.try_into()?))
}
fn be32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(span(bytes, at, 4)?.try_into()?))
}
fn be64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(span(bytes, at, 8)?.try_into()?))
}
fn align4(value: usize) -> Result<usize> {
    Ok(value.checked_add(3).context("FDT alignment overflow")? & !3)
}
fn disjoint(a: (usize, usize), b: (usize, usize)) -> bool {
    a.1 <= b.0 || b.1 <= a.0
}

fn initrd_properties(bytes: &[u8]) -> Result<(Property, Property)> {
    ensure!(
        bytes.len() >= 40 && be32(bytes, 0)? == 0xd00d_feed,
        "invalid FDT header/magic"
    );
    let total = be32(bytes, 4)? as usize;
    ensure!(
        (40..=DTB_MAX).contains(&total) && total <= bytes.len(),
        "invalid FDT total size"
    );
    ensure!(
        be32(bytes, 20)? == 17 && matches!(be32(bytes, 24)?, 16 | 17),
        "unsupported FDT version"
    );
    let structure = be32(bytes, 8)? as usize;
    let strings = be32(bytes, 12)? as usize;
    let reserve = be32(bytes, 16)? as usize;
    let string_size = be32(bytes, 32)? as usize;
    let structure_size = be32(bytes, 36)? as usize;
    let blob = &bytes[..total];
    span(blob, structure, structure_size)?;
    let names = span(blob, strings, string_size)?;
    let structure_end = structure
        .checked_add(structure_size)
        .context("FDT structure overflow")?;
    let strings_end = strings
        .checked_add(string_size)
        .context("FDT strings overflow")?;
    ensure!(
        structure >= 40
            && strings >= 40
            && reserve >= 40
            && structure % 4 == 0
            && structure_size % 4 == 0
            && reserve % 8 == 0,
        "invalid FDT block alignment/offset"
    );
    ensure!(
        disjoint((structure, structure_end), (strings, strings_end)),
        "overlapping FDT structure/strings"
    );
    let mut reserved_end = reserve;
    loop {
        let address = be64(blob, reserved_end)?;
        let size = be64(blob, reserved_end + 8)?;
        reserved_end = reserved_end
            .checked_add(16)
            .context("FDT reservation overflow")?;
        ensure!(
            disjoint((reserve, reserved_end), (structure, structure_end))
                && disjoint((reserve, reserved_end), (strings, strings_end)),
            "FDT reservations overlap another block"
        );
        if address == 0 && size == 0 {
            break;
        }
        address
            .checked_add(size)
            .context("FDT reserved memory overflow")?;
    }
    let mut at = structure;
    let mut stack: Vec<&[u8]> = Vec::new();
    let (mut root_seen, mut root_closed, mut chosen) = (false, false, 0);
    let (mut first, mut last) = (None, None);
    while at < structure_end {
        let token = be32(blob, at)?;
        at += 4;
        match token {
            1 => {
                ensure!(!root_closed && stack.len() < 64, "invalid FDT node nesting");
                let remaining = span(blob, at, structure_end - at)?;
                let length = remaining
                    .iter()
                    .position(|x| *x == 0)
                    .context("unterminated FDT node name")?;
                let name = &remaining[..length];
                if stack.is_empty() {
                    ensure!(!root_seen && name.is_empty(), "invalid/duplicate FDT root");
                    root_seen = true;
                } else {
                    ensure!(
                        !name.is_empty() && !name.contains(&b'/'),
                        "invalid FDT node name"
                    );
                }
                if stack.len() == 1 && name == b"chosen" {
                    chosen += 1;
                    ensure!(chosen == 1, "duplicate /chosen node");
                }
                at = align4(at + length + 1)?;
                ensure!(at <= structure_end, "truncated FDT node padding");
                stack.push(name);
            }
            2 => {
                ensure!(!stack.is_empty(), "unmatched FDT END_NODE");
                stack.pop();
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            3 => {
                ensure!(
                    !stack.is_empty() && structure_end - at >= 8,
                    "FDT property outside node/truncated header"
                );
                let length = be32(blob, at)? as usize;
                let name_offset = be32(blob, at + 4)? as usize;
                at += 8;
                let name_tail = names
                    .get(name_offset..)
                    .context("FDT property name offset out of bounds")?;
                let name_end = name_tail
                    .iter()
                    .position(|x| *x == 0)
                    .context("unterminated FDT property name")?;
                ensure!(name_end != 0, "empty FDT property name");
                let name = &name_tail[..name_end];
                let end = at
                    .checked_add(length)
                    .context("FDT property length overflow")?;
                let padded = align4(end)?;
                ensure!(padded <= structure_end, "truncated FDT property/padding");
                if stack.len() == 2 && stack[1] == b"chosen" {
                    let slot = if name == b"linux,initrd-start" {
                        Some(&mut first)
                    } else if name == b"linux,initrd-end" {
                        Some(&mut last)
                    } else {
                        None
                    };
                    if let Some(slot) = slot {
                        ensure!(
                            matches!(length, 4 | 8) && slot.is_none(),
                            "malformed/duplicate /chosen initrd property"
                        );
                        *slot = Some(Property { offset: at, length });
                    }
                }
                at = padded;
            }
            4 => {}
            9 => {
                ensure!(
                    root_seen && root_closed && stack.is_empty() && chosen == 1,
                    "incomplete FDT root/chosen"
                );
                ensure!(
                    blob[at..structure_end].iter().all(|x| *x == 0),
                    "tokens after FDT_END"
                );
                return Ok((
                    first.context("missing /chosen/linux,initrd-start")?,
                    last.context("missing /chosen/linux,initrd-end")?,
                ));
            }
            _ => anyhow::bail!("unknown FDT structure token {token:#x}"),
        }
    }
    anyhow::bail!("FDT structure has no END token")
}
fn patch(bytes: &mut [u8], property: Property, value: u64) -> Result<()> {
    let raw = if property.length == 4 {
        u32::try_from(value)
            .context("initrd address exceeds32-bit FDT property")?
            .to_be_bytes()
            .to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };
    bytes[property.offset..property.offset + property.length].copy_from_slice(&raw);
    Ok(())
}
fn write_clone(path: &Path, bytes: &[u8]) -> Result<()> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut name = path
        .file_name()
        .context("DTB output has no filename")?
        .to_os_string();
    name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = path.with_file_name(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "narf-aarch64-initrd-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn elf(loads: &[(u64, u64)]) -> Vec<u8> {
        let mut bytes = vec![0; 1024];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(loads.len() as u16).to_le_bytes());
        for (index, &(physical, memory)) in loads.iter().enumerate() {
            let at = 64 + index * 56;
            bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&512u64.to_le_bytes());
            // Deliberately unrelated to p_paddr. Placement must use physical
            // memory, never this high virtual address or the tiny file size.
            bytes[at + 16..at + 24].copy_from_slice(&0xffff_ffff_0000_0000u64.to_le_bytes());
            bytes[at + 24..at + 32].copy_from_slice(&physical.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&1u64.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&memory.to_le_bytes());
        }
        bytes
    }
    fn word(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }
    fn node(out: &mut Vec<u8>, name: &[u8]) {
        word(out, 1);
        out.extend_from_slice(name);
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    fn property(out: &mut Vec<u8>, name: u32, value: &[u8]) -> usize {
        word(out, 3);
        word(out, value.len() as u32);
        word(out, name);
        let at = out.len();
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        at
    }
    struct Dtb {
        bytes: Vec<u8>,
        start: usize,
        end: usize,
    }
    fn dtb(width: usize, duplicate: u8) -> Dtb {
        let names = b"linux,initrd-start\0linux,initrd-end\0bootargs\0";
        let end_name = names.iter().position(|x| *x == 0).unwrap() + 1;
        let boot_name = end_name + names[end_name..].iter().position(|x| *x == 0).unwrap() + 1;
        let mut structure = Vec::new();
        node(&mut structure, b"");
        node(&mut structure, b"other");
        property(&mut structure, 0, &[0x11; 4]);
        property(&mut structure, end_name as u32, &[0x22; 4]);
        word(&mut structure, 2);
        node(&mut structure, b"outer");
        node(&mut structure, b"chosen");
        property(&mut structure, 0, &[0x33; 8]);
        property(&mut structure, end_name as u32, &[0x44; 8]);
        word(&mut structure, 2);
        word(&mut structure, 2);
        node(&mut structure, b"chosen");
        property(
            &mut structure,
            boot_name as u32,
            b"test_subsystem=drivers/wireless loglevel=4\0",
        );
        let start = property(&mut structure, 0, &vec![0; width]);
        let end = property(&mut structure, end_name as u32, &vec![0; width]);
        if duplicate == 1 {
            property(&mut structure, 0, &vec![0; width]);
        }
        if duplicate == 2 {
            property(&mut structure, end_name as u32, &vec![0; width]);
        }
        word(&mut structure, 2);
        if duplicate == 3 {
            node(&mut structure, b"chosen");
            word(&mut structure, 2);
        }
        word(&mut structure, 2);
        word(&mut structure, 9);
        let struct_offset = 56;
        let string_offset = struct_offset + structure.len();
        let total = string_offset + names.len();
        let mut bytes = Vec::new();
        for value in [
            0xd00dfeed,
            total as u32,
            struct_offset as u32,
            string_offset as u32,
            40,
            17,
            16,
            0,
            names.len() as u32,
            structure.len() as u32,
        ] {
            word(&mut bytes, value);
        }
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend(structure);
        bytes.extend_from_slice(names);
        // Bytes outside totalsize must also survive the clone unchanged.
        bytes.extend_from_slice(b"TAIL");
        Dtb {
            bytes,
            start: start + struct_offset,
            end: end + struct_offset,
        }
    }
    fn files(
        temp: &Temp,
        kernel: &[u8],
        tree: &[u8],
        initrd_len: u64,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let kernel_path = temp.0.join("kernel.elf");
        let dtb_path = temp.0.join("cached.dtb");
        let initrd_path = temp.0.join("initramfs");
        fs::write(&kernel_path, kernel).unwrap();
        fs::write(&dtb_path, tree).unwrap();
        let file = File::create(&initrd_path).unwrap();
        file.set_len(initrd_len).unwrap();
        (kernel_path, dtb_path, initrd_path)
    }
    #[test]
    fn reported_large_bss_uses_actual_physical_end_and_preserves_every_other_dtb_byte() {
        for width in [4, 8] {
            let temp = Temp::new();
            let tree = dtb(width, 0);
            let raw = elf(&[
                (0x4008_0000, 0x1000),
                (0x4400_0000, 0x1000),
                (0x44df_5000, 0x0326_4ed0),
            ]);
            let (kernel, dtb, initrd) = files(&temp, &raw, &tree.bytes, 17);
            assert_eq!(kernel_end(&kernel).unwrap(), 0x4805_9ed0);
            let (output, start) = place(&kernel, &dtb, &initrd, 0x4f00_0000).unwrap();
            assert_eq!(start, 0x4810_0000);
            assert_ne!(output, dtb);
            assert!(output
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("initrd-0000000048100000-0000000000000011"));
            let mut expected = tree.bytes.clone();
            let start_bytes = if width == 4 {
                vec![0x48, 0x10, 0, 0]
            } else {
                vec![0, 0, 0, 0, 0x48, 0x10, 0, 0]
            };
            let end_bytes = if width == 4 {
                vec![0x48, 0x10, 0, 0x11]
            } else {
                vec![0, 0, 0, 0, 0x48, 0x10, 0, 0x11]
            };
            expected[tree.start..tree.start + width].copy_from_slice(&start_bytes);
            expected[tree.end..tree.end + width].copy_from_slice(&end_bytes);
            assert_eq!(fs::read(&output).unwrap(), expected);
            assert_eq!(fs::read(&dtb).unwrap(), tree.bytes);
            assert_eq!(
                place(&kernel, &dtb, &initrd, 0x4f00_0000).unwrap().0,
                output
            );
        }
    }
    #[test]
    fn small_kernel_floor_exact_dtb_boundary_and_address_length_keys() {
        let temp = Temp::new();
        let tree = dtb(4, 0);
        let (kernel, dtb, initrd) = files(&temp, &elf(&[(0x4008_0000, 4096)]), &tree.bytes, 16);
        let (first, start) = place(&kernel, &dtb, &initrd, FLOOR + 16).unwrap();
        assert_eq!(start, FLOOR);
        File::options()
            .write(true)
            .open(&initrd)
            .unwrap()
            .set_len(17)
            .unwrap();
        assert!(place(&kernel, &dtb, &initrd, FLOOR + 16).is_err());
        let second = place(&kernel, &dtb, &initrd, 0x4f00_0000).unwrap().0;
        assert_ne!(first, second);
        File::options()
            .write(true)
            .open(&initrd)
            .unwrap()
            .set_len(0)
            .unwrap();
        assert!(place(&kernel, &dtb, &initrd, 0x4f00_0000).is_err());
    }
    #[test]
    fn elf_header_table_and_segment_failures_are_checked() {
        let original = elf(&[(0x4008_0000, 4096)]);
        let temp = Temp::new();
        let path = temp.0.join("bad.elf");
        let mut invalid = vec![original[..63].to_vec()];
        for (offset, value) in [(4, 1), (5, 2), (18, 0), (20, 0), (52, 63), (54, 55)] {
            let mut raw = original.clone();
            raw[offset] = value;
            invalid.push(raw);
        }
        for count in [0u16, 4097, u16::MAX] {
            let mut raw = original.clone();
            raw[56..58].copy_from_slice(&count.to_le_bytes());
            invalid.push(raw);
        }
        for offset in [1024, u64::MAX - 8] {
            let mut raw = original.clone();
            raw[32..40].copy_from_slice(&offset.to_le_bytes());
            invalid.push(raw);
        }
        for (at, value) in [
            (64 + 8, u64::MAX),
            (64 + 24, u64::MAX),
            (64 + 32, 4097),
            (64 + 40, 0),
        ] {
            let mut raw = original.clone();
            raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
            invalid.push(raw);
        }
        let mut empty = original;
        empty[64..68].fill(0);
        invalid.push(empty);
        for raw in invalid {
            fs::write(&path, raw).unwrap();
            assert!(kernel_end(&path).is_err());
        }
    }
    #[test]
    fn sparse_giant_elf_tail_is_not_read_or_used_as_physical_memory() {
        let temp = Temp::new();
        let path = temp.0.join("sparse.elf");
        fs::write(&path, elf(&[(0x4008_0000, 4096)])).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4 * 1024 * 1024 * 1024)
            .unwrap();
        assert_eq!(kernel_end(&path).unwrap(), 0x4008_1000);
    }
    #[test]
    fn fdt_scope_missing_duplicates_and_malformed_extents_fail_closed() {
        for duplicate in [1, 2, 3] {
            assert!(initrd_properties(&dtb(4, duplicate).bytes).is_err());
        }
        let tree = dtb(4, 0);
        let mut invalid = Vec::new();
        let mut truncated = tree.bytes.clone();
        truncated.truncate(truncated.len() - 5);
        invalid.push(truncated);
        for (at, value) in [
            (0, 0),
            (4, u32::MAX),
            (8, u32::MAX),
            (12, u32::MAX),
            (16, 0),
            (20, 16),
            (36, 4),
            (tree.start - 8, 3),
            (tree.start - 4, u32::MAX),
        ] {
            let mut raw = tree.bytes.clone();
            raw[at..at + 4].copy_from_slice(&value.to_be_bytes());
            invalid.push(raw);
        }
        // Turn the exact chosen start into a different valid property; the
        // similarly named properties elsewhere must never satisfy the lookup.
        let mut missing = tree.bytes.clone();
        missing[tree.start - 4..tree.start].copy_from_slice(&36u32.to_be_bytes());
        invalid.push(missing);
        let mut reservation = tree.bytes.clone();
        reservation[55] = 1;
        invalid.push(reservation);
        let strings = be32(&tree.bytes, 12).unwrap() as usize;
        let length = be32(&tree.bytes, 32).unwrap() as usize;
        let mut names = tree.bytes.clone();
        names[strings..strings + length].fill(b'x');
        invalid.push(names);
        for raw in invalid {
            assert!(initrd_properties(&raw).is_err());
        }
    }
    #[test]
    fn alignment_end_overflow_and_32bit_property_width_are_checked() {
        let temp = Temp::new();
        let tree = dtb(4, 0);
        let (kernel, dtb_path, initrd) = files(&temp, &elf(&[(u64::MAX - 1, 1)]), &tree.bytes, 1);
        assert!(place(&kernel, &dtb_path, &initrd, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("alignment overflow"));
        fs::write(&kernel, elf(&[(0xffff_ffff_ffef_ffff, 1)])).unwrap();
        File::options()
            .write(true)
            .open(&initrd)
            .unwrap()
            .set_len(ALIGN)
            .unwrap();
        assert!(place(&kernel, &dtb_path, &initrd, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("initrd end overflow"));
        fs::write(&kernel, elf(&[(0x1_0000_0000, 1)])).unwrap();
        File::options()
            .write(true)
            .open(&initrd)
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(place(&kernel, &dtb_path, &initrd, 0x1_1000_0000).is_err());
        fs::write(&dtb_path, dtb(8, 0).bytes).unwrap();
        assert_eq!(
            place(&kernel, &dtb_path, &initrd, 0x1_1000_0000).unwrap().1,
            0x1_0010_0000
        );
    }
}

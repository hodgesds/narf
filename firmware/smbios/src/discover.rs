//! Boot-time SMBIOS discovery and raw-structure retention.
//!
//! A port of Linux `drivers/firmware/dmi_scan.c`:
//!
//! - [`smbios3_present`] / [`dmi_present`] = `dmi_smbios3_present` /
//!   `dmi_present` (anchor, length window, checksums, version fixups);
//! - [`efi_smbios_tables`] = the `SMBIOS3_TABLE_GUID` /
//!   `SMBIOS_TABLE_GUID` matches of `efi_config_parse_tables` (after
//!   `efi_systab_init`'s signature check);
//! - [`scan_legacy_region`] = the non-EFI 0xF0000 two-pass anchor
//!   search of `dmi_scan_machine`;
//! - [`scan_machine`] = `dmi_scan_machine`'s precedence, extended with
//!   the multiboot2 SMBIOS-tag copies the loader handed over;
//! - [`RawTable`] = the table `dmi_walk` re-walks, walked with
//!   `dmi_decode_table`'s exact bounds (short-entry stop, string-set
//!   scan bounded by `dmi_len`, end-of-table only for SMBIOS 3,
//!   trailing trim).
//!
//! Physical memory is read through [`PhysRead`] so the whole path runs
//! against synthetic memory in tests.

use alloc::vec::Vec;

/// `SMBIOS3_TABLE_GUID` f2fd1544-9794-4a2c-992e-e5bbcf20e394 in EFI
/// byte order (`EFI_GUID` = u32, u16, u16 little-endian, then 8 bytes).
pub const SMBIOS3_TABLE_GUID: [u8; 16] = [
    0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94,
];
/// `SMBIOS_TABLE_GUID` eb9d2d31-2d88-11d3-9a16-0090273fc14d.
pub const SMBIOS_TABLE_GUID: [u8; 16] = [
    0x31, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
];
/// `EFI_SYSTEM_TABLE_SIGNATURE` ("IBI SYST").
pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
/// `SMBIOS_ENTRY_POINT_SCAN_START` and the 64 KiB window Linux maps.
pub const SMBIOS_ENTRY_POINT_SCAN_START: u64 = 0xF0000;
pub const SMBIOS_ENTRY_POINT_SCAN_LEN: usize = 0x10000;
/// NARF bound on the structure table copied at boot. Linux maps
/// `dmi_len` whole; SMBIOS 3 `dmi_len` is only a *maximum* size, so a
/// bogus value would have NARF copy gigabytes. Real tables are a few
/// KiB.
pub const MAX_TABLE_LEN: u32 = 1 << 20;
/// NARF bound on EFI configuration-table entries walked (Linux trusts
/// `nr_tables`).
pub const MAX_EFI_CONFIG_TABLES: u64 = 1024;

/// Reads physical memory. `false` = the range cannot be read.
pub trait PhysRead {
    fn read(&self, phys: u64, out: &mut [u8]) -> bool;
}

/// Which path located the table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// EFI configuration table, `SMBIOS3_TABLE_GUID` (`efi.smbios3`).
    EfiSmbios3,
    /// EFI configuration table, `SMBIOS_TABLE_GUID` (`efi.smbios`).
    EfiSmbios,
    /// Multiboot2 tag 13 copy of an `_SM3_` entry point.
    LoaderSmbios3,
    /// Multiboot2 tag 13 copy of an `_SM_` entry point.
    LoaderSmbios,
    /// 0xF0000 scan, `_SM3_` anchor.
    LegacySmbios3,
    /// 0xF0000 scan, `_SM_` / `_DMI_` anchor.
    LegacySmbios,
}

/// `dmi_base` / `dmi_len` / `dmi_num` / `dmi_ver` as an entry point
/// decodes them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableLocation {
    pub base: u64,
    pub len: u32,
    /// Structure count (0 = SMBIOS 3: walk to the end-of-table marker).
    pub num: u16,
    /// `dmi_ver`: `major << 16 | minor << 8 | docrev`.
    pub version: u32,
}

fn dmi_checksum(buf: &[u8], len: usize) -> bool {
    buf[..len].iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

/// `dmi_smbios3_present`: `_SM3_`, length 24..=32, checksum over that
/// length. `buf` is the 32 bytes at the candidate.
pub fn smbios3_present(buf: &[u8; 32]) -> Option<TableLocation> {
    let n = buf[6] as usize;
    if &buf[0..5] != b"_SM3_" || !(24..=32).contains(&n) || !dmi_checksum(buf, n) {
        return None;
    }
    Some(TableLocation {
        // get_unaligned_be24(buf + 7)
        version: (buf[7] as u32) << 16 | (buf[8] as u32) << 8 | buf[9] as u32,
        num: 0,
        len: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        base: u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]),
    })
}

/// `dmi_present`: an optional `_SM_` header (length 30..=32 — 30 for
/// the SMBIOS 2.1 spec mistake — and checksum) at `buf[0]`, then the
/// mandatory `_DMI_` header at `buf[16]` with its 15-byte checksum. A
/// bare `_DMI_` is "legacy DMI" with a BCD version.
pub fn dmi_present(buf: &[u8; 32]) -> Option<TableLocation> {
    let n = buf[5] as usize;
    let mut smbios_ver: u32 =
        if &buf[0..4] == b"_SM_" && (30..=32).contains(&n) && dmi_checksum(buf, n) {
            u16::from_be_bytes([buf[6], buf[7]]) as u32
        } else {
            0
        };
    // "Some BIOS report weird SMBIOS version, fix that up"
    smbios_ver = match smbios_ver {
        0x021F | 0x0221 => 0x0203,
        0x0233 => 0x0206,
        v => v,
    };
    let d = &buf[16..32];
    if &d[0..5] != b"_DMI_" || !dmi_checksum(d, 15) {
        return None;
    }
    let ver = if smbios_ver != 0 {
        smbios_ver
    } else {
        ((d[14] as u32 & 0xF0) << 4) | (d[14] as u32 & 0x0F)
    };
    Some(TableLocation {
        version: ver << 8,
        num: u16::from_le_bytes([d[12], d[13]]),
        len: u16::from_le_bytes([d[6], d[7]]) as u32,
        base: u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as u64,
    })
}

/// `efi_systab_init` + the SMBIOS rows of `efi_config_parse_tables`
/// for a 64-bit system table at `systab`: `None` when the signature
/// does not match (EFI is then not enabled); otherwise
/// `(efi.smbios3, efi.smbios)`, a later duplicate GUID overriding an
/// earlier one as in Linux's table loop.
pub fn efi_smbios_tables(systab: u64, mem: &dyn PhysRead) -> Option<(Option<u64>, Option<u64>)> {
    // EFI_SYSTEM_TABLE (x86_64): hdr(24) fw_vendor(8) fw_revision(4+4)
    // con_in_handle con_in con_out_handle con_out stderr_handle stderr
    // runtime boottime (8 each) nr_tables(8 @104) tables(8 @112).
    let mut st = [0u8; 120];
    if !mem.read(systab, &mut st) {
        return None;
    }
    let sig = u64::from_le_bytes(st[0..8].try_into().unwrap());
    if sig != EFI_SYSTEM_TABLE_SIGNATURE {
        return None;
    }
    let nr = u64::from_le_bytes(st[104..112].try_into().unwrap());
    let tables = u64::from_le_bytes(st[112..120].try_into().unwrap());
    let (mut s3, mut s) = (None, None);
    for i in 0..nr.min(MAX_EFI_CONFIG_TABLES) {
        // efi_config_table_64_t { efi_guid_t guid; u64 table; }
        let mut e = [0u8; 24];
        if !mem.read(tables.wrapping_add(i * 24), &mut e) {
            break;
        }
        let table = u64::from_le_bytes(e[16..24].try_into().unwrap());
        if e[0..16] == SMBIOS3_TABLE_GUID {
            s3 = Some(table);
        } else if e[0..16] == SMBIOS_TABLE_GUID {
            s = Some(table);
        }
    }
    Some((s3, s))
}

/// The non-EFI branch of `dmi_scan_machine` over `region` (the 64 KiB
/// at 0xF0000): a sliding 32-byte window, first looking for `_SM3_` at
/// every paragraph but the last, then repeating for `_SM_`/`_DMI_`
/// with the window's first half zeroed on the first step. `try_entry`
/// is `dmi_*_present` + `dmi_walk_early`: the first candidate it
/// accepts wins.
pub fn scan_legacy_region<T>(
    region: &[u8],
    mut try_entry: impl FnMut(&[u8; 32], bool) -> Option<T>,
) -> Option<T> {
    let len = region.len() & !15;
    if len < 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&region[..16]);
    let mut q = 16;
    while q < len {
        buf[16..].copy_from_slice(&region[q..q + 16]);
        if let Some(t) = try_entry(&buf, true) {
            return Some(t);
        }
        buf.copy_within(16..32, 0);
        q += 16;
    }
    buf[..16].fill(0);
    let mut q = 0;
    while q < len {
        buf[16..].copy_from_slice(&region[q..q + 16]);
        if let Some(t) = try_entry(&buf, false) {
            return Some(t);
        }
        buf.copy_within(16..32, 0);
        q += 16;
    }
    None
}

/// What the scan may look at. `efi_system_table`, `loader_smbios3`
/// and `loader_smbios` come from the boot handoff; `legacy_scan` is
/// `CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK` (x86 only).
#[derive(Copy, Clone, Debug, Default)]
pub struct Sources {
    pub efi_system_table: Option<u64>,
    pub loader_smbios3: Option<[u8; 32]>,
    pub loader_smbios: Option<[u8; 32]>,
    pub legacy_scan: bool,
}

/// `dmi_scan_machine` + `dmi_walk_early`: locate the structure table and
/// copy it out.
///
/// 1. EFI (system table signature valid): `efi.smbios3` first, then
///    `efi.smbios` — the 64-bit entry point has precedence and a
///    failure to decode it falls back to the 32-bit one.
/// 2. The loader's multiboot2 copies, same precedence (NARF addition:
///    Linux is its own EFI stub and has no such tag).
/// 3. Only when EFI is not enabled, the 0xF0000 anchor scan.
pub fn scan_machine(src: &Sources, mem: &dyn PhysRead) -> Option<RawTable> {
    let try_sm3 = |buf: &[u8; 32], source| {
        smbios3_present(buf).and_then(|loc| RawTable::read(loc, source, mem))
    };
    let try_sm =
        |buf: &[u8; 32], source| dmi_present(buf).and_then(|loc| RawTable::read(loc, source, mem));
    let read32 = |phys: u64| {
        let mut b = [0u8; 32];
        mem.read(phys, &mut b).then_some(b)
    };
    let efi = src
        .efi_system_table
        .and_then(|st| efi_smbios_tables(st, mem));
    if let Some((s3, s)) = efi {
        if let Some(t) = s3
            .and_then(read32)
            .and_then(|b| try_sm3(&b, Source::EfiSmbios3))
        {
            return Some(t);
        }
        if let Some(t) = s
            .and_then(read32)
            .and_then(|b| try_sm(&b, Source::EfiSmbios))
        {
            return Some(t);
        }
    }
    if let Some(t) = src
        .loader_smbios3
        .and_then(|b| try_sm3(&b, Source::LoaderSmbios3))
    {
        return Some(t);
    }
    if let Some(t) = src
        .loader_smbios
        .and_then(|b| try_sm(&b, Source::LoaderSmbios))
    {
        return Some(t);
    }
    if efi.is_some() || !src.legacy_scan {
        return None;
    }
    let mut region = alloc::vec![0u8; SMBIOS_ENTRY_POINT_SCAN_LEN];
    if !mem.read(SMBIOS_ENTRY_POINT_SCAN_START, &mut region) {
        return None;
    }
    scan_legacy_region(&region, |buf, sm3| {
        if sm3 {
            try_sm3(buf, Source::LegacySmbios3)
        } else {
            try_sm(buf, Source::LegacySmbios)
        }
    })
}

// ── Raw structure table ────────────────────────────────────────────

/// One structure as `dmi_decode_table` hands it to a `decode`
/// callback: the formatted area (`hdr->length` bytes, header included)
/// followed by its string set through the terminating double NUL.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RawStructure<'a> {
    pub kind: u8,
    pub handle: u16,
    /// Formatted area + string set (incl. the double NUL).
    pub bytes: &'a [u8],
}

impl<'a> RawStructure<'a> {
    /// `hdr->length` — the formatted area's length.
    pub fn length(&self) -> u8 {
        self.bytes[1]
    }
    /// The formatted area (header included).
    pub fn formatted(&self) -> &'a [u8] {
        &self.bytes[..self.bytes[1] as usize]
    }
    /// The string set (each NUL-terminated, then a final NUL).
    pub fn strings(&self) -> &'a [u8] {
        &self.bytes[self.bytes[1] as usize..]
    }
    /// SMBIOS 1-based string `idx` (`dmi_string_nosave`); `None` for 0
    /// or past the set.
    pub fn string(&self, idx: u8) -> Option<&'a [u8]> {
        if idx == 0 {
            return None;
        }
        let set = self.strings();
        let mut start = 0;
        for i in 1..=idx {
            let end = start + set.get(start..)?.iter().position(|&b| b == 0)?;
            if end == start {
                return None; // the empty string ends the set
            }
            if i == idx {
                return Some(&set[start..end]);
            }
            start = end + 1;
        }
        None
    }
}

/// A copied structure table, walked the way `dmi_walk` walks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTable {
    bytes: Vec<u8>,
    num: u16,
    version: u32,
    source: Option<Source>,
}

/// `dmi_decode_table`'s walk: `(start, end)` of each structure that
/// would reach `decode`, plus the trimmed `dmi_len`.
fn decode_table(buf: &[u8], num: u16, mut decode: impl FnMut(usize, usize)) -> usize {
    let len = buf.len() as i64;
    let mut data: i64 = 0;
    let mut i: u32 = 0;
    while (num == 0 || i < num as u32) && data + 4 <= len {
        let start = data as usize;
        let kind = buf[start];
        let length = buf[start + 1] as i64;
        // "Corrupted DMI table" — a short entry cannot be stepped over.
        if length < 4 {
            break;
        }
        data += length;
        while data < len - 1 && (buf[data as usize] != 0 || buf[data as usize + 1] != 0) {
            data += 1;
        }
        if data < len - 1 {
            decode(start, data as usize + 2);
        }
        data += 2;
        i += 1;
        // End-of-table is trusted only behind a 64-bit entry point.
        if num == 0 && kind == 127 {
            break;
        }
    }
    if len > data {
        data as usize
    } else {
        buf.len()
    }
}

impl RawTable {
    /// Wrap a structure table (`num` = structure count, 0 for SMBIOS 3),
    /// trimming it to the walked length as `dmi_decode_table` does.
    pub fn from_bytes(mut bytes: Vec<u8>, num: u16) -> Self {
        let trimmed = decode_table(&bytes, num, |_, _| {});
        bytes.truncate(trimmed);
        Self {
            bytes,
            num,
            version: 0,
            source: None,
        }
    }

    /// `dmi_walk_early`: copy `loc.len` bytes at `loc.base` (bounded by
    /// [`MAX_TABLE_LEN`]). `None` when the range cannot be read.
    pub fn read(loc: TableLocation, source: Source, mem: &dyn PhysRead) -> Option<Self> {
        let len = loc.len.min(MAX_TABLE_LEN) as usize;
        let mut bytes = alloc::vec![0u8; len];
        if !mem.read(loc.base, &mut bytes) {
            return None;
        }
        let mut t = Self::from_bytes(bytes, loc.num);
        t.version = loc.version;
        t.source = Some(source);
        Some(t)
    }

    /// The (trimmed) table bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// `dmi_num` (0 = SMBIOS 3).
    pub fn structure_count(&self) -> u16 {
        self.num
    }
    /// `dmi_ver` (`major << 16 | minor << 8 | docrev`); 0 when built
    /// with [`RawTable::from_bytes`].
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Which path found it; `None` when built with
    /// [`RawTable::from_bytes`].
    pub fn source(&self) -> Option<Source> {
        self.source
    }

    /// Every structure `dmi_walk` passes to its callback, in table
    /// order.
    pub fn structures(&self) -> Vec<RawStructure<'_>> {
        let mut out = Vec::new();
        decode_table(&self.bytes, self.num, |s, e| {
            let b = &self.bytes[s..e];
            out.push(RawStructure {
                kind: b[0],
                handle: u16::from_le_bytes([b[2], b[3]]),
                bytes: b,
            });
        });
        out
    }

    /// The structures of SMBIOS type `kind`, in table order.
    pub fn structures_of_type(&self, kind: u8) -> Vec<RawStructure<'_>> {
        let mut v = self.structures();
        v.retain(|s| s.kind == kind);
        v
    }
}

// ── Boot table ─────────────────────────────────────────────────────

static BOOT_TABLE: narf_lib::sync::OnceLock<RawTable> = narf_lib::sync::OnceLock::new();

/// The table the boot-time scan found (`dmi_available`); `None` when
/// the firmware provided none or the scan has not run.
pub fn boot_table() -> Option<&'static RawTable> {
    BOOT_TABLE.get()
}

/// `dmi_walk` filtered to one type, over the boot table. Empty when
/// there is no table.
pub fn raw_structures_of_type(kind: u8) -> Vec<RawStructure<'static>> {
    boot_table().map_or_else(Vec::new, |t| t.structures_of_type(kind))
}

/// Physical reads through the kernel direct map
/// (`PhysAddr::kernel_ptr` — the window the ACPI table walk reads
/// firmware tables through). The low half is user address space once
/// the MMU handoff is done, so `phys` is never dereferenced as-is.
/// Address 0 and anything at or past `LOW_IDENTITY_LIMIT` (512 GiB —
/// the direct map's first PML4 slot, always built, maps all of it with
/// 1-GiB pages) are refused.
#[derive(Debug)]
pub struct KernelPhys;

impl PhysRead for KernelPhys {
    #[cfg(target_arch = "x86_64")]
    fn read(&self, phys: u64, out: &mut [u8]) -> bool {
        let Some(end) = phys.checked_add(out.len() as u64) else {
            return false;
        };
        if phys == 0 || end > narf_memory::addr::LOW_IDENTITY_LIMIT {
            return false;
        }
        let src = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
        // SAFETY: `[phys, end)` is below 512 GiB, all of which the
        // direct map's first slot maps (1-GiB pages, holes included);
        // before the map is live `kernel_ptr` is the boot identity map.
        // Firmware tables are plain RAM / ROM.
        unsafe {
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len());
        }
        true
    }

    /// No firmware-table source reaches the scan on other
    /// architectures yet (the aarch64 loader hands over a DTB only).
    #[cfg(not(target_arch = "x86_64"))]
    fn read(&self, _phys: u64, _out: &mut [u8]) -> bool {
        false
    }
}

/// `dmi_setup`: scan once, decode the table into the typed records
/// (`parse_stream`) and keep the raw copy for [`raw_structures_of_type`].
pub(crate) fn dmi_setup() -> narf_init::InitResult {
    use core::fmt::Write as _;
    let h = narf_boot::firmware_handoff();
    let src = Sources {
        efi_system_table: h.efi_system_table,
        loader_smbios3: h.smbios3_entry.map(|e| e.bytes),
        loader_smbios: h.smbios_entry.map(|e| e.bytes),
        legacy_scan: cfg!(target_arch = "x86_64"),
    };
    let Some(t) = scan_machine(&src, &KernelPhys) else {
        let _ = writeln!(narf_console::Writer, "  dmi: DMI not present or invalid.");
        return narf_init::InitResult::NotPresent;
    };
    crate::parse_stream(t.bytes());
    let mut sys = [crate::SmbiosSystem::ZERO; 1];
    let product = if crate::copy_system(&mut sys) == 1 {
        let p = &sys[0].product_name;
        let n = p.iter().position(|&b| b == 0).unwrap_or(p.len());
        core::str::from_utf8(&p[..n]).unwrap_or("?")
    } else {
        ""
    };
    let _ = writeln!(
        narf_console::Writer,
        "  dmi: SMBIOS {}.{}.{} via {:?}: {} bytes, {} structures; product \"{}\"",
        t.version() >> 16,
        (t.version() >> 8) & 0xFF,
        t.version() & 0xFF,
        t.source().unwrap_or(Source::LegacySmbios),
        t.bytes().len(),
        t.structures().len(),
        product
    );
    let _ = BOOT_TABLE.set(t);
    narf_init::InitResult::Ok
}

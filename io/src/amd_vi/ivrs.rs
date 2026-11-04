//! IVRS (ACPI I/O Virtualization Reporting Structure) decoder for the
//! AMD-Vi backend.
//!
//! Mirrors Linux `drivers/iommu/amd/init.c`:
//! - `get_highest_supported_ivhd_type`: of the IVHD block types the
//!   firmware lists for one IOMMU (10h / 11h / 40h), only the highest
//!   supported type is used, so a unit described twice is counted once;
//! - `init_iommu_from_acpi`: IVHD device entries (select / range / alias /
//!   extended select / special IOAPIC + HPET / ACPI HID), with
//!   `ivhd_entry_length` for the entry sizes;
//! - `init_memory_definitions` + `init_unity_map_range`: IVMD blocks with
//!   the unity-map or exclusion flag become direct-mapped regions
//!   (exclusion ranges are read/write unity maps, as Linux treats them).
//!
//! Pure byte-slice code: the boot path feeds it the table copy kept by
//! `narf_acpi::ivrs_table_copy`, tests feed synthetic tables.

extern crate alloc;

use alloc::vec::Vec;

/// IVRS header: SDT header (36) + IVinfo (4) + reserved (8).
pub const IVRS_HEADER_LENGTH: usize = 48;
/// Highest IVHD type Linux understands (`ACPI_IVHD_TYPE_MAX_SUPPORTED`).
pub const IVHD_TYPE_MAX_SUPPORTED: u8 = 0x40;

pub const IVHD_DEV_ALL: u8 = 0x01;
pub const IVHD_DEV_SELECT: u8 = 0x02;
pub const IVHD_DEV_SELECT_RANGE_START: u8 = 0x03;
pub const IVHD_DEV_RANGE_END: u8 = 0x04;
pub const IVHD_DEV_ALIAS: u8 = 0x42;
pub const IVHD_DEV_ALIAS_RANGE: u8 = 0x43;
pub const IVHD_DEV_EXT_SELECT: u8 = 0x46;
pub const IVHD_DEV_EXT_SELECT_RANGE: u8 = 0x47;
pub const IVHD_DEV_SPECIAL: u8 = 0x48;
pub const IVHD_DEV_ACPI_HID: u8 = 0xf0;

pub const IVHD_SPECIAL_IOAPIC: u8 = 1;
pub const IVHD_SPECIAL_HPET: u8 = 2;

/// IVHD header flags (Linux `IVHD_FLAG_*_MASK`): recommended control
/// register settings.
pub const IVHD_FLAG_HT_TUN_EN: u8 = 0x01;
pub const IVHD_FLAG_PASSPW_EN: u8 = 0x02;
pub const IVHD_FLAG_RESPASSPW_EN: u8 = 0x04;
pub const IVHD_FLAG_ISOC_EN: u8 = 0x08;

pub const ACPI_IVMD_TYPE_ALL: u8 = 0x20;
pub const ACPI_IVMD_TYPE: u8 = 0x21;
pub const ACPI_IVMD_TYPE_RANGE: u8 = 0x22;
pub const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
pub const IVMD_FLAG_IR: u8 = 0x02;
pub const IVMD_FLAG_IW: u8 = 0x04;
pub const IVMD_FLAG_EXCL_RANGE: u8 = 0x08;

/// Device-entry DTE setting flags (Linux `ACPI_DEVFLAG_*`).
pub const ACPI_DEVFLAG_INITPASS: u8 = 0x01;
pub const ACPI_DEVFLAG_EXTINT: u8 = 0x02;
pub const ACPI_DEVFLAG_NMI: u8 = 0x04;
pub const ACPI_DEVFLAG_SYSMGT1: u8 = 0x10;
pub const ACPI_DEVFLAG_SYSMGT2: u8 = 0x20;
pub const ACPI_DEVFLAG_LINT0: u8 = 0x40;
pub const ACPI_DEVFLAG_LINT1: u8 = 0x80;

/// Requester-ID range with the DTE setting flags of its device entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DevRange {
    pub first: u16,
    pub last: u16,
    pub flags: u8,
    /// Extended flags (types 46h/47h; bit 31 = ATS disabled).
    pub ext: u32,
}

/// Requesters `first..=last` reach the IOMMU as `alias` (Linux
/// `alias_table`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AliasRange {
    pub first: u16,
    pub last: u16,
    pub alias: u16,
}

/// IVHD special device (entry type 48h): IOAPIC or HPET with the
/// requester ID it uses for interrupts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpecialDevice {
    /// [`IVHD_SPECIAL_IOAPIC`] or [`IVHD_SPECIAL_HPET`].
    pub kind: u8,
    /// IOAPIC ID / HPET number.
    pub handle: u8,
    pub devid: u16,
    pub flags: u8,
}

/// ACPI HID device (entry type F0h, IVHD 40h only).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AcpiHidDevice {
    pub hid: [u8; 8],
    pub devid: u16,
    pub flags: u8,
}

/// One IOMMU unit (an IVHD block of the selected type).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IvhdUnit {
    pub ivhd_type: u8,
    pub flags: u8,
    /// Requester ID of the IOMMU itself.
    pub devid: u16,
    pub cap_ptr: u16,
    pub mmio_phys: u64,
    pub pci_seg: u16,
    pub info: u16,
    pub efr_attr: u32,
    /// Copy of the MMIO extended feature register (types 11h / 40h; 0 for
    /// 10h).
    pub efr_reg: u64,
    pub devices: Vec<DevRange>,
    pub aliases: Vec<AliasRange>,
    pub specials: Vec<SpecialDevice>,
    pub acpi_hids: Vec<AcpiHidDevice>,
}

/// IVMD unity / exclusion range, page aligned (Linux `unity_map_entry`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnityRange {
    pub pci_seg: u16,
    pub first: u16,
    pub last: u16,
    /// First byte (page aligned).
    pub start: u64,
    /// One past the last byte (page aligned).
    pub end: u64,
    /// bit 0 = read, bit 1 = write (Linux `prot = flags >> 1`).
    pub prot: u8,
}

/// Decoded IVRS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IvrsInfo {
    pub iv_info: u32,
    /// The IVHD type used (Linux `amd_iommu_target_ivhd_type`).
    pub ivhd_type: u8,
    pub units: Vec<IvhdUnit>,
    pub unity: Vec<UnityRange>,
}

/// Why an IVRS was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IvrsError {
    /// Shorter than the 48-byte header, or the SDT length disagrees.
    Truncated,
    /// Signature is not `IVRS`.
    BadSignature,
    /// No IVHD block of a supported type.
    NoUnits,
    /// An IVHD / IVMD block overruns the table or has a zero length.
    BadBlock,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    (u32_at(b, o) as u64) | ((u32_at(b, o + 4) as u64) << 32)
}

/// Linux `get_ivhd_header_size`.
pub fn ivhd_header_size(ivhd_type: u8) -> usize {
    match ivhd_type {
        0x10 => 24,
        0x11 | 0x40 => 40,
        _ => 0,
    }
}

/// Linux `ivhd_entry_length`: 4 << (type >> 6) for fixed entries; ACPI
/// HID entries carry their UID length at offset 21. 0 = unknown.
pub fn ivhd_entry_length(entry: &[u8]) -> usize {
    let ty = entry[0];
    if ty < 0x80 {
        4 << (ty >> 6)
    } else if ty == IVHD_DEV_ACPI_HID && entry.len() > 21 {
        entry[21] as usize + 22
    } else {
        0
    }
}

/// Linux `get_highest_supported_ivhd_type`: the last type listed for the
/// first block's IOMMU, scanning while types stay `<= 40h`.
fn highest_ivhd_type(t: &[u8]) -> Result<u8, IvrsError> {
    let mut p = IVRS_HEADER_LENGTH;
    if p + 8 > t.len() {
        return Err(IvrsError::NoUnits);
    }
    let mut last = t[p];
    let devid = u16_at(t, p + 4);
    while p + 8 <= t.len() && t[p] <= IVHD_TYPE_MAX_SUPPORTED {
        let len = u16_at(t, p + 2) as usize;
        if len == 0 || p + len > t.len() {
            return Err(IvrsError::BadBlock);
        }
        if u16_at(t, p + 4) == devid {
            last = t[p];
        }
        p += len;
    }
    if ivhd_header_size(last) == 0 {
        return Err(IvrsError::NoUnits);
    }
    Ok(last)
}

/// Decode a whole IVRS table (SDT header included). The checksum is
/// checked by `narf_acpi::parse_ivrs` before the copy is kept.
pub fn parse(t: &[u8]) -> Result<IvrsInfo, IvrsError> {
    if t.len() < IVRS_HEADER_LENGTH {
        return Err(IvrsError::Truncated);
    }
    if &t[0..4] != b"IVRS" {
        return Err(IvrsError::BadSignature);
    }
    let total = u32_at(t, 4) as usize;
    if total < IVRS_HEADER_LENGTH || total > t.len() {
        return Err(IvrsError::Truncated);
    }
    let t = &t[..total];
    let ivhd_type = highest_ivhd_type(t)?;
    let mut info = IvrsInfo {
        iv_info: u32_at(t, 36),
        ivhd_type,
        units: Vec::new(),
        unity: Vec::new(),
    };
    let mut p = IVRS_HEADER_LENGTH;
    while p + 4 <= t.len() {
        let ty = t[p];
        let len = u16_at(t, p + 2) as usize;
        if len == 0 || p + len > t.len() {
            return Err(IvrsError::BadBlock);
        }
        let block = &t[p..p + len];
        if ty == ivhd_type {
            info.units.push(parse_ivhd(block)?);
        } else if matches!(
            ty,
            ACPI_IVMD_TYPE_ALL | ACPI_IVMD_TYPE | ACPI_IVMD_TYPE_RANGE
        ) {
            if let Some(u) = parse_ivmd(block) {
                info.unity.push(u);
            }
        }
        p += len;
    }
    if info.units.is_empty() {
        return Err(IvrsError::NoUnits);
    }
    Ok(info)
}

fn parse_ivhd(h: &[u8]) -> Result<IvhdUnit, IvrsError> {
    let ty = h[0];
    let hdr = ivhd_header_size(ty);
    if hdr == 0 || h.len() < hdr {
        return Err(IvrsError::BadBlock);
    }
    let mut u = IvhdUnit {
        ivhd_type: ty,
        flags: h[1],
        devid: u16_at(h, 4),
        cap_ptr: u16_at(h, 6),
        mmio_phys: u64_at(h, 8),
        pci_seg: u16_at(h, 16),
        info: u16_at(h, 18),
        efr_attr: u32_at(h, 20),
        efr_reg: if hdr == 40 { u64_at(h, 24) } else { 0 },
        ..IvhdUnit::default()
    };
    // Range state across SELECT_RANGE_START / ALIAS_RANGE / EXT_SELECT_RANGE
    // → RANGE_END (Linux keeps `devid_start`, `flags`, `ext_flags`,
    // `devid_to`, `alias`).
    let (mut start, mut flags, mut ext, mut alias_to, mut alias) = (0u16, 0u8, 0u32, 0u16, false);
    let mut p = hdr;
    while p + 4 <= h.len() {
        let e = &h[p..];
        let elen = ivhd_entry_length(e);
        if elen == 0 || elen > e.len() {
            break;
        }
        let devid = u16_at(e, 1);
        let eflags = e[3];
        let ext_dw = if elen >= 8 { u32_at(e, 4) } else { 0 };
        match e[0] {
            IVHD_DEV_ALL => u.devices.push(DevRange {
                first: 0,
                last: 0xffff,
                flags: eflags,
                ext: 0,
            }),
            IVHD_DEV_SELECT => u.devices.push(DevRange {
                first: devid,
                last: devid,
                flags: eflags,
                ext: 0,
            }),
            IVHD_DEV_SELECT_RANGE_START => {
                (start, flags, ext, alias) = (devid, eflags, 0, false);
            }
            IVHD_DEV_ALIAS => {
                let to = (ext_dw >> 8) as u16;
                u.devices.push(DevRange {
                    first: devid,
                    last: devid,
                    flags: eflags,
                    ext: 0,
                });
                u.devices.push(DevRange {
                    first: to,
                    last: to,
                    flags: eflags,
                    ext: 0,
                });
                u.aliases.push(AliasRange {
                    first: devid,
                    last: devid,
                    alias: to,
                });
            }
            IVHD_DEV_ALIAS_RANGE => {
                (start, flags, ext, alias) = (devid, eflags, 0, true);
                alias_to = (ext_dw >> 8) as u16;
            }
            IVHD_DEV_EXT_SELECT => u.devices.push(DevRange {
                first: devid,
                last: devid,
                flags: eflags,
                ext: ext_dw,
            }),
            IVHD_DEV_EXT_SELECT_RANGE => {
                (start, flags, ext, alias) = (devid, eflags, ext_dw, false);
            }
            IVHD_DEV_RANGE_END => {
                if alias {
                    u.aliases.push(AliasRange {
                        first: start,
                        last: devid,
                        alias: alias_to,
                    });
                    u.devices.push(DevRange {
                        first: alias_to,
                        last: alias_to,
                        flags,
                        ext,
                    });
                }
                if start <= devid {
                    u.devices.push(DevRange {
                        first: start,
                        last: devid,
                        flags,
                        ext,
                    });
                }
            }
            IVHD_DEV_SPECIAL => u.specials.push(SpecialDevice {
                kind: (ext_dw >> 24) as u8,
                handle: ext_dw as u8,
                devid: (ext_dw >> 8) as u16,
                flags: eflags,
            }),
            IVHD_DEV_ACPI_HID if ty == 0x40 && elen >= 12 => {
                let mut hid = [0u8; 8];
                hid.copy_from_slice(&e[4..12]);
                u.acpi_hids.push(AcpiHidDevice {
                    hid,
                    devid,
                    flags: eflags,
                });
                u.devices.push(DevRange {
                    first: devid,
                    last: devid,
                    flags: eflags,
                    ext: 0,
                });
            }
            _ => {}
        }
        p += elen;
    }
    // Special devices are translated by this unit too (Linux
    // `set_dev_entry_from_acpi(iommu, devid, ...)` after
    // `add_special_device`).
    for s in u.specials.clone() {
        u.devices.push(DevRange {
            first: s.devid,
            last: s.devid,
            flags: s.flags,
            ext: 0,
        });
    }
    Ok(u)
}

/// Linux `init_unity_map_range` (only blocks with the unity or exclusion
/// flag reach it).
fn parse_ivmd(m: &[u8]) -> Option<UnityRange> {
    if m.len() < 32 {
        return None;
    }
    let flags = m[1];
    if flags & (IVMD_FLAG_UNITY_MAP | IVMD_FLAG_EXCL_RANGE) == 0 {
        return None;
    }
    let devid = u16_at(m, 4);
    let aux = u16_at(m, 6);
    let (first, last) = match m[0] {
        ACPI_IVMD_TYPE => (devid, devid),
        ACPI_IVMD_TYPE_ALL => (0, 0xffff),
        ACPI_IVMD_TYPE_RANGE => (devid, aux),
        _ => return None,
    };
    let page_align = |v: u64| v.checked_add(0xfff).map(|x| x & !0xfff);
    let start = page_align(u64_at(m, 16))?;
    let end = start.checked_add(page_align(u64_at(m, 24))?)?;
    let prot = if flags & IVMD_FLAG_EXCL_RANGE != 0 {
        (IVMD_FLAG_IW | IVMD_FLAG_IR) >> 1
    } else {
        (flags >> 1) & 0x3
    };
    Some(UnityRange {
        pci_seg: u16_at(m, 8),
        first,
        last,
        start,
        end,
        prot,
    })
}

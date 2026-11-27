//! DMI system identification: the strings Linux `dmi_scan.c`'s
//! `dmi_decode` saves from the BIOS, system, baseboard and chassis
//! structures (`dmi_ident[]`), which `dmi_get_system_info` hands out and
//! `drivers/firmware/dmi-id.c` publishes as `/sys/class/dmi/id`.
//!
//! Each slot is kept as `dmi_decode` leaves it:
//!
//! - the FIRST structure of a type that has the field fills it
//!   (`if (dmi_ident[slot]) return`);
//! - a field the structure's formatted area does not reach is absent;
//! - a string is `dmi_string`'s copy: string 0, a string past the set and
//!   an all-space string are empty, anything else is kept byte for byte
//!   (no trimming);
//! - the BIOS and EC firmware releases are `"major.minor"`, absent at
//!   `0xFF.0xFF`;
//! - the UUID is `%pUl` (first three fields little-endian) from SMBIOS 2.6
//!   and `%pUb` below, absent when all 00 or all FF;
//! - the chassis type is the type byte's low 7 bits in decimal.

use alloc::vec::Vec;

use crate::{RawStructure, RawTable};

/// `enum dmi_field` (`include/linux/mod_devicetable.h`): the slots
/// `dmi_decode` fills, in Linux's order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmiField {
    BiosVendor,
    BiosVersion,
    BiosDate,
    BiosRelease,
    EcFirmwareRelease,
    SysVendor,
    ProductName,
    ProductVersion,
    ProductSerial,
    ProductUuid,
    ProductSku,
    ProductFamily,
    BoardVendor,
    BoardName,
    BoardVersion,
    BoardSerial,
    BoardAssetTag,
    ChassisVendor,
    ChassisType,
    ChassisVersion,
    ChassisSerial,
    ChassisAssetTag,
}

/// `DMI_STRING_MAX` for the slots above.
const SLOTS: usize = DmiField::ChassisAssetTag as usize + 1;

/// `dmi_ident[]` decoded from one structure table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DmiIdent {
    slots: [Option<Vec<u8>>; SLOTS],
}

/// `DMI_ENTRY_BIOS`, `_SYSTEM`, `_BASEBOARD`, `_CHASSIS`.
const BIOS: u8 = 0;
const SYSTEM: u8 = 1;
const BASEBOARD: u8 = 2;
const CHASSIS: u8 = 3;

impl DmiIdent {
    /// `dmi_decode` over every structure `dmi_walk` passes (types 0-3).
    /// The UUID's byte order follows the table's `dmi_ver`
    /// ([`RawTable::version`]).
    pub fn decode(table: &RawTable) -> Self {
        let mut id = Self::default();
        let version = table.version();
        for s in table.structures() {
            match s.kind {
                BIOS => {
                    id.save_ident(&s, DmiField::BiosVendor, 4);
                    id.save_ident(&s, DmiField::BiosVersion, 5);
                    id.save_ident(&s, DmiField::BiosDate, 8);
                    id.save_release(&s, DmiField::BiosRelease, 21);
                    id.save_release(&s, DmiField::EcFirmwareRelease, 23);
                }
                SYSTEM => {
                    id.save_ident(&s, DmiField::SysVendor, 4);
                    id.save_ident(&s, DmiField::ProductName, 5);
                    id.save_ident(&s, DmiField::ProductVersion, 6);
                    id.save_ident(&s, DmiField::ProductSerial, 7);
                    id.save_uuid(&s, DmiField::ProductUuid, 8, version);
                    id.save_ident(&s, DmiField::ProductSku, 25);
                    id.save_ident(&s, DmiField::ProductFamily, 26);
                }
                BASEBOARD => {
                    id.save_ident(&s, DmiField::BoardVendor, 4);
                    id.save_ident(&s, DmiField::BoardName, 5);
                    id.save_ident(&s, DmiField::BoardVersion, 6);
                    id.save_ident(&s, DmiField::BoardSerial, 7);
                    id.save_ident(&s, DmiField::BoardAssetTag, 8);
                }
                CHASSIS => {
                    id.save_ident(&s, DmiField::ChassisVendor, 4);
                    id.save_type(&s, DmiField::ChassisType, 5);
                    id.save_ident(&s, DmiField::ChassisVersion, 6);
                    id.save_ident(&s, DmiField::ChassisSerial, 7);
                    id.save_ident(&s, DmiField::ChassisAssetTag, 8);
                }
                _ => {}
            }
        }
        id
    }

    /// `dmi_get_system_info(field)`: `None` for a field the table does
    /// not have (Linux's NULL), otherwise the saved bytes, which may be
    /// empty.
    pub fn get(&self, field: DmiField) -> Option<&[u8]> {
        self.slots[field as usize].as_deref()
    }

    fn slot(&mut self, field: DmiField) -> &mut Option<Vec<u8>> {
        &mut self.slots[field as usize]
    }

    /// `dmi_save_ident`: the string whose index is at `offset`.
    fn save_ident(&mut self, s: &RawStructure<'_>, field: DmiField, offset: usize) {
        if self.slot(field).is_some() || (s.length() as usize) <= offset {
            return;
        }
        *self.slot(field) = Some(dmi_string(s, s.bytes[offset]));
    }

    /// `dmi_save_release`: `"major.minor"` from the bytes at `index - 1`
    /// and `index`. Linux's bound is `dm->length < index`, so a minor at
    /// the first byte past the formatted area is still read.
    fn save_release(&mut self, s: &RawStructure<'_>, field: DmiField, index: usize) {
        if self.slot(field).is_some() || (s.length() as usize) < index {
            return;
        }
        let (major, minor) = (s.bytes[index - 1], s.bytes[index]);
        if major == 0xFF && minor == 0xFF {
            return;
        }
        *self.slot(field) = Some(alloc::format!("{major}.{minor}").into_bytes());
    }

    /// `dmi_save_uuid`: the 16 bytes at `index`, absent when all 00 or all
    /// FF.
    fn save_uuid(&mut self, s: &RawStructure<'_>, field: DmiField, index: usize, version: u32) {
        if self.slot(field).is_some() || (s.length() as usize) < index + 16 {
            return;
        }
        let d = &s.bytes[index..index + 16];
        if d.iter().all(|&b| b == 0x00) || d.iter().all(|&b| b == 0xFF) {
            return;
        }
        // "As of version 2.6 of the SMBIOS specification, the first 3
        // fields of the UUID are supposed to be little-endian encoded."
        let order: [usize; 16] = if version >= 0x02_06_00 {
            [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        } else {
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        };
        let mut text = Vec::with_capacity(36);
        for (i, &at) in order.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                text.push(b'-');
            }
            text.extend_from_slice(alloc::format!("{:02x}", d[at]).as_bytes());
        }
        *self.slot(field) = Some(text);
    }

    /// `dmi_save_type`: the byte at `index`, low 7 bits, in decimal.
    fn save_type(&mut self, s: &RawStructure<'_>, field: DmiField, index: usize) {
        if self.slot(field).is_some() || (s.length() as usize) <= index {
            return;
        }
        *self.slot(field) = Some(alloc::format!("{}", s.bytes[index] & 0x7F).into_bytes());
    }
}

/// `dmi_string` (through `dmi_string_nosave`): string `idx` of `s`'s set.
///
/// ```text
/// if (s) {
///     while (--s > 0 && *bp)
///         bp += strlen(bp) + 1;
///     /* Strings containing only spaces are considered empty */
///     ...
/// }
/// return dmi_empty_string;
/// ```
fn dmi_string(s: &RawStructure<'_>, idx: u8) -> Vec<u8> {
    if idx == 0 {
        return Vec::new();
    }
    // The walk guarantees the set ends in a double NUL.
    let set = s.strings();
    let len_at = |at: usize| {
        set[at..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(set.len() - at)
    };
    let mut at = 0;
    let mut left = idx;
    loop {
        left -= 1;
        if left == 0 || at >= set.len() || set[at] == 0 {
            break;
        }
        at += len_at(at) + 1;
    }
    if at >= set.len() {
        return Vec::new();
    }
    let string = &set[at..at + len_at(at)];
    if string.iter().all(|&b| b == b' ') {
        Vec::new()
    } else {
        string.to_vec()
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
//! SMBIOS board-data-file (BDF) identification shared by the ath drivers.
//!
//! `ath11k_core_check_smbios` and its `SmbiosBdf` result lived in the ath11k
//! driver's `board` module; promoted here so ath10k can read the board variant
//! without depending on an Atheros driver crate. The ath11k driver keeps its
//! own copies of these QCA SMBIOS constants for the rest of its board/QMI
//! paths; the private copies below make this unit self-contained.

use alloc::vec::Vec;

/// `ATH11K_QMI_BDF_EXT_STR_LENGTH` — `target.bdf_ext` incl. its NUL.
const ATH11K_QMI_BDF_EXT_STR_LENGTH: usize = 0x20;
const ATH11K_SMBIOS_BDF_EXT_TYPE: u8 = 0xF8;
const ATH11K_SMBIOS_BDF_EXT_LENGTH: u8 = 0x9;
const ATH11K_SMBIOS_BDF_EXT_MAGIC: &[u8] = b"BDF_";
const ATH11K_SMBIOS_CC_ISO: u8 = 1;
const ATH11K_SMBIOS_CC_WW: u8 = 2;

/// What `ath11k_core_check_cc_code_bdfext` takes from SMBIOS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbiosBdf {
    /// `ab->new_alpha2` when the structure sets a country.
    pub alpha2: Option<[u8; 2]>,
    /// `target.bdf_ext` (variant, magic stripped); empty = none.
    pub bdf_ext: Vec<u8>,
}

/// `ath11k_core_check_cc_code_bdfext` for one SMBIOS structure
/// (`structure` = formatted area followed by its string set), applied
/// to `state` the way `dmi_walk` applies it to every structure in
/// table order. Once `bdf_ext` is set, later structures are ignored.
pub fn smbios_bdf_ext(structure: &[u8], state: &mut SmbiosBdf) {
    if !state.bdf_ext.is_empty() || structure.len() < 2 {
        return;
    }
    if structure[0] != ATH11K_SMBIOS_BDF_EXT_TYPE {
        return;
    }
    if structure[1] != ATH11K_SMBIOS_BDF_EXT_LENGTH || structure.len() < 9 {
        // "wrong smbios bdf ext type length"
        return;
    }
    // struct ath11k_smbios_bdf: hdr(4) features_disabled(1)
    // country_code_flag(1) cc_code(2) bdf_enabled(1) bdf_ext[]
    let cc_flag = structure[5];
    let cc_code = u16::from_le_bytes([structure[6], structure[7]]);
    match cc_flag {
        ATH11K_SMBIOS_CC_ISO => {
            state.alpha2 = Some([(cc_code >> 8) as u8, cc_code as u8]);
        }
        ATH11K_SMBIOS_CC_WW => state.alpha2 = Some([b'0', b'0']),
        _ => {}
    }
    if structure[8] == 0 {
        // "bdf variant name not found"
        return;
    }
    // bdf_ext[] is the first string of the string set.
    let rest = &structure[9..];
    let s = &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())];
    if !s.starts_with(ATH11K_SMBIOS_BDF_EXT_MAGIC) {
        return;
    }
    let len = s.len().min(ATH11K_QMI_BDF_EXT_STR_LENGTH);
    if s[..len].iter().any(|&b| !(0x20..=0x7e).contains(&b)) {
        // "bdf variant name contains non ascii chars"
        return;
    }
    // strscpy(bdf_ext, bdf_ext + strlen(magic), 32): on overflow the
    // truncated copy stays in place (and is used).
    let v = &s[ATH11K_SMBIOS_BDF_EXT_MAGIC.len()..];
    state.bdf_ext = v[..v.len().min(ATH11K_QMI_BDF_EXT_STR_LENGTH - 1)].to_vec();
}

/// `ath11k_core_check_smbios` over `table`: `bdf_ext` cleared, then
/// `dmi_walk(ath11k_core_check_cc_code_bdfext)`. Only type-0xF8
/// structures are handed over — the callback returns at once for every
/// other type, so the result is the same.
pub fn check_smbios_in(table: &narf_firmware_smbios::RawTable) -> SmbiosBdf {
    let mut state = SmbiosBdf::default();
    for s in table.structures_of_type(ATH11K_SMBIOS_BDF_EXT_TYPE) {
        smbios_bdf_ext(s.bytes, &mut state);
    }
    state
}

/// `ath11k_core_check_smbios` against the table the boot-time DMI scan
/// retained. Empty (Linux's `-ENODATA`, "SMBIOS bdf variant name not
/// set") when the firmware gave no table or no valid `BDF_` string.
pub fn check_smbios() -> SmbiosBdf {
    narf_firmware_smbios::boot_table().map_or_else(SmbiosBdf::default, check_smbios_in)
}

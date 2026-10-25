//! Board data: `board-2.bin` parsing, board-name strings and the
//! SMBIOS board-data-file variant — pure functions, no I/O.
//!
//! Ported from Linux `drivers/net/wireless/ath/ath11k/core.c`:
//!
//! - `__ath11k_core_create_board_name` (+ the `create_board_name` /
//!   `create_fallback_board_name` / `create_bus_type_board_name` /
//!   `create_chip_id_board_name` wrappers) → [`board_name`].
//! - `ath11k_core_fetch_board_data_api_n` +
//!   `ath11k_core_parse_bd_ie_board` → [`fetch_board_data_api_n`].
//! - `ath11k_core_check_cc_code_bdfext` → [`smbios_bdf_ext`].
//! - `ath11k_core_fetch_bdf` / `ath11k_core_fetch_regdb` — the search
//!   order, as data: [`bdf_search`], [`regdb_search`]. The QMI layer
//!   ([`super::wlfw`]) walks them against the firmware store.
//!
//! `board-2.bin` layout (`hw.h`):
//!
//! ```text
//! "QCA-ATH11K-BOARD\0" padded to 4 bytes (20)
//! repeated: struct ath11k_fw_ie { __le32 id; __le32 len; u8 data[len]; } padded to 4
//!   id 0 ATH11K_BD_IE_BOARD / 1 ATH11K_BD_IE_REGDB, data = sub-IEs:
//!     id 0 *_NAME  (the board-name string, no NUL)
//!     id 1 *_DATA  (the blob for the names that precede it)
//! ```
//!
//! References (BSD-3-Clause-Clear, citation + adaptation permitted):
//! `core.c`, `core.h` (`struct ath11k_smbios_bdf`,
//! `ATH11K_SMBIOS_*`), `hw.h` (`ATH11K_BOARD_MAGIC`, `struct
//! ath11k_fw_ie`, `enum ath11k_bd_ie_*`), `qmi.h`
//! (`ATH11K_QMI_BDF_EXT_STR_LENGTH`).

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "board_parser_tests.rs"]
mod parser_tests;

/// `ATH11K_BOARD_MAGIC`.
pub const ATH11K_BOARD_MAGIC: &[u8] = b"QCA-ATH11K-BOARD";
/// `ATH11K_BOARD_API2_FILE`.
pub const ATH11K_BOARD_API2_FILE: &str = "board-2.bin";
/// `ATH11K_DEFAULT_BOARD_FILE`.
pub const ATH11K_DEFAULT_BOARD_FILE: &str = "board.bin";
/// `ATH11K_DEFAULT_CAL_FILE`.
pub const ATH11K_DEFAULT_CAL_FILE: &str = "caldata.bin";
/// `ATH11K_M3_FILE`.
pub const ATH11K_M3_FILE: &str = "m3.bin";
/// `ATH11K_REGDB_FILE_NAME`.
pub const ATH11K_REGDB_FILE_NAME: &str = "regdb.bin";

/// `enum ath11k_bd_ie_type`.
pub const ATH11K_BD_IE_BOARD: u32 = 0;
pub const ATH11K_BD_IE_REGDB: u32 = 1;
/// `enum ath11k_bd_ie_board_type` / `ath11k_bd_ie_regdb_type` (same
/// values for both).
pub const ATH11K_BD_IE_BOARD_NAME: u32 = 0;
pub const ATH11K_BD_IE_BOARD_DATA: u32 = 1;
pub const ATH11K_BD_IE_REGDB_NAME: u32 = 0;
pub const ATH11K_BD_IE_REGDB_DATA: u32 = 1;

/// `sizeof(struct ath11k_fw_ie)`.
const FW_IE_HDR: usize = 8;

/// `BOARD_NAME_SIZE` — `scnprintf` keeps at most 199 characters.
pub const BOARD_NAME_SIZE: usize = 200;
/// `ATH11K_QMI_BDF_EXT_STR_LENGTH` — `target.bdf_ext` incl. its NUL.
pub const ATH11K_QMI_BDF_EXT_STR_LENGTH: usize = 0x20;

/// `ATH11K_SMBIOS_BDF_EXT_TYPE`.
pub const ATH11K_SMBIOS_BDF_EXT_TYPE: u8 = 0xF8;
/// `ATH11K_SMBIOS_BDF_EXT_LENGTH` (formatted area, strings excluded).
pub const ATH11K_SMBIOS_BDF_EXT_LENGTH: u8 = 0x9;
/// `ATH11K_SMBIOS_BDF_EXT_MAGIC`.
pub const ATH11K_SMBIOS_BDF_EXT_MAGIC: &[u8] = b"BDF_";
/// `enum ath11k_smbios_cc_type`.
pub const ATH11K_SMBIOS_CC_DISABLE: u8 = 0;
pub const ATH11K_SMBIOS_CC_ISO: u8 = 1;
pub const ATH11K_SMBIOS_CC_WW: u8 = 2;

/// `ath11k_bus_str(ATH11K_BUS_PCI)`.
pub const BUS_PCI: &str = "pci";

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

// ── Board names ────────────────────────────────────────────────────

/// `enum ath11k_bdf_name_type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BdfNameType {
    Full,
    BusName,
    ChipId,
}

/// The `ab->id` + `ab->qmi.target` fields a board name is built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoardId {
    /// `ab->id.bdf_search == ATH11K_BDF_SEARCH_BUS_AND_BOARD` (set by
    /// `ath11k_pci_probe` for WCN6855 only).
    pub search_bus_and_board: bool,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub chip_id: u32,
    pub board_id: u32,
    /// `target.bdf_ext` without its NUL (empty = no variant).
    pub bdf_ext: Vec<u8>,
}

/// `scnprintf` into a `BOARD_NAME_SIZE` buffer: at most 199 bytes.
fn truncate(mut s: String, size: usize) -> String {
    if s.len() >= size {
        // Every byte written is ASCII (format strings + hex/decimal +
        // a printable-ASCII variant), so any cut is a char boundary.
        s.truncate(size - 1);
    }
    s
}

/// `__ath11k_core_create_board_name(ab, name, BOARD_NAME_SIZE,
/// with_variant, name_type)`. `chip_id` / `board_id` print with `%d`,
/// i.e. as signed 32-bit.
pub fn board_name(id: &BoardId, with_variant: bool, name_type: BdfNameType) -> String {
    // char variant[9 + ATH11K_QMI_BDF_EXT_STR_LENGTH]
    let mut variant = String::new();
    if with_variant && !id.bdf_ext.is_empty() {
        let _ = write!(variant, ",variant=");
        for &b in &id.bdf_ext {
            variant.push(b as char);
        }
        variant = truncate(variant, 9 + ATH11K_QMI_BDF_EXT_STR_LENGTH);
    }
    let chip = id.chip_id as i32;
    let board = id.board_id as i32;
    let mut s = String::new();
    if id.search_bus_and_board {
        match name_type {
            BdfNameType::Full => {
                let _ = write!(
                    s,
                    "bus={},vendor={:04x},device={:04x},subsystem-vendor={:04x},\
                     subsystem-device={:04x},qmi-chip-id={},qmi-board-id={}{}",
                    BUS_PCI,
                    id.vendor,
                    id.device,
                    id.subsystem_vendor,
                    id.subsystem_device,
                    chip,
                    board,
                    variant
                );
            }
            BdfNameType::BusName => {
                let _ = write!(s, "bus={}", BUS_PCI);
            }
            BdfNameType::ChipId => {
                let _ = write!(s, "bus={},qmi-chip-id={}", BUS_PCI, chip);
            }
        }
    } else {
        let _ = write!(
            s,
            "bus={},qmi-chip-id={},qmi-board-id={}{}",
            BUS_PCI, chip, board, variant
        );
    }
    truncate(s, BOARD_NAME_SIZE)
}

/// One step of a board-data search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardSearch {
    /// `ath11k_core_fetch_board_data_api_n(.., name, ie, name_id,
    /// data_id)` on `board-2.bin`.
    Api2 { name: String, ie_id: u32 },
    /// `ath11k_core_fetch_board_data_api_1(.., file)`.
    Api1 { file: &'static str },
}

/// `ath11k_core_fetch_bdf`'s order: full name (with variant),
/// fallback name (no variant), chip-id name, then `board.bin`.
pub fn bdf_search(id: &BoardId) -> [BoardSearch; 4] {
    [
        BoardSearch::Api2 {
            name: board_name(id, true, BdfNameType::Full),
            ie_id: ATH11K_BD_IE_BOARD,
        },
        BoardSearch::Api2 {
            name: board_name(id, false, BdfNameType::Full),
            ie_id: ATH11K_BD_IE_BOARD,
        },
        BoardSearch::Api2 {
            name: board_name(id, false, BdfNameType::ChipId),
            ie_id: ATH11K_BD_IE_BOARD,
        },
        BoardSearch::Api1 {
            file: ATH11K_DEFAULT_BOARD_FILE,
        },
    ]
}

/// `ath11k_core_fetch_regdb`'s order: full name, `bus=<bus>`, then
/// `regdb.bin`.
pub fn regdb_search(id: &BoardId) -> [BoardSearch; 3] {
    [
        BoardSearch::Api2 {
            name: board_name(id, true, BdfNameType::Full),
            ie_id: ATH11K_BD_IE_REGDB,
        },
        BoardSearch::Api2 {
            name: board_name(id, false, BdfNameType::BusName),
            ie_id: ATH11K_BD_IE_REGDB,
        },
        BoardSearch::Api1 {
            file: ATH11K_REGDB_FILE_NAME,
        },
    ]
}

// ── board-2.bin ────────────────────────────────────────────────────

/// Why `fetch_board_data_api_n` failed, with the Linux return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    /// Shorter than the 17-byte NUL-terminated magic ("file too
    /// short") — `-EINVAL`.
    ShortMagic,
    /// "found invalid board magic" — `-EINVAL`.
    BadMagic,
    /// Shorter than the 20-byte padded magic — `-EINVAL`.
    NoRoomAfterMagic,
    /// Top-level IE longer than the bytes left ("invalid length for
    /// board ie_id") — `-EINVAL`.
    BadIeLength {
        ie_id: u32,
        ie_len: usize,
        len: usize,
    },
    /// Sub-IE longer than its parent ("invalid %s length") —
    /// `-EINVAL`.
    BadSubIeLength { buf_len: usize, need: usize },
    /// No matching name, or a matching name with no data after it
    /// (`-ENODATA` via the `!bd->data || !bd->len` check).
    NoData,
}

impl BoardError {
    /// The negative Linux errno, as a positive number.
    pub fn errno(self) -> i32 {
        match self {
            BoardError::NoData => 61, // ENODATA
            _ => 22,                  // EINVAL
        }
    }
}

/// `ath11k_core_parse_bd_ie_board`: walk the sub-IEs of one top-level
/// IE. `Ok(Some(range))` = the data IE after a matching name;
/// `Ok(None)` = `-ENOENT` (no match). A name match is never reset by
/// a later non-matching name — the first data IE after any match is
/// taken, exactly as Linux does.
fn parse_bd_ie_board(
    file: &[u8],
    start: usize,
    mut buf_len: usize,
    boardname: &[u8],
    name_id: u32,
    data_id: u32,
) -> Result<Option<(usize, usize)>, BoardError> {
    let mut pos = start;
    let mut name_match_found = false;
    while buf_len > FW_IE_HDR {
        let board_ie_id = le32(file, pos);
        let mut board_ie_len = le32(file, pos + 4) as usize;
        let data = pos + FW_IE_HDR;
        buf_len -= FW_IE_HDR;
        pos += FW_IE_HDR;

        if buf_len < align4(board_ie_len) {
            return Err(BoardError::BadSubIeLength {
                buf_len,
                need: align4(board_ie_len),
            });
        }

        if board_ie_id == name_id {
            if board_ie_len == boardname.len() && &file[data..data + board_ie_len] == boardname {
                name_match_found = true;
            }
        } else if board_ie_id == data_id && name_match_found {
            return Ok(Some((data, board_ie_len)));
        }
        // (Linux warns "unknown %s id found" for any other id.)
        board_ie_len = align4(board_ie_len);
        buf_len -= board_ie_len;
        pos += board_ie_len;
    }
    Ok(None)
}

/// `ath11k_core_fetch_board_data_api_n` on the bytes of
/// `board-2.bin`: the `(offset, len)` of the data IE for `boardname`
/// inside top-level IEs of type `ie_id_match`. A zero-length match is
/// [`BoardError::NoData`], as Linux's final `!bd->len` check makes it.
pub fn fetch_board_data_api_n(
    file: &[u8],
    boardname: &[u8],
    ie_id_match: u32,
    name_id: u32,
    data_id: u32,
) -> Result<(usize, usize), BoardError> {
    // magic has an extra NUL byte
    let magic_len = ATH11K_BOARD_MAGIC.len() + 1;
    if file.len() < magic_len {
        return Err(BoardError::ShortMagic);
    }
    if &file[..ATH11K_BOARD_MAGIC.len()] != ATH11K_BOARD_MAGIC || file[magic_len - 1] != 0 {
        return Err(BoardError::BadMagic);
    }
    let magic_len = align4(magic_len);
    if file.len() < magic_len {
        return Err(BoardError::NoRoomAfterMagic);
    }
    let mut pos = magic_len;
    let mut len = file.len() - magic_len;
    let mut found = None;
    while len > FW_IE_HDR {
        let ie_id = le32(file, pos);
        let mut ie_len = le32(file, pos + 4) as usize;
        len -= FW_IE_HDR;
        pos += FW_IE_HDR;
        if len < align4(ie_len) {
            return Err(BoardError::BadIeLength { ie_id, ie_len, len });
        }
        if ie_id == ie_id_match {
            if let Some(r) = parse_bd_ie_board(file, pos, ie_len, boardname, name_id, data_id)? {
                found = Some(r);
                break;
            }
        }
        ie_len = align4(ie_len);
        len -= ie_len;
        pos += ie_len;
    }
    match found {
        Some((off, n)) if n != 0 => Ok((off, n)),
        _ => Err(BoardError::NoData),
    }
}

/// One `struct ath11k_fw_ie`: `(id, data)`.
pub type FwIe = (u32, Vec<u8>);

/// Build a `board-2.bin` image (for tests and tooling): magic, then
/// one top-level IE per `(ie_id, [(sub_id, bytes)])`, each padded.
pub fn build_board2(ies: &[(u32, Vec<FwIe>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ATH11K_BOARD_MAGIC);
    out.push(0);
    out.resize(align4(out.len()), 0);
    for (id, subs) in ies {
        let mut body = Vec::new();
        for (sid, data) in subs {
            body.extend_from_slice(&sid.to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(data);
            body.resize(align4(body.len()), 0);
        }
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out.resize(align4(out.len()), 0);
    }
    out
}

// ── SMBIOS variant ─────────────────────────────────────────────────

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

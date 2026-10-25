//! Owned AX firmware selection. No hardware state is changed here.

use alloc::vec::Vec;
use core::ops::Range;

use super::fw::FwError;
use super::fwdl::{self, FwHeader, FwSection, FWDL_SECTION_MAX_NUM};
use super::mac::ChipId;

const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
const EMPTY: FwSection = FwSection {
    kind: 0,
    dladdr: 0,
    len: 0,
    chksum: false,
    redl: false,
    payload_off: 0,
};

/// Only a missing file permits trying an older filename. Invalid signatures,
/// revoked authority and invalid images abort the operation.
pub trait Files {
    fn load(&mut self, name: &'static str) -> Result<Vec<u8>, FwError>;
}

/// The selected image and all parsed offsets share one immutable owner.
#[derive(Debug)]
pub struct PreparedFirmware {
    bytes: Vec<u8>,
    image: Range<usize>,
    sections: [FwSection; FWDL_SECTION_MAX_NUM],
    header: FwHeader,
    name: &'static str,
    chip: ChipId,
}

impl PreparedFirmware {
    pub fn chip(&self) -> ChipId {
        self.chip
    }
    pub fn image(&self) -> &[u8] {
        &self.bytes[self.image.clone()]
    }
    pub(super) fn container(&self) -> &[u8] {
        &self.bytes
    }
    pub fn header(&self) -> &FwHeader {
        &self.header
    }
    pub fn sections(&self) -> &[FwSection] {
        &self.sections[..usize::from(self.header.section_num)]
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn payload(&self, section: usize) -> Option<&[u8]> {
        let section = self.sections().get(section)?;
        self.image()
            .get(section.payload_off..section.payload_off + section.len as usize)
    }

    /// Construct the plain AX FWHDR_DL payload: dynamic extensions stay on the
    /// host; part_size is always2020. The caller must independently establish
    /// disabled hardware secure boot before using this unmodified section list.
    /// Secure loaders need fuse-selected signatures, blacklist and overrides.
    pub fn unsecured_header(&self) -> Result<Vec<u8>, FwError> {
        // Linux can ignore later formatted security sections. Until the
        // download plan couples descriptor compaction with payload selection,
        // reject that layout instead of constructing contradictory transfers.
        if self
            .sections()
            .iter()
            .filter(|section| section.kind == 9)
            .count()
            > 1
        {
            return Err(FwError::UnsupportedFormat);
        }
        let base = if self.header.version == 0 { 32 } else { 48 };
        let end = base + self.sections().len() * 16;
        let mut output = Vec::new();
        output
            .try_reserve_exact(end)
            .map_err(|_| FwError::NoMemory)?;
        output.extend_from_slice(&self.image()[..end]);
        let original =
            u32::from_le_bytes(output[28..32].try_into().map_err(|_| FwError::BadFormat)?);
        output[28..32].copy_from_slice(&((original & !0xffff) | 2020).to_le_bytes());
        Ok(output)
    }
}

pub const fn filenames(chip: ChipId) -> &'static [&'static str] {
    match chip {
        ChipId::Rtl8852A => &["rtw89/rtw8852a_fw-1.bin", "rtw89/rtw8852a_fw.bin"],
        ChipId::Rtl8852B => &[
            "rtw89/rtw8852b_fw-2.bin",
            "rtw89/rtw8852b_fw-1.bin",
            "rtw89/rtw8852b_fw.bin",
        ],
        ChipId::Rtl8852C => &[
            "rtw89/rtw8852c_fw-2.bin",
            "rtw89/rtw8852c_fw-1.bin",
            "rtw89/rtw8852c_fw.bin",
        ],
        ChipId::Rtl8851B => &["rtw89/rtw8851b_fw-1.bin", "rtw89/rtw8851b_fw.bin"],
        ChipId::Rtl8922A => &[],
    }
}

pub fn load(files: &mut impl Files, chip: ChipId, cut: u8) -> Result<PreparedFirmware, FwError> {
    let names = filenames(chip);
    if names.is_empty() {
        return Err(FwError::UnsupportedFormat);
    }
    if cut > 15 {
        return Err(FwError::BadFormat);
    }
    for &name in names {
        let bytes = match files.load(name) {
            Err(FwError::BlobMissing) => continue,
            result => result?,
        };
        if bytes.len() > MAX_FILE_SIZE {
            return Err(FwError::BadFormat);
        }
        return prepare(bytes, name, chip, cut);
    }
    Err(FwError::BlobMissing)
}

fn prepare(
    bytes: Vec<u8>,
    name: &'static str,
    chip: ChipId,
    cut: u8,
) -> Result<PreparedFirmware, FwError> {
    let prefer_ce = matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8851B);
    let image = if prefer_ce {
        match fwdl::select_image(&bytes, cut, fwdl::FW_TYPE_NORMAL_CE) {
            Err(FwError::ImageMissing) => fwdl::select_image(&bytes, cut, fwdl::FW_TYPE_NORMAL)?,
            result => result?,
        }
    } else {
        fwdl::select_image(&bytes, cut, fwdl::FW_TYPE_NORMAL)?
    };
    let start = image.as_ptr() as usize - bytes.as_ptr() as usize;
    let range = start..start + image.len();
    let mut sections = [EMPTY; FWDL_SECTION_MAX_NUM];
    let header = fwdl::parse_auto(image, &mut sections)?;
    Ok(PreparedFirmware {
        bytes,
        image: range,
        sections,
        header,
        name,
        chip,
    })
}

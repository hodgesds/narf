//! Immutable fuse-selected AX header and section transfers. No hardware I/O.
use super::{
    fw::FwError,
    fwdl::FWDL_SECTION_PER_PKT_LEN,
    mac::ChipId,
    prepared::PreparedFirmware,
    secure::{self, Blacklist, Fuses},
};
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(FwError),
    Secure(secure::Error),
    ChipMismatch,
    SectionGeometry,
}
impl From<FwError> for Error {
    fn from(value: FwError) -> Self {
        Self::Firmware(value)
    }
}
impl From<secure::Error> for Error {
    fn from(value: secure::Error) -> Self {
        Self::Secure(value)
    }
}

#[derive(Debug)]
struct Section {
    original: usize,
    len: usize,
    signature: Option<Range<usize>>,
}
#[derive(Debug)]
pub struct DownloadPlan {
    image: PreparedFirmware,
    secure: bool,
    header: Vec<u8>,
    sections: Vec<Section>,
}
impl DownloadPlan {
    pub fn new(
        image: PreparedFirmware,
        fuses: Fuses,
        blacklist: Option<Blacklist>,
    ) -> Result<Self, Error> {
        if image.chip() != fuses.chip() {
            return Err(Error::ChipMismatch);
        }
        let version = image.header().version;
        let base = if version == 0 { 32 } else { 48 };
        let mut header = Vec::new();
        header
            .try_reserve_exact(base + 16 * image.sections().len())
            .map_err(|_| FwError::NoMemory)?;
        header.extend_from_slice(&image.image()[..base]);
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(image.sections().len())
            .map_err(|_| FwError::NoMemory)?;
        let mut secure_found = false;
        for (index, section) in image.sections().iter().enumerate() {
            let mut len = section.len as usize;
            let mut signature = None;
            let mut ignore = false;
            if section.kind == 9 {
                let content = image.payload(index).ok_or(Error::SectionGeometry)?;
                let pool = image.header().signature_pools[index];
                if let Some(pool) = pool {
                    if pool.bitmap {
                        if secure_found {
                            ignore = true;
                        } else if fuses.enabled() {
                            signature = fuses.signature(image.image(), pool, content)?;
                            ignore = signature.is_none();
                        }
                    } else if fuses.enabled() {
                        signature = fuses.signature(image.image(), pool, content)?;
                    }
                } else if fuses.enabled() {
                    return Err(secure::Error::MissingSignature.into());
                }
                if !ignore {
                    secure_found = true;
                    fuses.check_blacklist(blacklist, content)?;
                    if fuses.enabled() && version == 0 && image.chip() == ChipId::Rtl8852B {
                        // Known AX B security geometry; a checksum-bearing override
                        // needs a separate proven header/trailer interpretation.
                        if section.chksum || len < 960 {
                            return Err(Error::SectionGeometry);
                        }
                        len = 960;
                    }
                }
            }
            if ignore {
                // Linux v0 does not compact ignored descriptors. Refuse a
                // contradictory header/payload stream until that case is proven.
                if version == 0 {
                    return Err(Error::SectionGeometry);
                }
                continue;
            }
            if let Some(range) = &signature {
                if len > FWDL_SECTION_PER_PKT_LEN || len < range.len() {
                    return Err(Error::SectionGeometry);
                }
            }
            let at = base + 16 * index;
            header.extend_from_slice(&image.image()[at..at + 16]);
            if len != section.len as usize {
                let end = header.len();
                let flags = u32::from_le_bytes(
                    header[end - 12..end - 8]
                        .try_into()
                        .map_err(|_| Error::SectionGeometry)?,
                );
                header[end - 12..end - 8]
                    .copy_from_slice(&((flags & !0x00ff_ffff) | len as u32).to_le_bytes());
            }
            sections.push(Section {
                original: index,
                len,
                signature,
            });
        }
        if fuses.enabled() && !secure_found {
            return Err(secure::Error::MissingSignature.into());
        }
        let count = u32::from_le_bytes(
            header[24..28]
                .try_into()
                .map_err(|_| Error::SectionGeometry)?,
        );
        header[24..28]
            .copy_from_slice(&((count & !0xff00) | (sections.len() as u32) << 8).to_le_bytes());
        let part = u32::from_le_bytes(
            header[28..32]
                .try_into()
                .map_err(|_| Error::SectionGeometry)?,
        );
        header[28..32].copy_from_slice(&((part & !0xffff) | 2020).to_le_bytes());
        Ok(Self {
            image,
            secure: fuses.enabled(),
            header,
            sections,
        })
    }
    pub fn chip(&self) -> ChipId {
        self.image.chip()
    }
    pub fn secure_enabled(&self) -> bool {
        self.secure
    }
    pub fn idmem_share_mode(&self) -> u8 {
        let word = u32::from_le_bytes(self.header[28..32].try_into().unwrap());
        ((word >> 18) & 15) as u8
    }
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
    pub fn section_len(&self, section: usize) -> Option<usize> {
        self.sections.get(section).map(|s| s.len)
    }
    pub fn header(&self) -> &[u8] {
        &self.header
    }
    /// Build one owned FWHDR_DL command. Receipt must remain owned by the CH12
    /// transport until TXBD consumption; there is no runtime firmware ACK.
    pub fn header_command(&self, sequence: u8) -> Result<Vec<u8>, Error> {
        let length = self.header.len() + 8;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| FwError::NoMemory)?;
        output.extend_from_slice(&(0x0000_000du32 | (u32::from(sequence) << 24)).to_le_bytes());
        output.extend_from_slice(&(length as u32).to_le_bytes());
        output.extend_from_slice(&self.header);
        Ok(output)
    }
    /// Copy one raw2020-byte-aligned section chunk. Security replacement is
    /// applied only to owned output; the verified image is never mutated.
    pub fn chunk(&self, index: usize, offset: usize) -> Result<Vec<u8>, Error> {
        let section = self.sections.get(index).ok_or(Error::SectionGeometry)?;
        if offset >= section.len || offset % FWDL_SECTION_PER_PKT_LEN != 0 {
            return Err(Error::SectionGeometry);
        }
        let end = core::cmp::min(offset + FWDL_SECTION_PER_PKT_LEN, section.len);
        let mut output = Vec::new();
        output
            .try_reserve_exact(end - offset)
            .map_err(|_| FwError::NoMemory)?;
        output.extend_from_slice(
            &self
                .image
                .payload(section.original)
                .ok_or(Error::SectionGeometry)?[offset..end],
        );
        if let Some(signature) = &section.signature {
            // Construction proved a single-packet section and exact key extent.
            let start = output.len() - signature.len();
            output[start..].copy_from_slice(&self.image.image()[signature.clone()]);
        }
        Ok(output)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "download_plan_tests.rs"]
mod tests;

//! Navi22 SMC v2.0 container, from Linux `amdgpu_ucode.h` and
//! `smu_v11_0.c`. Only the common-header microcode payload is sent to PSP;
//! the trailing soft PowerPlay table is separate, file-relative metadata.
//! This parser checks structure, not authenticity or board power policy.

pub const NAVI22_SMC: &str = crate::amdgpu_rdna2::NAVI22.firmware.smc;
const MAX_CONTAINER: usize = 2 * 1024 * 1024; // linux: n/a (NARF bound)
const MAX_UCODE: usize = 1024 * 1024; // linux: n/a (NARF bound)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
}
#[derive(Debug)]
pub struct Image<'a> {
    payload: &'a [u8],
    powerplay: Option<&'a [u8]>,
    version: u32,
    tables: Option<(&'a [u8], &'a [u8])>,
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_for_ip(bytes, 11)
    }
    /// SMU14.0.2/3 retain the v2.0 container; the board table stays separate.
    pub fn parse_smu14(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_for_ip(bytes, 14)
    }
    fn parse_for_ip(bytes: &'a [u8], ip: u8) -> Result<Self, Error> {
        // linux-lit: 44=sizeof(struct smc_firmware_header_v2_0)
        if bytes.len() < 44 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        // linux-lit: 8=offsetof(struct common_firmware_header, header_version_major); 12=offsetof(struct common_firmware_header, ip_version_major)
        if !matches!(&bytes[8..12], [2, 0, 0, 0] | [2, 0, 1, 0]) || bytes[12..16] != [ip, 0, 0, 0] {
            return Err(Error::Unsupported);
        }
        // linux-lit: 24=offsetof(struct common_firmware_header, ucode_array_offset_bytes)
        let start = word(bytes, 24) as usize;
        // linux-lit: 20=offsetof(struct common_firmware_header, ucode_size_bytes)
        let size = word(bytes, 20) as usize;
        // linux-lit: 0=offsetof(struct common_firmware_header, size_bytes)
        if word(bytes, 0) as usize != bytes.len()
            // linux-lit: 4=offsetof(struct common_firmware_header, header_size_bytes); 44=sizeof(struct smc_firmware_header_v2_0)
            || word(bytes, 4) != 44
            || start < 44 // linux-lit: 44=sizeof(struct smc_firmware_header_v2_0)
            || start % 4 != 0
            || size == 0
            || size > MAX_UCODE
            || size % 4 != 0
        {
            return Err(Error::Invalid);
        }
        let end = start.checked_add(size).ok_or(Error::Invalid)?;
        let payload = bytes.get(start..end).ok_or(Error::Invalid)?;
        // linux-lit: 36=offsetof(struct smc_firmware_header_v2_0, ppt_offset_bytes)
        let ppt_start = word(bytes, 36) as usize;
        // linux-lit: 40=offsetof(struct smc_firmware_header_v2_0, ppt_size_bytes)
        let ppt_size = word(bytes, 40) as usize;
        let multiple = bytes[10] == 1;
        let tables = if multiple {
            let count = ppt_start;
            let offset = ppt_size;
            if count == 0 || count > 256 || offset < 44 {
                return Err(Error::Invalid);
            }
            let entries_end = offset.checked_add(count * 12).ok_or(Error::Invalid)?;
            let entries = bytes.get(offset..entries_end).ok_or(Error::Invalid)?;
            if offset < end && start < entries_end {
                return Err(Error::Invalid);
            }
            for (i, entry) in entries.chunks_exact(12).enumerate() {
                let at = word(entry, 4) as usize;
                let size = word(entry, 8) as usize;
                let table_end = at.checked_add(size).ok_or(Error::Invalid)?;
                if at < 44
                    || size == 0
                    || table_end > bytes.len()
                    || (at < end && start < table_end)
                    || (at < entries_end && offset < table_end)
                {
                    return Err(Error::Invalid);
                }
                for other in entries[..i * 12].chunks_exact(12) {
                    let other_at = word(other, 4) as usize;
                    let other_end = other_at + word(other, 8) as usize;
                    if word(entry, 0) == word(other, 0) || (at < other_end && other_at < table_end)
                    {
                        return Err(Error::Invalid);
                    }
                }
            }
            Some((entries, bytes))
        } else {
            None
        };
        let powerplay = if multiple {
            None
        } else if ppt_size == 0 {
            if ppt_start != 0 {
                return Err(Error::Invalid);
            }
            None
        } else {
            let ppt_end = ppt_start.checked_add(ppt_size).ok_or(Error::Invalid)?;
            // linux-lit: 44=sizeof(struct smc_firmware_header_v2_0)
            if ppt_start < 44 || (ppt_start < end && start < ppt_end) {
                return Err(Error::Invalid);
            }
            Some(bytes.get(ppt_start..ppt_end).ok_or(Error::Invalid)?)
        };
        Ok(Self {
            payload,
            powerplay,
            tables,
            // linux-lit: 16=offsetof(struct common_firmware_header, ucode_version)
            version: word(bytes, 16),
        })
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Validated container metadata only. Selecting/applying a board PowerPlay
    /// table requires a separate VBIOS/power-policy path, not PSP LOAD_IP_FW.
    /// Select the exact VBIOS board-table ID from SMC 2.1; SMC 2.0 has one
    /// table and uses the ID only to select firmware rather than VBIOS.
    pub fn powerplay_for(&self, id: u32) -> Option<&'a [u8]> {
        match self.tables {
            None => self.powerplay,
            Some((entries, bytes)) => {
                entries
                    .chunks_exact(12)
                    .find(|e| word(e, 0) == id)
                    .map(|e| {
                        let at = word(e, 4) as usize;
                        &bytes[at..at + word(e, 8) as usize]
                    })
            }
        }
    }
    pub fn powerplay_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.tables
            .into_iter()
            .flat_map(|(entries, _)| entries.chunks_exact(12).map(|e| word(e, 0)))
    }
    pub fn powerplay(&self) -> Option<&'a [u8]> {
        self.powerplay
    }
}

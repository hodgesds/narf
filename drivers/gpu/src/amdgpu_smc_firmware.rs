//! Navi22 SMC v2.0 container, from Linux `amdgpu_ucode.h` and
//! `smu_v11_0.c`. Only the common-header microcode payload is sent to PSP;
//! the trailing soft PowerPlay table is separate, file-relative metadata.
//! This parser checks structure, not authenticity or board power policy.

pub const NAVI22_SMC: &str = "amdgpu/navy_flounder_smc.bin";
const MAX_CONTAINER: usize = 2 * 1024 * 1024;
const MAX_UCODE: usize = 1024 * 1024;

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
        if bytes.len() < 44 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        if bytes[8..12] != [2, 0, 0, 0] || bytes[12..16] != [ip, 0, 0, 0] {
            return Err(Error::Unsupported);
        }
        let start = word(bytes, 24) as usize;
        let size = word(bytes, 20) as usize;
        if word(bytes, 0) as usize != bytes.len()
            || word(bytes, 4) != 44
            || start < 44
            || start % 4 != 0
            || size == 0
            || size > MAX_UCODE
            || size % 4 != 0
        {
            return Err(Error::Invalid);
        }
        let end = start.checked_add(size).ok_or(Error::Invalid)?;
        let payload = bytes.get(start..end).ok_or(Error::Invalid)?;
        let ppt_start = word(bytes, 36) as usize;
        let ppt_size = word(bytes, 40) as usize;
        let powerplay = if ppt_size == 0 {
            if ppt_start != 0 {
                return Err(Error::Invalid);
            }
            None
        } else {
            let ppt_end = ppt_start.checked_add(ppt_size).ok_or(Error::Invalid)?;
            if ppt_start < 44 || (ppt_start < end && start < ppt_end) {
                return Err(Error::Invalid);
            }
            Some(bytes.get(ppt_start..ppt_end).ok_or(Error::Invalid)?)
        };
        Ok(Self {
            payload,
            powerplay,
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
    pub fn powerplay(&self) -> Option<&'a [u8]> {
        self.powerplay
    }
}

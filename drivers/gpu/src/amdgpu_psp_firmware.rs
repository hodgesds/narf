//! PSP 11/14 signed SOS containers (Linux `amdgpu_ucode.h` and
//! `amdgpu_psp.c::psp_init_sos_microcode`). Offsets are payload-relative.
//! Parsing checks structure only; the firmware registry and PSP authenticate
//! the image. No untrusted descriptor becomes an MMIO address.

pub const NAVI22_SOS: &str = "amdgpu/navy_flounder_sos.bin";
pub const PSP14_0_2_SOS: &str = "amdgpu/psp_14_0_2_sos.bin";
pub const PSP14_0_3_SOS: &str = "amdgpu/psp_14_0_3_sos.bin";
pub const STAGING_SIZE: usize = 1024 * 1024; // linux: PSP_1_MEG
const MAX_CONTAINER: usize = 8 * STAGING_SIZE; // linux: n/a (NARF bound)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    KeyDatabase,
    Spl,
    SystemDriver,
    SocDriver,
    InterfaceDriver,
    HardwareDebugDriver,
    RasDriver,
    IpKeyManager,
    SecureOs,
}
impl Component {
    pub(crate) const fn command(self) -> u32 {
        match self {
            Self::KeyDatabase => 0x0008_0000, // linux-lit: 0x0008_0000=PSP_BL__LOAD_KEY_DATABASE
            Self::Spl => 0x1000_0000,         // linux-lit: 0x1000_0000=PSP_BL__LOAD_TOS_SPL_TABLE
            Self::SystemDriver => 0x0001_0000, // linux-lit: 0x0001_0000=PSP_BL__LOAD_SYSDRV
            Self::SocDriver => 0x000b_0000,   // linux-lit: 0x000b_0000=PSP_BL__LOAD_SOCDRV
            Self::InterfaceDriver => 0x000d_0000, // linux-lit: 0x000d_0000=PSP_BL__LOAD_INTFDRV
            Self::HardwareDebugDriver => 0x000c_0000, // linux-lit: 0x000c_0000=PSP_BL__LOAD_DBGDRV
            Self::RasDriver => 0x000e_0000,   // linux-lit: 0x000e_0000=PSP_BL__LOAD_RASDRV
            Self::IpKeyManager => 0x000f_0000, // linux-lit: 0x000f_0000=PSP_BL__LOAD_IPKEYMGRDRV
            Self::SecureOs => 0x0002_0000,    // linux-lit: 0x0002_0000=PSP_BL__LOAD_SOSDRV
        }
    }
}

#[derive(Debug)]
pub struct Image<'a> {
    components: [Option<(Component, &'a [u8])>; 9],
    version: u32,
    toc: Option<&'a [u8]>,
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
impl<'a> Image<'a> {
    /// Accept PSP 11.0 header versions 1.0 through 1.3. All descriptors,
    /// including non-boot TOC/RL/alternate images, must lie in the payload and
    /// not overlap. v1.2's reserved descriptor is deliberately ignored.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        // linux-lit: 44=sizeof(struct psp_firmware_header_v1_0)
        if bytes.len() < 44 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        // linux-lit: 10=offsetof(struct common_firmware_header, header_version_minor)
        let minor = u16::from_le_bytes([bytes[10], bytes[11]]);
        // linux-lit: 8=offsetof(struct common_firmware_header, header_version_major); 12=offsetof(struct common_firmware_header, ip_version_major)
        if bytes[8..10] != [1, 0] || minor > 3 || bytes[12..16] != [11, 0, 0, 0] {
            return Err(Error::Unsupported);
        }
        let header_size = match minor {
            // linux-lit: 44=sizeof(struct psp_firmware_header_v1_0)
            0 => 44,
            // linux-lit: 68=sizeof(struct psp_firmware_header_v1_1); 68=sizeof(struct psp_firmware_header_v1_2)
            1 | 2 => 68,
            _ => 116, // linux-lit: 116=sizeof(struct psp_firmware_header_v1_3)
        };
        // linux-lit: 24=offsetof(struct common_firmware_header, ucode_array_offset_bytes)
        let start = word(bytes, 24) as usize;
        // linux-lit: 20=offsetof(struct common_firmware_header, ucode_size_bytes)
        let size = word(bytes, 20) as usize;
        // linux-lit: 0=offsetof(struct common_firmware_header, size_bytes)
        if word(bytes, 0) as usize != bytes.len()
            // linux-lit: 4=offsetof(struct common_firmware_header, header_size_bytes)
            || word(bytes, 4) as usize != header_size
            || start < header_size
            || size == 0
        {
            return Err(Error::Invalid);
        }
        let end = start.checked_add(size).ok_or(Error::Invalid)?;
        let payload = bytes.get(start..end).ok_or(Error::Invalid)?;
        // [system, SOS, TOC, KDB, SPL, RL, system_aux, SOS_aux].
        let mut ranges = [(0usize, 0usize); 8];
        // linux-lit: 36=offsetof(struct psp_firmware_header_v1_0, sos.offset_bytes)
        ranges[0] = (0, word(bytes, 36) as usize);
        let descriptors = match minor {
            0 => 1,
            1 | 2 => 3,
            _ => 7,
        };
        for i in 0..descriptors {
            if minor == 2 && i == 1 {
                continue;
            }
            // linux-lit: 36=offsetof(struct psp_firmware_header_v1_0, sos.offset_bytes); 12=sizeof(struct psp_fw_legacy_bin_desc)
            let offset = word(bytes, 36 + i * 12) as usize;
            // linux-lit: 40=offsetof(struct psp_firmware_header_v1_0, sos.size_bytes); 12=sizeof(struct psp_fw_legacy_bin_desc)
            let len = word(bytes, 40 + i * 12) as usize;
            if len > STAGING_SIZE || offset.checked_add(len).is_none_or(|end| end > size) {
                return Err(Error::Invalid);
            }
            ranges[i + 1] = (offset, len);
        }
        if ranges[0].1 == 0 || ranges[0].1 > STAGING_SIZE || ranges[1].1 == 0 {
            return Err(Error::Invalid);
        }
        for (i, &(offset, len)) in ranges.iter().enumerate() {
            if len == 0 {
                continue;
            }
            for &(other, count) in &ranges[..i] {
                if count != 0 && offset < other + count && other < offset + len {
                    return Err(Error::Invalid);
                }
            }
        }
        let part = |index: usize, kind| {
            let (offset, len) = ranges[index];
            (len != 0).then(|| (kind, &payload[offset..offset + len]))
        };
        let (toc_offset, toc_size) = ranges[2];
        Ok(Self {
            components: [
                part(3, Component::KeyDatabase),
                part(4, Component::Spl),
                part(0, Component::SystemDriver),
                None,
                None,
                None,
                None,
                None,
                part(1, Component::SecureOs),
            ],
            // linux-lit: 16=offsetof(struct common_firmware_header, ucode_version)
            version: word(bytes, 16),
            toc: (toc_size != 0).then(|| &payload[toc_offset..toc_offset + toc_size]),
        })
    }
    /// PSP14's v2.0 descriptor table. The common header's size is 36 bytes;
    /// the variable descriptors follow it, before the payload offset. Every
    /// descriptor is validated, including TOC/RL which are not boot commands.
    /// v2.1 auxiliary-image selection and SPDM are deliberately unsupported.
    pub fn parse_psp14(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 36 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        if bytes[8..12] != [2, 0, 0, 0] || bytes[12..16] != [14, 0, 0, 0] {
            return Err(Error::Unsupported);
        }
        let count = word(bytes, 32) as usize;
        let start = word(bytes, 24) as usize;
        let size = word(bytes, 20) as usize;
        if !(2..=11).contains(&count)
            || word(bytes, 0) as usize != bytes.len()
            || word(bytes, 4) != 36
            || start < 36 + count * 16
            || size == 0
        {
            return Err(Error::Invalid);
        }
        let end = start.checked_add(size).ok_or(Error::Invalid)?;
        let payload = bytes.get(start..end).ok_or(Error::Invalid)?;
        let mut parts = [None; 12];
        let mut ranges = [(0usize, 0usize); 12];
        for descriptor in bytes[36..36 + count * 16].chunks_exact(16) {
            let kind = word(descriptor, 0) as usize;
            if !(1..=11).contains(&kind) {
                return Err(Error::Unsupported);
            }
            let offset = word(descriptor, 8) as usize;
            let length = word(descriptor, 12) as usize;
            if parts[kind].is_some()
                || length == 0
                || length > STAGING_SIZE
                || offset.checked_add(length).is_none_or(|end| end > size)
            {
                return Err(Error::Invalid);
            }
            for &(other, length_other) in &ranges {
                if length_other != 0 && offset < other + length_other && other < offset + length {
                    return Err(Error::Invalid);
                }
            }
            ranges[kind] = (offset, length);
            parts[kind] = Some(&payload[offset..offset + length]);
        }
        if parts[1].is_none() || parts[2].is_none() {
            return Err(Error::Invalid);
        }
        let part = |index: usize, kind| parts[index].map(|bytes| (kind, bytes));
        Ok(Self {
            components: [
                part(3, Component::KeyDatabase),
                part(5, Component::Spl),
                part(2, Component::SystemDriver),
                part(7, Component::SocDriver),
                part(8, Component::InterfaceDriver),
                part(9, Component::HardwareDebugDriver),
                part(10, Component::RasDriver),
                part(11, Component::IpKeyManager),
                part(1, Component::SecureOs),
            ],
            version: word(bytes, 16),
            toc: parts[4],
        })
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Payload of the optional embedded TOC used by GPCOM LOAD_TOC. v1.0 and
    /// v1.2 have no TOC; their TMR uses the PSP11 default size instead.
    pub fn toc(&self) -> Option<&'a [u8]> {
        self.toc
    }
    /// Linux boot order, omitting optional absent components. SOS is last;
    /// descriptor ordering in a PSP14 container does not change boot ordering.
    pub fn components(&self) -> impl Iterator<Item = (Component, &'a [u8])> + '_ {
        self.components.iter().flatten().copied()
    }
}

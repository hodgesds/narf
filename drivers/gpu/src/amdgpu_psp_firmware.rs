//! PSP 11 signed SOS containers (Linux `amdgpu_ucode.h` and
//! `amdgpu_psp.c::psp_init_sos_microcode`). Offsets are payload-relative.
//! Parsing checks structure only; the firmware registry and PSP authenticate
//! the image. No untrusted descriptor becomes an MMIO address.

pub const NAVI22_SOS: &str = "amdgpu/navy_flounder_sos.bin";
pub const STAGING_SIZE: usize = 1024 * 1024;
const MAX_CONTAINER: usize = 8 * STAGING_SIZE;

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
    SecureOs,
}
impl Component {
    pub(crate) const fn command(self) -> u32 {
        match self {
            Self::KeyDatabase => 0x0008_0000,
            Self::Spl => 0x1000_0000,
            Self::SystemDriver => 0x0001_0000,
            Self::SecureOs => 0x0002_0000,
        }
    }
}

#[derive(Debug)]
pub struct Image<'a> {
    components: [Option<(Component, &'a [u8])>; 4],
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
        if bytes.len() < 44 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        let minor = u16::from_le_bytes([bytes[10], bytes[11]]);
        if bytes[8..10] != [1, 0] || minor > 3 || bytes[12..16] != [11, 0, 0, 0] {
            return Err(Error::Unsupported);
        }
        let header_size = match minor {
            0 => 44,
            1 | 2 => 68,
            _ => 116,
        };
        let start = word(bytes, 24) as usize;
        let size = word(bytes, 20) as usize;
        if word(bytes, 0) as usize != bytes.len()
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
            let offset = word(bytes, 36 + i * 12) as usize;
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
                part(1, Component::SecureOs),
            ],
            version: word(bytes, 16),
            toc: (toc_size != 0).then(|| &payload[toc_offset..toc_offset + toc_size]),
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
    /// Linux PSP11 boot order, omitting optional absent KDB/SPL components.
    pub fn components(&self) -> impl Iterator<Item = (Component, &'a [u8])> + '_ {
        self.components.iter().flatten().copied()
    }
}

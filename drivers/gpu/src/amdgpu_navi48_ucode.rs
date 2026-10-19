//! GC12/SDMA7/VCN5/DCN4 signed firmware container layouts, as defined by
//! Linux amdgpu_ucode.{h,c}, amdgpu_rlc.c and psp_gfx_if.h.
//! Structural validation only; the PSP authenticates payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Smc,
    Sdma,
    Pfp,
    Me,
    Mec,
    Mes,
    Mes1,
    Imu,
    Rlc,
    Vcn,
    Dmcub,
}
impl Source {
    pub const ALL: [Self; 11] = [
        Self::Smc,
        Self::Sdma,
        Self::Pfp,
        Self::Me,
        Self::Mec,
        Self::Mes,
        Self::Mes1,
        Self::Imu,
        Self::Rlc,
        Self::Vcn,
        Self::Dmcub,
    ];
}
/// PSP firmware types in Linux UCODE_ID order. All RS64 instructions precede
/// their per-pipe stacks. The RLC_G upload triggers autoload before media.
pub const UPLOAD_ORDER: [u32; 27] = [
    18, 71, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 33, 34, 81, 82, 68, 69, 22, 20, 21, 26, 48,
    8, 13, 51,
];
#[derive(Clone, Copy, Debug)]
pub struct Payload<'a> {
    bytes: &'a [u8],
    kind: u32,
}
impl<'a> Payload<'a> {
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn firmware_type(self) -> u32 {
        self.kind
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPoints {
    pub code: u64,
    pub data: Option<u64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    source: Source,
    version: u32,
    /// `ucode_feature_version` of a v2.0 CP header (PFP, ME, MEC); 0 for
    /// every other image.
    feature: u32,
    entries: Option<EntryPoints>,
    payloads: [Option<Payload<'a>>; 13],
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn address(bytes: &[u8], at: usize) -> u64 {
    u64::from(word(bytes, at)) | (u64::from(word(bytes, at + 4)) << 32)
}
fn part(bytes: &[u8], header: usize, offset: u32, size: u32) -> Result<&[u8], Error> {
    let start = offset as usize;
    let length = size as usize;
    if start < header || start % 4 != 0 || length == 0 || length % 4 != 0 || length > 2 << 20 {
        return Err(Error::Invalid);
    }
    let end = start.checked_add(length).ok_or(Error::Invalid)?;
    bytes.get(start..end).ok_or(Error::Invalid)
}
impl<'a> Image<'a> {
    pub(crate) const EMPTY: Self = Self {
        source: Source::Smc,
        version: 0,
        feature: 0,
        entries: None,
        payloads: [None; 13],
    };
    pub fn parse(source: Source, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 32 || bytes.len() > 4 << 20 {
            return Err(Error::Invalid);
        }
        let mut image = Self {
            source,
            version: word(bytes, 16),
            ..Self::EMPTY
        };
        if source == Source::Rlc {
            let rlc = crate::amdgpu_gfx_firmware::Image::parse_rlc12(bytes)
                .map_err(|_| Error::Invalid)?;
            for (slot, p) in image.payloads.iter_mut().zip(rlc.payloads()) {
                *slot = Some(Payload {
                    bytes: p.bytes(),
                    kind: p.firmware_type(),
                });
            }
            return Ok(image);
        }
        if source == Source::Smc {
            let smc = crate::amdgpu_smc_firmware::Image::parse_smu14(bytes)
                .map_err(|_| Error::Invalid)?;
            image.payloads[0] = Some(Payload {
                bytes: smc.payload(),
                kind: 18,
            });
            return Ok(image);
        }
        let (header, version, ip) = match source {
            Source::Sdma => (44, 3, 7),
            Source::Pfp | Source::Me | Source::Mec => (60, 2, 12),
            Source::Mes | Source::Mes1 => (72, 1, 12),
            Source::Imu => (48, 1, 12),
            Source::Vcn => (32, 1, 5),
            Source::Dmcub => (40, 1, 4),
            _ => unreachable!(),
        };
        if word(bytes, 8) != version || word(bytes, 12) != ip {
            return Err(Error::Unsupported);
        }
        if bytes.len() < header
            || word(bytes, 4) as usize != header
            || word(bytes, 0) as usize != bytes.len()
        {
            return Err(Error::Invalid);
        }
        let offset = word(bytes, 24);
        let size = word(bytes, 20);
        let main = part(bytes, header, offset, size)?;
        if offset as usize + main.len() != bytes.len() {
            return Err(Error::Invalid);
        }
        let mut add = |slot: usize, bytes: &'a [u8], kind| {
            image.payloads[slot] = Some(Payload { bytes, kind });
        };
        match source {
            Source::Pfp | Source::Me | Source::Mec | Source::Mes | Source::Mes1 => {
                let mes = matches!(source, Source::Mes | Source::Mes1);
                let (code_size, code_offset, data_size, data_offset, entry) = if mes {
                    (
                        word(bytes, 36),
                        word(bytes, 40),
                        word(bytes, 48),
                        word(bytes, 52),
                        56,
                    )
                } else {
                    (
                        word(bytes, 36),
                        word(bytes, 40),
                        word(bytes, 44),
                        word(bytes, 48),
                        52,
                    )
                };
                if code_offset != offset
                    || code_offset.checked_add(code_size) != Some(data_offset)
                    || code_size.checked_add(data_size) != Some(size)
                {
                    return Err(Error::Invalid);
                }
                let code = part(bytes, header, code_offset, code_size)?;
                let data = part(bytes, header, data_offset, data_size)?;
                let (kind, stack, copies) = match source {
                    Source::Pfp => (87, 90, 2),
                    Source::Me => (88, 92, 2),
                    Source::Mec => (89, 94, 4),
                    Source::Mes => (33, 34, 1),
                    Source::Mes1 => (81, 82, 1),
                    _ => unreachable!(),
                };
                add(0, code, kind);
                for i in 0..copies {
                    add(i + 1, data, stack + i as u32);
                }
                let entries = EntryPoints {
                    code: address(bytes, entry),
                    data: mes.then(|| address(bytes, entry + 8)),
                };
                if entries.code == 0
                    || entries.code % 4 != 0
                    || entries.data.is_some_and(|p| p == 0 || p % 4 != 0)
                {
                    return Err(Error::Invalid);
                }
                image.entries = Some(entries);
                if !mes {
                    image.feature = word(bytes, 32);
                }
            }
            Source::Sdma => {
                if word(bytes, 36) != offset || word(bytes, 40) != size {
                    return Err(Error::Invalid);
                }
                add(0, main, 71);
            }
            Source::Imu => {
                let instruction_size = word(bytes, 32);
                let data_size = word(bytes, 40);
                // IMU offsets are relative to the common payload, unlike CP.
                if word(bytes, 36) != 0
                    || word(bytes, 44) != instruction_size
                    || instruction_size.checked_add(data_size) != Some(size)
                {
                    return Err(Error::Invalid);
                }
                add(0, part(bytes, header, offset, instruction_size)?, 68);
                add(
                    1,
                    part(
                        bytes,
                        header,
                        offset.checked_add(instruction_size).ok_or(Error::Invalid)?,
                        data_size,
                    )?,
                    69,
                );
            }
            Source::Vcn => add(0, main, 13),
            Source::Dmcub => {
                let inst = word(bytes, 32);
                if inst.checked_add(word(bytes, 36)) != Some(size) {
                    return Err(Error::Invalid);
                }
                add(0, part(bytes, header, offset, inst)?, 51);
            }
            _ => unreachable!(),
        }
        Ok(image)
    }
    pub fn source(&self) -> Source {
        self.source
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    /// The CP firmware's feature version (`AMDGPU_INFO_FW_VERSION`'s
    /// `feature`), 0 for images without one.
    pub fn feature(&self) -> u32 {
        self.feature
    }
    pub fn entry_points(&self) -> Option<EntryPoints> {
        self.entries
    }
    pub fn payloads(&self) -> impl Iterator<Item = Payload<'a>> + '_ {
        self.payloads.iter().flatten().copied()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_ucode_tests.rs"]
pub(crate) mod tests;

//! Navi22 PSP graphics payload selection. Layouts/order follow Linux
//! amdgpu_ucode.h, amdgpu_ucode.c, amdgpu_rlc.c and psp_gfx_if.h.
//! Parsing validates structure, not signatures; PSP authenticates payloads.

const MAX_CONTAINER: usize = 4 << 20;
const MAX_PAYLOAD: usize = 2 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Sdma,
    Ce,
    Pfp,
    Me,
    Mec,
    Mec2,
    Rlc,
    Vcn,
    Dmcub,
}
impl Source {
    /// Linux UCODE_ID order, not numeric PSP firmware-type order.
    pub const ORDER: [Self; 9] = [
        Self::Sdma,
        Self::Ce,
        Self::Pfp,
        Self::Me,
        Self::Mec,
        Self::Mec2,
        Self::Rlc,
        Self::Vcn,
        Self::Dmcub,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Sdma => "amdgpu/navy_flounder_sdma.bin",
            Self::Ce => "amdgpu/navy_flounder_ce.bin",
            Self::Pfp => "amdgpu/navy_flounder_pfp.bin",
            Self::Me => "amdgpu/navy_flounder_me.bin",
            Self::Mec => "amdgpu/navy_flounder_mec.bin",
            Self::Mec2 => "amdgpu/navy_flounder_mec2.bin",
            Self::Rlc => "amdgpu/navy_flounder_rlc.bin",
            Self::Vcn => "amdgpu/navy_flounder_vcn.bin",
            Self::Dmcub => "amdgpu/navy_flounder_dmcub.bin",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
}
#[derive(Clone, Copy, Debug)]
pub struct Payload<'a> {
    bytes: &'a [u8],
    firmware_type: u32,
}
impl<'a> Payload<'a> {
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn firmware_type(self) -> u32 {
        self.firmware_type
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    source: Source,
    version: u32,
    payloads: [Option<Payload<'a>>; 13],
    count: usize,
}
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}
impl Span {
    const EMPTY: Self = Self { start: 0, end: 0 };
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn span(bytes: &[u8], header: usize, start: u32, size: u32) -> Result<Span, Error> {
    let start = start as usize;
    let size = size as usize;
    let end = start.checked_add(size).ok_or(Error::Invalid)?;
    // Empty descriptors may point at a valid file boundary (real RLC images do).
    if start % 4 != 0
        || size % 4 != 0
        || size > MAX_PAYLOAD
        || end > bytes.len()
        || (start < header && !(start == 0 && size == 0))
    {
        return Err(Error::Invalid);
    }
    Ok(Span { start, end })
}
fn record(ranges: &mut [Span; 17], count: &mut usize, next: Span) -> Result<(), Error> {
    if next.start == next.end {
        return Ok(());
    }
    if ranges[..*count]
        .iter()
        .any(|r| r.start < next.end && next.start < r.end)
    {
        return Err(Error::Invalid);
    }
    ranges[*count] = next;
    *count += 1;
    Ok(())
}
impl<'a> Image<'a> {
    pub fn parse(source: Source, bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_for_gc(source, bytes, 0x3000a)
    }
    /// GC12 retains the RLC v2.2 layout, but carries a different IP identity.
    pub(crate) fn parse_rlc12(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 32 || word(bytes, 8) != 0x20002 {
            return Err(Error::Unsupported);
        }
        Self::parse_for_gc(Source::Rlc, bytes, 12)
    }
    fn parse_for_gc(source: Source, bytes: &'a [u8], gc: u32) -> Result<Self, Error> {
        if bytes.len() < 32 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        let version = word(bytes, 8);
        let minor = (version >> 16) as usize;
        let header = match source {
            Source::Vcn if version == 1 && word(bytes, 12) == 3 => 32,
            Source::Dmcub if version == 1 && word(bytes, 12) == 3 => 40,
            Source::Sdma if version == 1 && word(bytes, 12) == 0x20005 => 48,
            Source::Rlc
                if version & 0xffff == 2 && (2..=4).contains(&minor) && word(bytes, 12) == gc =>
            {
                [172, 204, 244][minor - 2]
            }
            Source::Ce | Source::Pfp | Source::Me | Source::Mec | Source::Mec2
                if version == 1 && word(bytes, 12) == gc =>
            {
                44
            }
            _ => return Err(Error::Unsupported),
        };
        if bytes.len() < header
            || word(bytes, 0) as usize != bytes.len()
            || word(bytes, 4) as usize != header
            || word(bytes, 20) == 0
        {
            return Err(Error::Invalid);
        }
        let mut main = span(bytes, header, word(bytes, 24), word(bytes, 20))?;
        let mut image = Self {
            source,
            version: word(bytes, 16),
            payloads: [None; 13],
            count: 0,
        };
        if matches!(source, Source::Vcn | Source::Dmcub) {
            // VCN uses the entire common-header payload. DMCUB sends only
            // inst_const_bytes, including its PSP packaging, never BSS/data.
            if main.end != bytes.len() {
                return Err(Error::Invalid);
            }
            if source == Source::Dmcub {
                let inst = word(bytes, 32);
                let data = word(bytes, 36);
                if inst == 0 || inst.checked_add(data) != Some(word(bytes, 20)) {
                    return Err(Error::Invalid);
                }
                main = span(bytes, header, word(bytes, 24), inst)?;
            }
            image.push(bytes, main, if source == Source::Vcn { 13 } else { 51 });
            return Ok(image);
        }
        if source != Source::Rlc {
            let jt_field = if source == Source::Sdma { 40 } else { 36 };
            let jt_start = (word(bytes, jt_field) as usize)
                .checked_mul(4)
                .ok_or(Error::Invalid)?;
            let jt_size = (word(bytes, jt_field + 4) as usize)
                .checked_mul(4)
                .ok_or(Error::Invalid)?;
            let jt_end = jt_start.checked_add(jt_size).ok_or(Error::Invalid)?;
            if jt_end > main.end - main.start {
                return Err(Error::Invalid);
            }
            if matches!(source, Source::Mec | Source::Mec2) {
                // Linux sends the MEC prefix, omitting its trailing JT, and
                // skips both separate MEC*_JT uploads when autoload is enabled.
                if jt_size == 0 || jt_start == 0 || jt_end != main.end - main.start {
                    return Err(Error::Invalid);
                }
                main.end -= jt_size;
            }
            let kind = match source {
                Source::Sdma => 9,
                Source::Ce => 3,
                Source::Pfp => 2,
                Source::Me => 1,
                Source::Mec | Source::Mec2 => 4,
                Source::Rlc | Source::Vcn | Source::Dmcub => unreachable!(),
            };
            image.push(bytes, main, kind);
            return Ok(image);
        }

        let mut ranges = [Span::EMPTY; 17];
        let mut count = 0;
        record(&mut ranges, &mut count, main)?;
        // File-relative format/register arrays are metadata, never IP firmware.
        for size_field in [72, 80, 88, 96] {
            record(
                &mut ranges,
                &mut count,
                span(
                    bytes,
                    header,
                    word(bytes, size_field + 4),
                    word(bytes, size_field),
                )?,
            )?;
        }
        if minor == 4 {
            // Retained P/V descriptors are unused in this header revision.
            for field in [180, 196] {
                if word(bytes, field) != 0 {
                    return Err(Error::Unsupported);
                }
                span(bytes, header, word(bytes, field + 4), 0)?;
            }
        }
        let mut add = |size_field, kind| -> Result<(), Error> {
            let part = span(
                bytes,
                header,
                word(bytes, size_field + 4),
                word(bytes, size_field),
            )?;
            record(&mut ranges, &mut count, part)?;
            image.push(bytes, part, kind);
            Ok(())
        };
        if minor == 4 {
            // v2.4 retains the v2.3 P/V slots but Linux does not load them.
            for (field, kind) in [(204, 27), (212, 28), (220, 29), (228, 65), (236, 66)] {
                add(field, kind)?;
            }
        }
        for (field, kind) in [(116, 22), (132, 20), (148, 21), (156, 26), (164, 48)] {
            add(field, kind)?;
        }
        if minor == 3 {
            add(180, 25)?;
            add(196, 7)?;
        }
        // Loading RLC_G is Linux's trigger to send AUTOLOAD_RLC afterwards.
        image.push(bytes, main, 8);
        Ok(image)
    }
    fn push(&mut self, bytes: &'a [u8], part: Span, firmware_type: u32) {
        if part.start != part.end {
            self.payloads[self.count] = Some(Payload {
                bytes: &bytes[part.start..part.end],
                firmware_type,
            });
            self.count += 1;
        }
    }
    pub fn source(&self) -> Source {
        self.source
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn payloads(&self) -> impl Iterator<Item = Payload<'a>> + '_ {
        self.payloads.iter().flatten().copied()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx_firmware_tests.rs"]
pub(crate) mod tests;

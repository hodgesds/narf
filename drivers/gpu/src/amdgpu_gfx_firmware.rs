//! Navi22 PSP graphics payload selection. Layouts/order follow Linux
//! amdgpu_ucode.h, amdgpu_ucode.c, amdgpu_rlc.c and psp_gfx_if.h.
//! Parsing validates structure, not signatures; PSP authenticates payloads.

const MAX_CONTAINER: usize = 4 << 20; // linux: n/a (NARF bound)
const MAX_PAYLOAD: usize = 2 << 20; // linux: n/a (NARF bound)
/// `GFX_FW_TYPE_VCN1` (psp_gfx_if.h).
pub(crate) const VCN1_TYPE: u32 = 58; // linux: GFX_FW_TYPE_VCN1

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
        self.name_for(&crate::amdgpu_rdna2::NAVI22)
    }
    /// Container selected by an exact discrete RDNA2 profile.
    pub fn name_for(self, profile: &crate::amdgpu_rdna2::Profile) -> &'static str {
        let firmware = profile.firmware;
        match self {
            Self::Sdma => firmware.sdma,
            Self::Ce => firmware.ce,
            Self::Pfp => firmware.pfp,
            Self::Me => firmware.me,
            Self::Mec => firmware.mec,
            Self::Mec2 => firmware.mec2,
            Self::Rlc => firmware.rlc,
            Self::Vcn => firmware.vcn,
            Self::Dmcub => firmware.dmcub,
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
        // linux-lit: 32=sizeof(struct common_firmware_header)
        if bytes.len() < 32 || bytes.len() > MAX_CONTAINER {
            return Err(Error::Invalid);
        }
        // linux-lit: 8=offsetof(struct common_firmware_header, header_version_major)
        let version = word(bytes, 8);
        let minor = (version >> 16) as usize;
        let header = match source {
            // linux-lit: 12=offsetof(struct common_firmware_header, ip_version_major); 32=sizeof(struct common_firmware_header)
            Source::Vcn if version == 1 && word(bytes, 12) == 3 => 32,
            // linux-lit: 12=offsetof(struct common_firmware_header, ip_version_major); 40=sizeof(struct dmcub_firmware_header_v1_0)
            Source::Dmcub if version == 1 && word(bytes, 12) == 3 => 40,
            // linux-lit: 12=offsetof(struct common_firmware_header, ip_version_major); 48=sizeof(struct sdma_firmware_header_v1_0)
            Source::Sdma if version == 1 && word(bytes, 12) == 0x20005 => 48,
            Source::Rlc
                // linux-lit: 12=offsetof(struct common_firmware_header, ip_version_major)
                if version & 0xffff == 2 && (2..=4).contains(&minor) && word(bytes, 12) == gc =>
            {
                // linux-lit: 172=sizeof(struct rlc_firmware_header_v2_2); 204=sizeof(struct rlc_firmware_header_v2_3); 244=sizeof(struct rlc_firmware_header_v2_4)
                [172, 204, 244][minor - 2]
            }
            Source::Ce | Source::Pfp | Source::Me | Source::Mec | Source::Mec2
                // linux-lit: 12=offsetof(struct common_firmware_header, ip_version_major)
                if version == 1 && word(bytes, 12) == gc =>
            {
                44 // linux-lit: 44=sizeof(struct gfx_firmware_header_v1_0)
            }
            _ => return Err(Error::Unsupported),
        };
        if bytes.len() < header
            // linux-lit: 0=offsetof(struct common_firmware_header, size_bytes)
            || word(bytes, 0) as usize != bytes.len()
            // linux-lit: 4=offsetof(struct common_firmware_header, header_size_bytes)
            || word(bytes, 4) as usize != header
            // linux-lit: 20=offsetof(struct common_firmware_header, ucode_size_bytes)
            || word(bytes, 20) == 0
        {
            return Err(Error::Invalid);
        }
        // linux-lit: 24=offsetof(struct common_firmware_header, ucode_array_offset_bytes); 20=offsetof(struct common_firmware_header, ucode_size_bytes)
        let mut main = span(bytes, header, word(bytes, 24), word(bytes, 20))?;
        let mut image = Self {
            source,
            // linux-lit: 16=offsetof(struct common_firmware_header, ucode_version)
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
                // linux-lit: 32=offsetof(struct dmcub_firmware_header_v1_0, inst_const_bytes)
                let inst = word(bytes, 32);
                // linux-lit: 36=offsetof(struct dmcub_firmware_header_v1_0, bss_data_bytes)
                let data = word(bytes, 36);
                // linux-lit: 20=offsetof(struct common_firmware_header, ucode_size_bytes)
                if inst == 0 || inst.checked_add(data) != Some(word(bytes, 20)) {
                    return Err(Error::Invalid);
                }
                // linux-lit: 24=offsetof(struct common_firmware_header, ucode_array_offset_bytes)
                main = span(bytes, header, word(bytes, 24), inst)?;
            }
            // linux-lit: 13=GFX_FW_TYPE_VCN; 51=GFX_FW_TYPE_DMUB
            image.push(bytes, main, if source == Source::Vcn { 13 } else { 51 });
            return Ok(image);
        }
        if source != Source::Rlc {
            // linux-lit: 40=offsetof(struct sdma_firmware_header_v1_0, jt_offset); 36=offsetof(struct gfx_firmware_header_v1_0, jt_offset)
            let jt_field = if source == Source::Sdma { 40 } else { 36 };
            let jt_start = (word(bytes, jt_field) as usize)
                .checked_mul(4)
                .ok_or(Error::Invalid)?;
            // linux-lit: 4=offsetof(struct gfx_firmware_header_v1_0, jt_size) - offsetof(struct gfx_firmware_header_v1_0, jt_offset)
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
                Source::Sdma => 9,               // linux-lit: 9=GFX_FW_TYPE_SDMA0
                Source::Ce => 3,                 // linux-lit: 3=GFX_FW_TYPE_CP_CE
                Source::Pfp => 2,                // linux-lit: 2=GFX_FW_TYPE_CP_PFP
                Source::Me => 1,                 // linux-lit: 1=GFX_FW_TYPE_CP_ME
                Source::Mec | Source::Mec2 => 4, // linux-lit: 4=GFX_FW_TYPE_CP_MEC
                Source::Rlc | Source::Vcn | Source::Dmcub => unreachable!(),
            };
            image.push(bytes, main, kind);
            return Ok(image);
        }

        let mut ranges = [Span::EMPTY; 17];
        let mut count = 0;
        record(&mut ranges, &mut count, main)?;
        // File-relative format/register arrays are metadata, never IP firmware.
        // linux-lit: 72=offsetof(struct rlc_firmware_header_v2_0, reg_list_format_size_bytes); 80=offsetof(struct rlc_firmware_header_v2_0, reg_list_size_bytes); 88=offsetof(struct rlc_firmware_header_v2_0, reg_list_format_separate_size_bytes); 96=offsetof(struct rlc_firmware_header_v2_0, reg_list_separate_size_bytes)
        for size_field in [72, 80, 88, 96] {
            record(
                &mut ranges,
                &mut count,
                span(
                    bytes,
                    header,
                    // linux-lit: 4=offsetof(struct rlc_firmware_header_v2_0, reg_list_format_array_offset_bytes) - offsetof(struct rlc_firmware_header_v2_0, reg_list_format_size_bytes)
                    word(bytes, size_field + 4),
                    word(bytes, size_field),
                )?,
            )?;
        }
        if minor == 4 {
            // Retained P/V descriptors are unused in this header revision.
            // linux-lit: 180=offsetof(struct rlc_firmware_header_v2_3, rlcp_ucode_size_bytes); 196=offsetof(struct rlc_firmware_header_v2_3, rlcv_ucode_size_bytes)
            for field in [180, 196] {
                if word(bytes, field) != 0 {
                    return Err(Error::Unsupported);
                }
                // linux-lit: 4=offsetof(struct rlc_firmware_header_v2_3, rlcp_ucode_offset_bytes) - offsetof(struct rlc_firmware_header_v2_3, rlcp_ucode_size_bytes)
                span(bytes, header, word(bytes, field + 4), 0)?;
            }
        }
        let mut add = |size_field, kind| -> Result<(), Error> {
            let part = span(
                bytes,
                header,
                // linux-lit: 4=offsetof(struct rlc_firmware_header_v2_1, save_restore_list_cntl_offset_bytes) - offsetof(struct rlc_firmware_header_v2_1, save_restore_list_cntl_size_bytes)
                word(bytes, size_field + 4),
                word(bytes, size_field),
            )?;
            record(&mut ranges, &mut count, part)?;
            image.push(bytes, part, kind);
            Ok(())
        };
        if minor == 4 {
            // v2.4 retains the v2.3 P/V slots but Linux does not load them.
            // linux-lit: 204=offsetof(struct rlc_firmware_header_v2_4, global_tap_delays_ucode_size_bytes); 27=GFX_FW_TYPE_GLOBAL_TAP_DELAYS
            // linux-lit: 212=offsetof(struct rlc_firmware_header_v2_4, se0_tap_delays_ucode_size_bytes); 28=GFX_FW_TYPE_SE0_TAP_DELAYS
            // linux-lit: 220=offsetof(struct rlc_firmware_header_v2_4, se1_tap_delays_ucode_size_bytes); 29=GFX_FW_TYPE_SE1_TAP_DELAYS
            // linux-lit: 228=offsetof(struct rlc_firmware_header_v2_4, se2_tap_delays_ucode_size_bytes); 65=GFX_FW_TYPE_SE2_TAP_DELAYS
            // linux-lit: 236=offsetof(struct rlc_firmware_header_v2_4, se3_tap_delays_ucode_size_bytes); 66=GFX_FW_TYPE_SE3_TAP_DELAYS
            for (field, kind) in [(204, 27), (212, 28), (220, 29), (228, 65), (236, 66)] {
                add(field, kind)?;
            }
        }
        // linux-lit: 116=offsetof(struct rlc_firmware_header_v2_1, save_restore_list_cntl_size_bytes); 22=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL
        // linux-lit: 132=offsetof(struct rlc_firmware_header_v2_1, save_restore_list_gpm_size_bytes); 20=GFX_FW_TYPE_RLC_RESTORE_LIST_GPM_MEM
        // linux-lit: 148=offsetof(struct rlc_firmware_header_v2_1, save_restore_list_srm_size_bytes); 21=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_MEM
        // linux-lit: 156=offsetof(struct rlc_firmware_header_v2_2, rlc_iram_ucode_size_bytes); 26=GFX_FW_TYPE_RLC_IRAM
        // linux-lit: 164=offsetof(struct rlc_firmware_header_v2_2, rlc_dram_ucode_size_bytes); 48=GFX_FW_TYPE_RLC_DRAM_BOOT
        for (field, kind) in [(116, 22), (132, 20), (148, 21), (156, 26), (164, 48)] {
            add(field, kind)?;
        }
        if minor == 3 {
            // linux-lit: 180=offsetof(struct rlc_firmware_header_v2_3, rlcp_ucode_size_bytes); 25=GFX_FW_TYPE_RLC_P
            add(180, 25)?;
            // linux-lit: 196=offsetof(struct rlc_firmware_header_v2_3, rlcv_ucode_size_bytes); 7=GFX_FW_TYPE_RLC_V
            add(196, 7)?;
        }
        // Loading RLC_G is Linux's trigger to send AUTOLOAD_RLC afterwards.
        image.push(bytes, main, 8); // linux-lit: 8=GFX_FW_TYPE_RLC_G
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
    /// `amdgpu_vcn_setup_ucode`: Linux registers one PSP upload of the shared
    /// VCN image per unharvested instance, `UCODE_ID_VCN` (GFX_FW_TYPE_VCN,
    /// 13) for instance 0 and `UCODE_ID_VCN1` (GFX_FW_TYPE_VCN1, 58) for
    /// instance 1. `mask` bit i selects instance i; other sources are refused.
    pub(crate) fn for_vcn_instances(mut self, mask: u8) -> Result<Self, Error> {
        if self.source != Source::Vcn || mask & !3 != 0 || self.count != 1 {
            return Err(Error::Invalid);
        }
        let bytes = self.payloads[0].take().ok_or(Error::Invalid)?.bytes;
        self.count = 0;
        // linux-lit: 13=GFX_FW_TYPE_VCN
        for (instance, kind) in [(0, 13), (1, VCN1_TYPE)] {
            if mask & (1 << instance) != 0 {
                self.payloads[self.count] = Some(Payload {
                    bytes,
                    firmware_type: kind,
                });
                self.count += 1;
            }
        }
        Ok(self)
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

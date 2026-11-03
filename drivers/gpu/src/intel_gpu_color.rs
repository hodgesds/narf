//! Owned TGL+ Pipe-A CSC/LUT transactions with exact display profiles.
//! MIT Linux b90c984d615e: intel_color.c::ilk_csc_convert_ctm,
//! ilk_update_pipe_csc, icl_color_commit_noarm/arm and tgl_color_funcs;
//! intel_color_regs.h / skl_universal_plane_regs.h. Precision LUT preload
//! follows icl_load_luts/bdw_load_lut_10/intel_can_preload_luts; active/combined
//! updates use the separately retained intel_gpu_dsb transport.
use crate::{drm::card::FlipStamp, intel_gpu::Generation, intel_gpu_aux::MmioWindow};
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::FsError;

#[path = "intel_gpu_color_gen12.rs"]
mod gen12;
pub(crate) use gen12::{Profile, DISPLAY12_WORDS, MAX_COLOR_BLOB, MAX_COLOR_BLOB_TOTAL};
pub(crate) const MODE: u64 = 0x49028;
pub(crate) const GAMMA: u64 = 0x4a480;
const FRAME: u64 = 0x70040;
const CSC_ENABLE: u32 = 1 << 31;
const REGISTERS: [u64; 12] = [
    0x49030, 0x49034, 0x49038, // pre offsets
    0x49010, 0x49014, 0x49018, 0x4901c, 0x49020, 0x49024, // coefficients
    0x49040, 0x49044, 0x49048, // post offsets
];
const PLANE_COLOR_UNSUPPORTED: u32 =
    (1 << 21) | (1 << 20) | (7 << 17) | (1 << 15) | (1 << 14) | (3 << 4);

fn pipeline(io: &impl MmioWindow, primary_control: u32) -> bool {
    let plane = io.read32(0x70180);
    let color = io.read32(0x701cc);
    plane & 0xff800000 == primary_control
        && color != u32::MAX
        && color & PLANE_COLOR_UNSUPPORTED == 0
        && color & (1 << 13) != 0
        && io.read32(0x70034) == 0
        && io.read32(0x701c8) == 0
}

/// Full owned TGL+ Pipe-A RGB modeset baseline, never used by inherited/live KMS
/// adoption. Linux glk_plane_color_ctl + icl_color_commit_arm select this
/// bypass for RGB with no CTM/LUTs. The primary and pipe must already be off.
/// PIPE_CSC_MODE=0 closes both ICL_CSC_ENABLE and ICL_OUTPUT_CSC_ENABLE;
/// plane COLOR_CTL closes input/plane CSC and HDR LUT gates. Their inactive
/// coefficient/LUT contents are left intact. RGB also requires CUS_CTL=0
/// (skl_plane_check_fb/icl_plane_update_noarm), so no inherited Y-plane fetch.
/// Every address belongs solely to Pipe A's primary or Pipe A color block.
pub(crate) fn initialize_rgb_bypass<M: MmioWindow + ?Sized>(io: &M) -> Result<(), FsError> {
    initialize_pipe_rgb_bypass(io, crate::intel_gpu_pipes::Pipe::A)
}

/// [`initialize_rgb_bypass`] for `pipe`'s primary and color block, at the
/// per-pipe addresses (`intel_color_regs.h`: `SKL_BOTTOM_COLOR` and the
/// plane registers stride 0x1000, `GAMMA_MODE` 0x800, `PIPE_CSC_MODE`
/// 0x100). The external Pipe B–D owner uses it with that pipe off
/// (`hsw_crtc_enable` → `intel_color_modeset`).
pub(crate) fn initialize_pipe_rgb_bypass<M: MmioWindow + ?Sized>(
    io: &M,
    pipe: crate::intel_gpu_pipes::Pipe,
) -> Result<(), FsError> {
    let p = pipe as u64;
    let plane = io.read32(0x70180 + p * 0x1000);
    let conf = io.read32(0x70008 + p * 0x1000);
    if plane == u32::MAX || conf == u32::MAX {
        return Err(FsError::NoDevice);
    }
    if plane & (1 << 31) != 0 || conf & (3 << 30) != 0 {
        return Err(FsError::Busy);
    }
    let registers = [
        (0x70034 + p * 0x1000, 0),
        (GAMMA + p * 0x800, 0),
        (MODE + p * 0x100, 0),
        (0x701c8 + p * 0x1000, 0),
        (0x701cc + p * 0x1000, 1 << 13),
    ];
    for (register, value) in registers {
        io.write32(register, value);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    for (register, value) in registers {
        if io.read32(register) != value {
            return Err(FsError::NoDevice);
        }
    }
    Ok(())
}

/// Linux CTM uses sign-magnitude S31.32, not a two's complement i64.
pub(crate) fn coefficient(input: u64) -> u16 {
    let absolute = (input & !(1 << 63)).min((4u64 << 32) - 1);
    let (exponent, fractional) = if absolute < 1 << 29 {
        (3, 12)
    } else if absolute < 1 << 30 {
        (2, 11)
    } else if absolute < 1 << 31 {
        (1, 10)
    } else if absolute < 1 << 32 {
        (0, 9)
    } else if absolute < 2 << 32 {
        (7, 8)
    } else {
        (6, 7)
    };
    let mantissa = ((absolute >> (32 - fractional - 3)) + 4).min(0xfff) & 0xff8;
    (((input >> 63) as u16) << 15) | (exponent << 12) | mantissa as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Image {
    values: [u32; 12],
    mode: u32,
}
impl Image {
    fn ctm(coefficients: [u64; 9]) -> Self {
        let c = coefficients.map(coefficient);
        Self {
            values: [
                0,
                0,
                0,
                u32::from(c[0]) << 16 | u32::from(c[1]),
                u32::from(c[2]) << 16,
                u32::from(c[3]) << 16 | u32::from(c[4]),
                u32::from(c[5]) << 16,
                u32::from(c[6]) << 16 | u32::from(c[7]),
                u32::from(c[8]) << 16,
                0,
                0,
                0,
            ],
            mode: CSC_ENABLE,
        }
    }
    fn matches(&self, io: &impl MmioWindow) -> bool {
        io.read32(MODE) == self.mode
            && REGISTERS
                .iter()
                .zip(self.values)
                .all(|(&r, v)| io.read32(r) == v)
    }
}
/// MTL/Arrow's native post-CSC LUT: 1024 RGB entries, ten bits/channel.
/// This profile has no monotonic/equal-channel restriction (XE_LPDP_FEATURES).
pub(crate) const LUT_SIZE: usize = 1024;
pub(crate) const LEGACY_LUT_SIZE: usize = 256;
const LEGACY_BASE: u64 = 0x4a000;
const INDEX: u64 = 0x4a400;
const DATA: u64 = 0x4a404;
const POST_ENABLE: u32 = 1 << 30;
const MAX_REGS: [u64; 6] = [0x4a420, 0x4a424, 0x4a428, 0x4a430, 0x4a434, 0x4a438];
const PRE_INDEX: u64 = 0x4a484;
const PRE_DATA: u64 = 0x4a488;
const PRE_ENABLE: u32 = 1 << 31;
pub(crate) const DEGAMMA_SIZE: usize = 129;
const PRE_WORDS: usize = 131;
/// XE_LPDP_FEATURES: equal RGB and nondecreasing, U0.16 -> U0.24 rounded.
/// glk_load_degamma_lut clamps its two extended-range entries at 1.0.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DegammaLut {
    entries: Vec<u32>,
    profile: Profile,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Luts {
    pub(crate) post: Option<Arc<Lut>>,
    pub(crate) pre: Option<Arc<DegammaLut>>,
}
impl DegammaLut {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Arc<Self>, FsError> {
        Self::decode_profile(bytes, Profile::Mtl)
    }
    pub(crate) fn decode_profile(bytes: &[u8], profile: Profile) -> Result<Arc<Self>, FsError> {
        if bytes.len() != profile.sizes().1 * 8 {
            return Err(FsError::InvalidData);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(profile.pre_words())
            .map_err(|_| FsError::OutOfMemory)?;
        let mut previous = 0;
        for bytes in bytes.chunks_exact(8) {
            let channel = |at| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
            let green = channel(2);
            if channel(0) != green || channel(4) != green || green < previous {
                return Err(FsError::InvalidData);
            }
            previous = green;
            entries.push(if profile == Profile::Mtl {
                ((u64::from(green) * 0xffffff + 32767) / 65535) as u32
            } else {
                u32::from(green)
            });
        }
        entries.extend(
            [if profile == Profile::Mtl {
                1 << 24
            } else {
                1 << 16
            }; 2],
        );
        Ok(Arc::new(Self { entries, profile }))
    }
}
#[derive(Debug)]
struct PrePalette(Vec<u32>);
impl PrePalette {
    fn capture(io: &impl MmioWindow, words: usize) -> Result<Self, FsError> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(words)
            .map_err(|_| FsError::OutOfMemory)?;
        for i in 0..words {
            io.write32(PRE_INDEX, i as u32);
            let value = io.read32(PRE_DATA);
            if value == u32::MAX {
                io.write32(PRE_INDEX, 0);
                return Err(FsError::NoDevice);
            }
            entries.push(value);
        }
        io.write32(PRE_INDEX, 0);
        Ok(Self(entries))
    }
    fn matches(io: &impl MmioWindow, entries: &[u32]) -> bool {
        let mut matches = true;
        for (i, &value) in entries.iter().enumerate() {
            io.write32(PRE_INDEX, i as u32);
            matches &= io.read32(PRE_DATA) == value;
        }
        io.write32(PRE_INDEX, 0);
        matches
    }
    fn write(io: &impl MmioWindow, entries: &[u32]) -> Result<(), FsError> {
        io.write32(PRE_INDEX, 0);
        io.write32(PRE_INDEX, 1 << 10);
        for &value in entries {
            io.write32(PRE_DATA, value);
        }
        io.write32(PRE_INDEX, 0);
        if !Self::matches(io, entries) {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lut {
    entries: Vec<u32>,
}
impl Lut {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Arc<Self>, FsError> {
        Self::decode_profile(bytes, Profile::Mtl)
    }
    pub(crate) fn decode_profile(bytes: &[u8], profile: Profile) -> Result<Arc<Self>, FsError> {
        if profile == Profile::Display12 && bytes.len() != LEGACY_LUT_SIZE * 8 {
            return gen12::decode_display12(bytes);
        }
        let size = bytes.len() / 8;
        if bytes.len() % 8 != 0 || ![LEGACY_LUT_SIZE, LUT_SIZE].contains(&size) {
            return Err(FsError::InvalidData);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(size)
            .map_err(|_| FsError::OutOfMemory)?;
        for bytes in bytes.chunks_exact(8) {
            // drm_color_lut_extract(16 -> 8/10) rounds, not truncates. The UAPI
            // reserved word is ignored, exactly as Linux's ilk_lut_10 does.
            let channel = |at| {
                let v = u32::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
                (v * if size == LEGACY_LUT_SIZE { 255 } else { 1023 } + 32767) / 65535
            };
            entries.push(if size == LEGACY_LUT_SIZE {
                channel(0) << 16 | channel(2) << 8 | channel(4)
            } else {
                channel(0) << 20 | channel(2) << 10 | channel(4)
            });
        }
        Ok(Arc::new(Self { entries }))
    }
    fn mode(&self) -> u32 {
        if self.entries.len() == gen12::DISPLAY12_WORDS {
            3
        } else {
            u32::from(self.entries.len() != LEGACY_LUT_SIZE)
        }
    }
    fn write(&self, io: &impl MmioWindow) -> Result<(), FsError> {
        if self.entries.len() == gen12::DISPLAY12_WORDS {
            // Only a complete retained DSB stream can witness unreadable RAM.
            Err(FsError::Unsupported)
        } else if self.entries.len() == LEGACY_LUT_SIZE {
            legacy_write(io, &self.entries)
        } else {
            Palette::write(io, &self.entries, [1 << 16; 6])
        }
    }
    fn matches(&self, io: &impl MmioWindow) -> bool {
        if self.entries.len() == gen12::DISPLAY12_WORDS {
            gen12::matches_display12(io, &self.entries)
        } else if self.entries.len() == LEGACY_LUT_SIZE {
            io.write32(INDEX, 0);
            self.entries
                .iter()
                .enumerate()
                .all(|(i, &value)| io.read32(LEGACY_BASE + i as u64 * 4) == value)
        } else {
            let mut matches = true;
            for (i, &value) in self.entries.iter().enumerate() {
                io.write32(INDEX, i as u32);
                matches &= io.read32(DATA) == value;
            }
            io.write32(INDEX, 0);
            matches && MAX_REGS.into_iter().all(|r| io.read32(r) == 1 << 16)
        }
    }
}
fn legacy_write(io: &impl MmioWindow, entries: &[u32]) -> Result<(), FsError> {
    io.write32(INDEX, 0);
    for (i, &value) in entries.iter().enumerate() {
        io.write32(LEGACY_BASE + i as u64 * 4, value);
    }
    if entries
        .iter()
        .enumerate()
        .any(|(i, &value)| io.read32(LEGACY_BASE + i as u64 * 4) != value)
    {
        return Err(FsError::NoDevice);
    }
    Ok(())
}
#[derive(Debug)]
struct Palette {
    entries: Vec<u32>,
    legacy: Vec<u32>,
    maxima: [u32; 6],
}
impl Palette {
    fn capture(io: &impl MmioWindow) -> Result<Self, FsError> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(LUT_SIZE)
            .map_err(|_| FsError::OutOfMemory)?;
        for i in 0..LUT_SIZE {
            io.write32(INDEX, i as u32);
            let value = io.read32(DATA);
            if value == u32::MAX {
                io.write32(INDEX, 0);
                return Err(FsError::NoDevice);
            }
            entries.push(value);
        }
        io.write32(INDEX, 0);
        let mut legacy = Vec::new();
        legacy
            .try_reserve_exact(LEGACY_LUT_SIZE)
            .map_err(|_| FsError::OutOfMemory)?;
        for i in 0..LEGACY_LUT_SIZE {
            let value = io.read32(LEGACY_BASE + i as u64 * 4);
            if value == u32::MAX {
                return Err(FsError::NoDevice);
            }
            legacy.push(value);
        }
        let maxima = MAX_REGS.map(|r| io.read32(r));
        if maxima.contains(&u32::MAX) {
            return Err(FsError::NoDevice);
        }
        Ok(Self {
            entries,
            legacy,
            maxima,
        })
    }
    fn restore(&self, io: &impl MmioWindow) -> Result<(), FsError> {
        // Both access paths were captured while gamma was inactive. Restore
        // legacy first, precision last, then verify both views in case they
        // alias shared palette RAM. The original mode remains gated off.
        legacy_write(io, &self.legacy)?;
        Self::write(io, &self.entries, self.maxima)?;
        if self
            .legacy
            .iter()
            .enumerate()
            .any(|(i, &value)| io.read32(LEGACY_BASE + i as u64 * 4) != value)
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    fn write(io: &impl MmioWindow, entries: &[u32], maxima: [u32; 6]) -> Result<(), FsError> {
        // bdw_load_lut_10: reset index before enabling auto increment, then
        // reset it afterwards so subsequent legacy palette access still works.
        io.write32(INDEX, 0);
        io.write32(INDEX, 1 << 15);
        for &value in entries {
            io.write32(DATA, value);
        }
        io.write32(INDEX, 0);
        for (register, value) in MAX_REGS.into_iter().zip(maxima) {
            io.write32(register, value);
        }
        // Verify the actual indexed palette, not only the last DATA register.
        let mut matches = true;
        for (i, &value) in entries.iter().enumerate() {
            io.write32(INDEX, i as u32);
            matches &= io.read32(DATA) == value;
        }
        io.write32(INDEX, 0);
        if !matches
            || MAX_REGS
                .into_iter()
                .zip(maxima)
                .any(|(r, v)| io.read32(r) != v)
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
}
/// Retained desired image for an independently owned DSB DMA transaction.
#[derive(Debug)]
pub(crate) struct Update {
    primary_control: u32,
    image: Image,
    gamma: u32,
    lut: Option<Arc<Lut>>,
    restore_palette: bool,
    write_lut: bool,
    degamma: Option<Arc<DegammaLut>>,
    write_degamma: bool,
    restore_pre: bool,
    pub(crate) registers: Vec<(u64, u32)>,
}
impl Update {
    pub(crate) fn degamma(&self) -> Option<&[u32]> {
        self.degamma
            .as_ref()
            .filter(|_| self.write_degamma)
            .map(|lut| lut.entries.as_slice())
    }
    pub(crate) fn lut(&self) -> Option<&[u32]> {
        self.lut
            .as_ref()
            .filter(|_| self.write_lut)
            .map(|lut| lut.entries.as_slice())
    }
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    image: Image,
    gamma: u32,
    restore_palette: bool,
    restore_pre: bool,
    start: u32,
    deadline: u64,
}
/// State is installed in the per-card owner before pause/arm. Failed or
/// cancelled operations keep this original image and uncertain pending state.
#[derive(Debug)]
pub(crate) struct Owner {
    original: Image,
    /// Source-selected immutable original and transactional current input.
    /// Arbitration/family is never inferred from a later readable format.
    original_primary_control: u32,
    primary_control: u32,
    gen12_family: Option<crate::intel_gpu_gt::Gen12Platform>,
    /// None admits common CTM only. Gen12 requires a retained internal-pipe
    /// resource witness before this profile may be qualified.
    profile: Option<Profile>,
    gamma: u32,
    expected: Image,
    expected_gamma: u32,
    original_palette: Option<Palette>,
    original_pre: Option<PrePalette>,
    palette_dirty: bool,
    pre_dirty: bool,
    degamma: Option<Arc<DegammaLut>>,
    lut: Option<Arc<Lut>>,
    pending: Option<Pending>,
    external_pending: bool,
    failed: bool,
}
impl Owner {
    pub(crate) fn capture(io: &impl MmioWindow, generation: Generation) -> Result<Self, FsError> {
        match generation {
            Generation::TigerLake => {
                Self::capture_gen12(io, crate::intel_gpu_gt::Gen12Platform::TigerLake)
            }
            Generation::MeteorLake => Self::capture_control(io, generation, None, 0x84000000),
            // AlderLake alone cannot distinguish display12 ADLS from
            // display13 ADLP/N. Actual callers must supply the PCI family.
            _ => Err(FsError::Unsupported),
        }
    }
    pub(crate) fn capture_gen12(
        io: &impl MmioWindow,
        family: crate::intel_gpu_gt::Gen12Platform,
    ) -> Result<Self, FsError> {
        let generation = if family == crate::intel_gpu_gt::Gen12Platform::TigerLake {
            Generation::TigerLake
        } else {
            Generation::AlderLake
        };
        Self::capture_control(
            io,
            generation,
            Some(family),
            crate::intel_gpu_pipes::gen12_xrgb_control(family),
        )
    }
    fn capture_control(
        io: &impl MmioWindow,
        generation: Generation,
        gen12_family: Option<crate::intel_gpu_gt::Gen12Platform>,
        primary_control: u32,
    ) -> Result<Self, FsError> {
        let mode = io.read32(MODE);
        let gamma = io.read32(GAMMA);
        if mode != 0
            || gamma == u32::MAX
            || gamma & (3 << 30) != 0
            || !pipeline(io, primary_control)
        {
            return Err(FsError::Unsupported);
        }
        let mut values = [0; 12];
        for (value, register) in values.iter_mut().zip(REGISTERS) {
            *value = io.read32(register);
            if *value == u32::MAX {
                return Err(FsError::NoDevice);
            }
        }
        let original = Image { values, mode };
        Ok(Self {
            original,
            original_primary_control: primary_control,
            primary_control,
            gen12_family,
            profile: (generation == Generation::MeteorLake).then_some(Profile::Mtl),
            gamma,
            expected: original,
            expected_gamma: gamma,
            original_palette: None,
            original_pre: None,
            palette_dirty: false,
            pre_dirty: false,
            degamma: None,
            lut: None,
            pending: None,
            external_pending: false,
            failed: false,
        })
    }
    pub(crate) fn qualify_gen12(&mut self, profile: Profile) -> Result<(), FsError> {
        if self
            .gen12_family
            .is_none_or(|family| Profile::gen12(family) != profile)
        {
            return Err(FsError::Unsupported);
        }
        if self.profile == Some(profile) {
            return Ok(());
        }
        if self.pending() || self.expected_gamma & (POST_ENABLE | PRE_ENABLE) != 0 {
            return Err(FsError::Unsupported);
        }
        self.profile = Some(profile);
        Ok(())
    }
    pub(crate) fn owns_unreadable_ram(&self) -> bool {
        self.profile == Some(Profile::Display12) && self.palette_dirty
    }
    fn check_luts(&self, lut: Option<&Lut>, pre: Option<&DegammaLut>) -> Result<(), FsError> {
        if lut.is_none() && pre.is_none() {
            return Ok(());
        }
        let profile = self.profile.ok_or(FsError::Unsupported)?;
        if pre.is_some_and(|p| p.profile != profile)
            || lut.is_some_and(|p| {
                p.entries.len() != LEGACY_LUT_SIZE
                    && p.entries.len()
                        != if profile == Profile::Display12 {
                            gen12::DISPLAY12_WORDS
                        } else {
                            LUT_SIZE
                        }
            })
        {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some() || self.external_pending
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn arm(
        &mut self,
        io: &impl MmioWindow,
        coefficients: Option<[u64; 9]>,
        now: u64,
    ) -> Result<(), FsError> {
        self.arm_color(io, coefficients, self.lut.clone(), now)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn arm_color(
        &mut self,
        io: &impl MmioWindow,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<Lut>>,
        now: u64,
    ) -> Result<(), FsError> {
        self.arm_stages(io, coefficients, lut, self.degamma.clone(), now)
    }
    pub(crate) fn arm_stages(
        &mut self,
        io: &impl MmioWindow,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<Lut>>,
        degamma: Option<Arc<DegammaLut>>,
        now: u64,
    ) -> Result<(), FsError> {
        if self.failed {
            return Err(FsError::NoDevice);
        }
        if self.pending() {
            return Err(FsError::Busy);
        }
        self.check_luts(lut.as_deref(), degamma.as_deref())?;
        // Display12 requires a complete DSB stream, even for inactive preload.
        if self.profile == Some(Profile::Display12) && (lut.is_some() || degamma.is_some()) {
            return Err(FsError::Unsupported);
        }
        // Single-buffered LUT: only inactive preload is source-qualified.
        // Same-LUT CTM changes do not touch palette memory at all.
        let changed = self.lut != lut;
        let changed_pre = self.degamma != degamma;
        if ((changed && lut.is_some()) || (changed_pre && degamma.is_some()))
            && self.expected_gamma & (POST_ENABLE | PRE_ENABLE) != 0
        {
            return Err(FsError::Unsupported);
        }
        if !pipeline(io, self.primary_control)
            || !self.expected.matches(io)
            || io.read32(GAMMA) != self.expected_gamma
        {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        if let Some(pre) = degamma.as_ref().filter(|_| changed_pre) {
            if self.original_pre.is_none() {
                self.original_pre = Some(PrePalette::capture(
                    io,
                    self.profile.map_or(PRE_WORDS, Profile::pre_words),
                )?);
            }
            self.failed = true;
            self.pre_dirty = true;
            PrePalette::write(io, &pre.entries)?;
            self.failed = false;
        }
        if let Some(lut) = lut.as_ref().filter(|_| changed) {
            if self.original_palette.is_none() {
                self.original_palette = Some(Palette::capture(io)?);
            }
            // Retain original and uncertain ownership before the first write.
            self.failed = true;
            self.palette_dirty = true;
            lut.write(io)?;
            self.failed = false;
        }
        let mut gamma = if let Some(lut) = &lut {
            (self.gamma & !3) | POST_ENABLE | lut.mode()
        } else {
            self.gamma
        };
        if degamma.is_some() {
            gamma |= PRE_ENABLE;
        }
        let both_off = lut.is_none() && degamma.is_none();
        let restore_palette =
            both_off && self.palette_dirty && self.profile != Some(Profile::Display12);
        let restore_pre = both_off && self.pre_dirty;
        self.lut = lut;
        self.degamma = degamma;
        self.write(
            io,
            coefficients.map_or(self.original, Image::ctm),
            gamma,
            restore_palette,
            restore_pre,
            now,
        )
    }
    pub(crate) fn needs_inactive_preload(
        &self,
        lut: Option<&Lut>,
        pre: Option<&DegammaLut>,
    ) -> bool {
        self.profile == Some(Profile::Display12)
            && self.expected_gamma & (POST_ENABLE | PRE_ENABLE) == 0
            && (lut.is_some() || pre.is_some())
            && (self.lut.as_deref() != lut || self.degamma.as_deref() != pre)
    }
    pub(crate) fn prepare_inactive_preload(
        &mut self,
        io: &impl MmioWindow,
        lut: Option<Arc<Lut>>,
        pre: Option<Arc<DegammaLut>>,
    ) -> Result<Update, FsError> {
        if !self.needs_inactive_preload(lut.as_deref(), pre.as_deref()) {
            return Err(FsError::Unsupported);
        }
        let mut update = self.prepare_stages(io, None, lut, pre)?;
        // Retain current visible bypass/CSC through the full table DMA. The
        // subsequent transaction arms enable only after this stream is proved.
        update.image = self.expected;
        update.gamma = self.expected_gamma;
        update.registers.clear();
        Ok(update)
    }
    pub(crate) fn prepare_stages(
        &mut self,
        io: &impl MmioWindow,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<Lut>>,
        degamma: Option<Arc<DegammaLut>>,
    ) -> Result<Update, FsError> {
        // Gen12 DSB and native LUT layouts have separate qualification gates.
        if self.profile.is_none() {
            return Err(FsError::Unsupported);
        }
        self.check_luts(lut.as_deref(), degamma.as_deref())?;
        if self.failed {
            return Err(FsError::NoDevice);
        }
        if self.pending() {
            return Err(FsError::Busy);
        }
        if !pipeline(io, self.primary_control)
            || !self.expected.matches(io)
            || io.read32(GAMMA) != self.expected_gamma
        {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        if lut.is_some()
            && self.original_palette.is_none()
            && self.profile != Some(Profile::Display12)
        {
            // First use is inactive by capture's strict initial bypass gate.
            if self.expected_gamma & POST_ENABLE != 0 {
                return Err(FsError::NoDevice);
            }
            self.original_palette = Some(Palette::capture(io)?);
        }
        if degamma.is_some() && self.original_pre.is_none() {
            if self.expected_gamma & PRE_ENABLE != 0 {
                return Err(FsError::NoDevice);
            }
            self.original_pre = Some(PrePalette::capture(
                io,
                self.profile.map_or(PRE_WORDS, Profile::pre_words),
            )?);
        }
        let image = coefficients.map_or(self.original, Image::ctm);
        let mut gamma = if let Some(lut) = &lut {
            (self.gamma & !3) | POST_ENABLE | lut.mode()
        } else {
            self.gamma
        };
        if degamma.is_some() {
            gamma |= PRE_ENABLE;
        }
        let mut registers: Vec<(u64, u32)> = REGISTERS.into_iter().zip(image.values).collect();
        registers.extend([(GAMMA, gamma), (MODE, image.mode)]);
        let both_off = lut.is_none() && degamma.is_none();
        let restore_palette =
            both_off && self.palette_dirty && self.profile != Some(Profile::Display12);
        self.external_pending = true;
        let write_lut = self.lut != lut;
        let write_degamma = self.degamma != degamma;
        let restore_pre = both_off && self.pre_dirty;
        Ok(Update {
            primary_control: self.primary_control,
            image,
            gamma,
            lut,
            restore_palette,
            write_lut,
            degamma,
            write_degamma,
            restore_pre,
            registers,
        })
    }
    /// Bind only the qualified opaque input of the already prepared joint
    /// primary transaction. The old image was checked by prepare_stages.
    pub(crate) fn target_input(
        &self,
        update: &mut Update,
        input: crate::intel_gpu_scanout::InputFormat,
    ) -> Result<(), FsError> {
        if self.profile != Some(Profile::Mtl)
            || self.gen12_family.is_some()
            || self.original_primary_control != 0x84000000
        {
            return Err(FsError::Unsupported);
        }
        update.primary_control = (self.original_primary_control & !(0x1f << 23)) | input.control();
        Ok(())
    }
    /// A separately completed fresh console arm has restored the immutable
    /// original input. Keep any still-owned color image exactly as observed.
    pub(crate) fn console_restored(&mut self, io: &impl MmioWindow) -> Result<(), FsError> {
        if self.pending()
            || self.failed
            || !pipeline(io, self.original_primary_control)
            || !self.expected.matches(io)
            || io.read32(GAMMA) != self.expected_gamma
        {
            return Err(FsError::NoDevice);
        }
        self.primary_control = self.original_primary_control;
        Ok(())
    }
    /// Read-only reconciliation of an unexposed format intent. Active color
    /// may remain owned, but the input must still be the immutable original.
    pub(crate) fn original_input_visible(&self, io: &impl MmioWindow) -> bool {
        self.primary_control == self.original_primary_control && self.check_visible(io).is_ok()
    }
    pub(crate) fn original_visible(&self) -> bool {
        self.expected == self.original
            && self.expected_gamma == self.gamma
            && self.lut.is_none()
            && self.degamma.is_none()
            && !self.palette_dirty
            && !self.pre_dirty
            && !self.pending()
    }
    pub(crate) fn cancel_dsb_before_arm(&mut self) {
        self.external_pending = false;
    }
    /// Called synchronously after an arm that may expose palette commands,
    /// before yielding the session. A strict pre-write refusal never reaches
    /// this point. Keep the obligation through cancellation or partial DMA.
    pub(crate) fn expose_dsb(&mut self, update: &Update) {
        self.palette_dirty |= update.write_lut && update.lut.is_some();
        self.pre_dirty |= update.write_degamma && update.degamma.is_some();
    }
    /// Recheck only persistent visible arms after the complete profile-specific
    /// LUT/DSB proof. RAM remains exclusively owned; display12 never attempts
    /// architecturally unreliable fine/coarse data readback here or elsewhere.
    pub(crate) fn check_visible(&self, io: &impl MmioWindow) -> Result<(), FsError> {
        if self.failed
            || self.external_pending
            || !pipeline(io, self.primary_control)
            || !self.expected.matches(io)
            || io.read32(GAMMA) != self.expected_gamma
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    pub(crate) fn complete_dsb(
        &mut self,
        io: &impl MmioWindow,
        update: &Update,
    ) -> Result<(), FsError> {
        if !self.external_pending || self.failed {
            return Err(FsError::NoDevice);
        }
        self.failed = true;
        if !pipeline(io, update.primary_control)
            || !update.image.matches(io)
            || io.read32(GAMMA) != update.gamma
        {
            return Err(FsError::NoDevice);
        }
        if let Some(lut) = &update.lut {
            if !lut.matches(io) {
                return Err(FsError::NoDevice);
            }
        }
        if update.restore_palette {
            let original = self.original_palette.as_ref().expect("original palette");
            original.restore(io)?;
            self.palette_dirty = false;
        }
        if let Some(pre) = &update.degamma {
            if !PrePalette::matches(io, &pre.entries) {
                return Err(FsError::NoDevice);
            }
        }
        if update.restore_pre {
            PrePalette::write(io, &self.original_pre.as_ref().expect("original pre").0)?;
            self.pre_dirty = false;
        }
        self.primary_control = update.primary_control;
        self.expected = update.image;
        self.expected_gamma = update.gamma;
        self.lut = update.lut.clone();
        self.degamma = update.degamma.clone();
        self.external_pending = false;
        self.failed = false;
        Ok(())
    }
    /// Only a fresh post-reset view may restore an image after loss. First
    /// latch disabled gamma; original single-buffered entries are rewritten
    /// only after that separate frame/readback proof, before admission reopens.
    pub(crate) fn recover_original(
        &mut self,
        io: &impl MmioWindow,
        now: u64,
    ) -> Result<(), FsError> {
        self.failed = false;
        self.pending = None;
        self.external_pending = false;
        if !pipeline(io, self.original_primary_control) {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.primary_control = self.original_primary_control;
        self.lut = None;
        self.degamma = None;
        // Fresh recovery revalidates all retained original RAM, including
        // stages restored before the loss. Ordinary bypassed CTM commits do
        // not create this recovery-only obligation.
        self.palette_dirty |= self.original_palette.is_some();
        self.pre_dirty |= self.original_pre.is_some();
        self.write(
            io,
            self.original,
            self.gamma,
            self.palette_dirty && self.profile != Some(Profile::Display12),
            self.pre_dirty,
            now,
        )
    }
    fn write(
        &mut self,
        io: &impl MmioWindow,
        image: Image,
        gamma: u32,
        restore_palette: bool,
        restore_pre: bool,
        now: u64,
    ) -> Result<(), FsError> {
        let start = io.read32(FRAME);
        if start == u32::MAX {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.pending = Some(Pending {
            image,
            gamma,
            restore_palette,
            restore_pre,
            start,
            deadline: now.saturating_add(1_000_000_000),
        });
        for (&register, value) in REGISTERS.iter().zip(image.values) {
            io.write32(register, value);
        }
        io.write32(GAMMA, gamma);
        io.write32(MODE, image.mode);
        if !image.matches(io) || io.read32(GAMMA) != gamma {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        // Capture after the posted arm. A prior vblank is never latch evidence.
        let armed = io.read32(FRAME);
        if armed == u32::MAX || armed != start {
            // GAMMA_MODE and CSC_MODE have separate arm writes. Refuse a
            // transaction spanning the latch boundary instead of reporting a
            // possibly split CTM/gamma update as atomic success.
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.pending.as_mut().expect("pending color").start = armed;
        Ok(())
    }
    pub(crate) fn poll(
        &mut self,
        io: &impl MmioWindow,
        now: u64,
    ) -> Result<Option<FlipStamp>, FsError> {
        if self.failed {
            return Err(FsError::NoDevice);
        }
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        if !pipeline(io, self.primary_control)
            || !pending.image.matches(io)
            || io.read32(GAMMA) != pending.gamma
        {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        let before = io.read32(FRAME);
        let after = io.read32(FRAME);
        if before != u32::MAX && before == after && before != pending.start {
            if pending.restore_palette {
                // POST_CSC_GAMMA_ENABLE is now proved off at a later vblank.
                // No in-place active restoration is hidden behind this path.
                let original = self.original_palette.as_ref().expect("saved palette");
                self.failed = true;
                original.restore(io)?;
                self.palette_dirty = false;
                self.failed = false;
            }
            if pending.restore_pre {
                self.failed = true;
                PrePalette::write(io, &self.original_pre.as_ref().expect("saved pre").0)?;
                self.pre_dirty = false;
                self.failed = false;
            }
            self.expected = pending.image;
            self.expected_gamma = pending.gamma;
            self.pending = None;
            return Ok(Some(FlipStamp {
                ns: now,
                sequence: before,
            }));
        }
        if now >= pending.deadline {
            self.failed = true;
            return Err(FsError::TimedOut);
        }
        Ok(None)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_color_tests.rs"]
mod tests;

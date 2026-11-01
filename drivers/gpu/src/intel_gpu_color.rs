//! Owned Pipe-A CTM transaction for MTL/Arrow's TGL+ display color pipeline.
//! MIT Linux b90c984d615e: intel_color.c::ilk_csc_convert_ctm,
//! ilk_update_pipe_csc, icl_color_commit_noarm/arm and tgl_color_funcs;
//! intel_color_regs.h / skl_universal_plane_regs.h. No LUT writes or DSB.
use crate::{drm::card::FlipStamp, intel_gpu::Generation, intel_gpu_aux::MmioWindow};
use narf_filesystem::FsError;

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

fn pipeline(io: &impl MmioWindow) -> bool {
    let plane = io.read32(0x70180);
    let color = io.read32(0x701cc);
    plane & 0x9f000000 == 0x84000000
        && color != u32::MAX
        && color & PLANE_COLOR_UNSUPPORTED == 0
        && color & (1 << 13) != 0
        && io.read32(0x70034) == 0
        && io.read32(0x701c8) == 0
}

/// Full owned MTL/Arrow modeset baseline, never used by inherited/live KMS
/// adoption. Linux glk_plane_color_ctl + icl_color_commit_arm select this
/// bypass for RGB with no CTM/LUTs. The primary and pipe must already be off.
/// PIPE_CSC_MODE=0 closes both ICL_CSC_ENABLE and ICL_OUTPUT_CSC_ENABLE;
/// plane COLOR_CTL closes input/plane CSC and HDR LUT gates. Their inactive
/// coefficient/LUT contents are left intact. RGB also requires CUS_CTL=0
/// (skl_plane_check_fb/icl_plane_update_noarm), so no inherited Y-plane fetch.
/// Every address belongs solely to Pipe A's primary or Pipe A color block.
pub(crate) fn initialize_rgb_bypass<M: MmioWindow + ?Sized>(io: &M) -> Result<(), FsError> {
    let plane = io.read32(0x70180);
    let pipe = io.read32(0x70008);
    if plane == u32::MAX || pipe == u32::MAX {
        return Err(FsError::NoDevice);
    }
    if plane & (1 << 31) != 0 || pipe & (3 << 30) != 0 {
        return Err(FsError::Busy);
    }
    let registers = [
        (0x70034, 0),
        (GAMMA, 0),
        (MODE, 0),
        (0x701c8, 0),
        (0x701cc, 1 << 13),
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
#[derive(Clone, Copy, Debug)]
struct Pending {
    image: Image,
    start: u32,
    deadline: u64,
}
/// State is installed in the per-card owner before pause/arm. Failed or
/// cancelled operations keep this original image and uncertain pending state.
#[derive(Debug)]
pub(crate) struct Owner {
    original: Image,
    gamma: u32,
    expected: Image,
    pending: Option<Pending>,
    failed: bool,
}
impl Owner {
    pub(crate) fn capture(io: &impl MmioWindow, generation: Generation) -> Result<Self, FsError> {
        if generation != Generation::MeteorLake {
            return Err(FsError::Unsupported);
        }
        let mode = io.read32(MODE);
        let gamma = io.read32(GAMMA);
        if mode != 0 || gamma == u32::MAX || gamma & (3 << 30) != 0 || !pipeline(io) {
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
            gamma,
            expected: original,
            pending: None,
            failed: false,
        })
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn arm(
        &mut self,
        io: &impl MmioWindow,
        coefficients: Option<[u64; 9]>,
        now: u64,
    ) -> Result<(), FsError> {
        if self.failed {
            return Err(FsError::NoDevice);
        }
        if self.pending.is_some() {
            return Err(FsError::Busy);
        }
        if !pipeline(io) || !self.expected.matches(io) || io.read32(GAMMA) != self.gamma {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.write(io, coefficients.map_or(self.original, Image::ctm), now)
    }
    /// Only the fresh post-reset view can restore an image after loss. No
    /// old pending frame/readback is consumed as evidence of this new arm.
    pub(crate) fn recover_original(
        &mut self,
        io: &impl MmioWindow,
        now: u64,
    ) -> Result<(), FsError> {
        self.failed = false;
        self.pending = None;
        if !pipeline(io) {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.write(io, self.original, now)
    }
    fn write(&mut self, io: &impl MmioWindow, image: Image, now: u64) -> Result<(), FsError> {
        // Publish uncertain ownership before the first write. All coefficient
        // registers are non-arming shadow registers on TGL+; CSC_MODE is last.
        let start = io.read32(FRAME);
        if start == u32::MAX {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.pending = Some(Pending {
            image,
            start,
            deadline: now.saturating_add(1_000_000_000),
        });
        for (&register, value) in REGISTERS.iter().zip(image.values) {
            io.write32(register, value);
        }
        io.write32(GAMMA, self.gamma);
        io.write32(MODE, image.mode);
        if !image.matches(io) || io.read32(GAMMA) != self.gamma {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        // Capture after posting the arm. Waiting for a later stable frame
        // cannot mistake a vblank between coefficient writes and arm for latch.
        let start = io.read32(FRAME);
        if start == u32::MAX {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        self.pending.as_mut().expect("pending color").start = start;
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
        if !pipeline(io) || !pending.image.matches(io) || io.read32(GAMMA) != self.gamma {
            self.failed = true;
            return Err(FsError::NoDevice);
        }
        let before = io.read32(FRAME);
        let after = io.read32(FRAME);
        if before != u32::MAX && before == after && before != pending.start {
            self.expected = pending.image;
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

//! Native OPP/FMT/DPG preparation under the DCN401 timing owner's lifetime.
//! Linux uses dcn10_opp.c/dcn20_opp.c with native DCN4 register banks.
use super::*;

#[path = "amdgpu_dcn401_blank.rs"]
mod blank;
pub use blank::BlankRunning;

const EXPANSION: u64 = 0x183f;
const FMT: u64 = 0x1840;
const DEPTH: u64 = 0x1841;
const SEED_R: u64 = 0x1842;
const SEED_G: u64 = 0x1843;
const SEED_B: u64 = 0x1844;
const CLAMP: u64 = 0x1845;
const MAP420: u64 = 0x1847; // FMT_MAP420_MEMORY_CONTROL
const EDGE: u64 = 0x1849;
const DPG: u64 = 0x1854;
const DIMENSIONS: u64 = 0x1856;
const RED: u64 = 0x1857;
const GREEN: u64 = 0x1858;
const BLUE: u64 = 0x1859;
const OFFSET: u64 = 0x185a;
const PENDING: u64 = 0x185b;
const PIPE: u64 = 0x188c;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    Bpc8,
    Bpc10,
    Bpc12,
}
impl ColorDepth {
    pub(in crate::amdgpu_dcn401_otg) fn dpg(self) -> u32 {
        match self {
            Self::Bpc8 => 1,
            Self::Bpc10 => 2,
            Self::Bpc12 => 3,
        }
    }
    fn truncate(self) -> u32 {
        match self {
            Self::Bpc8 => 0x11,  // truncation to 8 bpc
            Self::Bpc10 => 0x23, // native TRUN10 rounding mode
            Self::Bpc12 => 0,    // no reduction
        }
    }
}
/// RGB black pattern. Timing dimensions come from the matching prepared
/// pipe; no independent size can accidentally disagree with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlankRequest {
    pub pipe: u8,
    pub depth: ColorDepth,
    /// Limited-range (16-235) RGB output, Linux's COLOR_SPACE_SRGB_LIMITED:
    /// the MPC output CSC compresses the range, the blank pattern is limited
    /// black and the stream signals it. Full range (COLOR_SPACE_SRGB)
    /// otherwise.
    pub limited: bool,
    /// HDMI YCbCr 4:2:0 output (COLOR_SPACE_YCBCR709): the formatter
    /// subsamples, the MPC output CSC converts to BT.709 YCbCr (always
    /// limited range: `limited` is for RGB) and the blank pattern is YCbCr
    /// black. Requires 4:2:0 timing.
    pub ycbcr420: bool,
}
impl BlankRequest {
    /// The OPP registers, then for 4:2:0 the 4:2:0 memory's power control
    /// (opp1_program_fmt releases its forced state; RGB leaves it alone).
    pub(in crate::amdgpu_dcn401_otg) fn registers(
        self,
        t: Timing,
    ) -> impl Iterator<Item = (u64, u32, u32)> {
        self.common_registers(t)
            .into_iter()
            .chain(self.ycbcr420.then_some((MAP420, 3, 0)))
    }
    fn common_registers(self, t: Timing) -> [(u64, u32, u32); 14] {
        // black_color_format: limited black is 0x40 of 10 bits, a YCbCr
        // chroma midpoint 0x200, MSB aligned in both 16-bit colour fields.
        let (red, green, blue) = match (self.ycbcr420, self.limited) {
            (true, _) => (0x8000_8000, 0x1000_1000, 0x8000_8000), // Cr, Y, Cb
            (false, true) => (0x1000_1000, 0x1000_1000, 0x1000_1000),
            (false, false) => (0, 0, 0),
        };
        // FMT_PIXEL_ENCODING 4:2:0, subsampling mode 2, Cb/Cr bit
        // reduction bypassed (opp1_set_pixel_encoding); RGB otherwise.
        let format = if self.ycbcr420 {
            2 << 16 | 2 << 18 | 1 << 21
        } else {
            0
        };
        [
            // No 4:2:2/4:2:0 chroma filter extra left pixel on the primary
            // OPP (opp2_get_left_edge_extra_pixel_count).
            (EDGE, 1, 0),
            // Explicit truncation, no spatial/temporal dithering or randomization.
            (DEPTH, 0x1ff33, self.depth.truncate()),
            // Clear RGB/YUV offsets as well as the inactive dither seeds.
            (SEED_R, 0xffff00ff, 0),
            (SEED_G, 0xffff00ff, 0),
            (SEED_B, 0xffff00ff, 0),
            (FMT, 0x2f3f00, format), // frame counter/randomization off
            (CLAMP, 0x70001, 1),     // full range
            (
                EXPANSION,
                0x11,
                if self.depth == ColorDepth::Bpc8 {
                    0x11
                } else {
                    1
                },
            ),
            (DIMENSIONS, 0x3fff3fff, t.h_active << 16 | t.v_active),
            (OFFSET, 0x3fff3fff, 0),
            (BLUE, u32::MAX, blue),
            (GREEN, u32::MAX, green),
            (RED, u32::MAX, red),
            // Equal black bars; clear range/resolution/field-polarity.
            (DPG, 0x01ff3171, 0x41 | self.depth.dpg() << 12),
        ]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlankApplied {
    pub request: BlankRequest,
    pub timing: Applied,
    /// Observed double-buffer pending bit. The OTG remains stopped; even zero
    /// is not evidence of active blanking. Scanout startup must verify it again
    /// after acknowledged timing enable, before allowing plane or link output.
    pub pending: bool,
}
impl Layout {
    pub(super) fn opp(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x5a) * 4
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn blank_timing(
        &self,
        request: BlankRequest,
        clock: dccg::Applied,
    ) -> Result<Applied, Error> {
        let timing = self
            .status
            .pipes
            .get(usize::from(request.pipe))
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?;
        if timing.clock != clock
            || timing.request.pipe != request.pipe
            || timing.request.timing.h_active > 0x3fff
            || timing.request.timing.v_active > 0x3fff
            // 4:2:0 formatting on 4:2:0 timing only, and always YCbCr's
            // own (limited) range.
            || request.ycbcr420 != timing.request.ycbcr420
            || request.ycbcr420 && request.limited
        {
            return Err(Error::Invalid);
        }
        Ok(timing)
    }
    async fn program_blank(
        &mut self,
        request: BlankRequest,
        timing: Applied,
    ) -> Result<BlankApplied, Error> {
        let l = self.layout;
        let at = |r| l.opp(request.pipe, r);
        // A digital bypass would bypass this format path. The caller must
        // retire that configuration before preparing ordinary RGB output.
        if self.read(at(PIPE))? & 0x10 != 0 {
            return Err(Error::Busy);
        }
        self.update(at(PIPE), 1, 1)?;
        self.wait(at(PIPE), 2, 2, 1000).await?;
        for (r, mask, value) in request.registers(timing.request.timing) {
            self.update(at(r), mask, value)?;
        }
        let pending = self.read(at(PENDING))? & 1 != 0;
        Ok(BlankApplied {
            request,
            timing,
            pending,
        })
    }
    pub(super) async fn prepare_blank(
        &mut self,
        request: BlankRequest,
        clock: dccg::Applied,
    ) -> Result<BlankApplied, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        let timing = self.blank_timing(request, clock)?;
        self.preflight(request.pipe, false)?;
        // Do not overwrite a previous unlatched FMT/DPG transaction.
        if self.read(self.layout.opp(request.pipe, FMT))? & 0x1000000 != 0
            || self.read(self.layout.opp(request.pipe, PENDING))? & 1 != 0
            || self.read(self.layout.opp(request.pipe, PIPE))? & 0x10 != 0
        {
            return Err(Error::Busy);
        }
        self.status.state = State::PreparingBlank(request.pipe);
        self.status.mpcs[usize::from(request.pipe)] = None;
        self.status.requestor = None;
        self.status.deadlines = None;
        match self.program_blank(request, timing).await {
            Ok(applied) => {
                self.status.blanks[usize::from(request.pipe)] = Some(applied);
                self.status.state = State::BlankPrepared;
                Ok(applied)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Stage OPP full-range RGB format and a solid black pattern for prepared
    /// timing. All consumers remain stopped. This does not prove active blanking:
    /// native double-buffer completion follows timing enable, a separate step.
    pub async fn prepare_blank(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        request: BlankRequest,
    ) -> Result<BlankApplied, Error> {
        if !self.0.status.state.reusable() {
            return Err(Error::Busy);
        }
        if request.pipe >= 4 {
            return Err(Error::Invalid);
        }
        let (held, layout) = self.0.held();
        let clock = dccg
            .timing_clock_except(self.0.io.0, clocks, request.pipe, &|at| {
                held_by_sibling(held, layout, at)
            })
            .map_err(Error::PipeClocks)?;
        self.0.prepare_blank(request, clock).await
    }
}

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
    /// Bits per component.
    pub fn bpc(self) -> u32 {
        match self {
            Self::Bpc8 => 8,
            Self::Bpc10 => 10,
            Self::Bpc12 => 12,
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
    /// The stream's output color space (amdgpu_dm_get_output_color_space):
    /// it selects the output CSC (find_color_matrix), the blank black
    /// (color_space_to_black_color) and the colorimetry the stream signals.
    /// `limited` must say whether it is a limited-range RGB space.
    pub colorspace: crate::amdgpu_hdr::DcColorSpace,
}
impl BlankRequest {
    /// The plain stream color spaces `limited` and `ycbcr420` describe
    /// alone (DRM's Default colorimetry above the SDTV pixel rate).
    pub fn default_colorspace(limited: bool, ycbcr420: bool) -> crate::amdgpu_hdr::DcColorSpace {
        use crate::amdgpu_hdr::DcColorSpace as C;
        match (ycbcr420, limited) {
            (true, _) => C::Ycbcr709,
            (false, true) => C::SrgbLimited,
            (false, false) => C::Srgb,
        }
    }
    /// The OPP registers, then for 4:2:0 the 4:2:0 memory's power control
    /// (opp1_program_fmt releases its forced state; RGB leaves it alone).
    /// One ODM segment's OPP (`segment` 0 is the timing's own OPP): the
    /// pattern generator covers that segment's columns only, at its offset
    /// within the line (dcn20_blank_pixel_data per ODM slice).
    pub(in crate::amdgpu_dcn401_otg) fn segment_registers(
        self,
        plan: Plan,
        segment: u32,
    ) -> impl Iterator<Item = (u64, u32, u32)> {
        let (x, width) = plan.segment(segment);
        // opp2_get_left_edge_extra_pixel_count: a non-primary OPP's 4:2:0
        // chroma filter takes one pixel from the left neighbour.
        let edge = u32::from(self.ycbcr420 && segment > 0);
        self.common_registers(plan.request.timing, width, x, edge)
            .into_iter()
            .chain(self.ycbcr420.then_some((MAP420, 3, 0)))
    }
    fn common_registers(self, t: Timing, width: u32, x: u32, edge: u32) -> [(u64, u32, u32); 14] {
        // color_space_to_black_color: YCbCr spaces' black, sRGB limited's
        // (0x40 of 10 bits), and full-range black for every other space,
        // BT.2020 limited RGB included. MSB aligned in both 16-bit colour
        // fields; YCbCr chroma sits at its 0x200 midpoint.
        use crate::amdgpu_hdr::DcColorSpace as C;
        let (red, green, blue) = match self.colorspace {
            C::Ycbcr601
            | C::Ycbcr709
            | C::Ycbcr709Black
            | C::Ycbcr601Limited
            | C::Ycbcr709Limited
            | C::Ycbcr2020Limited
            | C::Ycbcr2020Full => (0x8000_8000, 0x1000_1000, 0x8000_8000), // Cr, Y, Cb
            C::SrgbLimited => (0x1000_1000, 0x1000_1000, 0x1000_1000),
            _ => (0, 0, 0),
        };
        // FMT_PIXEL_ENCODING 4:2:0, subsampling mode 2, Cb/Cr bit
        // reduction bypassed (opp1_set_pixel_encoding); RGB otherwise.
        let format = if self.ycbcr420 {
            2 << 16 | 2 << 18 | 1 << 21
        } else {
            0
        };
        [
            // The 4:2:2/4:2:0 chroma filter's extra left pixel: none on the
            // primary OPP (opp2_get_left_edge_extra_pixel_count).
            (EDGE, 1, edge),
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
            (DIMENSIONS, 0x3fff3fff, width << 16 | t.v_active),
            (OFFSET, 0x3fff3fff, x),
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
        self.base + (reg + u64::from(self.inst(pipe)) * 0x5a) * 4
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
            // A compressed stream's OPP feeds its DSC the depth the PPS
            // codes (the stream's display_color_depth).
            || timing
                .request
                .dsc
                .is_some_and(|c| u32::from(c.bpc) != request.depth.bpc())
            || request.ycbcr420 && request.limited
            // `limited` names the limited-range RGB spaces exactly.
            || request.limited
                != matches!(
                    request.colorspace,
                    crate::amdgpu_hdr::DcColorSpace::SrgbLimited
                        | crate::amdgpu_hdr::DcColorSpace::Rgb2020Limited
                )
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
        let plan = timing.request.plan()?;
        let mut pending = false;
        // Every ODM segment's OPP: pipe clock on, then its formatter and
        // its part of the black pattern (enable_stream_timing's
        // opp_pipe_clock_control for each OPP head, then blank_pixel_data).
        for (segment, o) in plan.opps().enumerate() {
            let at = |r| l.opp(o, r);
            // A digital bypass would bypass this format path. The caller must
            // retire that configuration before preparing ordinary RGB output.
            if self.read(at(PIPE))? & 0x10 != 0 {
                return Err(Error::Busy);
            }
            self.update(at(PIPE), 1, 1)?;
            self.wait(at(PIPE), 2, 2, 1000).await?;
            for (r, mask, value) in request.segment_registers(plan, segment as u32) {
                self.update(at(r), mask, value)?;
            }
            pending |= self.read(at(PENDING))? & 1 != 0;
        }
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
        for o in timing.request.plan()?.opps() {
            if self.read(self.layout.opp(o, FMT))? & 0x1000000 != 0
                || self.read(self.layout.opp(o, PENDING))? & 1 != 0
                || self.read(self.layout.opp(o, PIPE))? & 0x10 != 0
            {
                return Err(Error::Busy);
            }
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
        if request.pipe >= self.0.layout.pool.count() {
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

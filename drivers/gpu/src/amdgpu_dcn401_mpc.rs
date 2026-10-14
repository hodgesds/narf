//! Native opaque RGB composition preparation. Linux DCN401 uses
//! mpc2_update_blending, mpc3 output denormalization/CSC/OGAM, mpc32 MCM
//! bypass and mpc401 gamut remapping. Route selectors stay disconnected.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcApplied {
    pub dpp: DppApplied,
    pub depth: ColorDepth,
    /// The output CSC compresses to limited range (the blank request's).
    pub limited: bool,
    /// The output CSC converts to BT.709 YCbCr for a 4:2:0 stream (the
    /// blank request's).
    pub ycbcr420: bool,
    /// CURRENT selectors not yet at the request: location, OGAM, OGAM gamut,
    /// shaper, 3D LUT, post-1D LUT, first/second MCM gamut (all bypass) and
    /// output CSC (bypass, or set A when limited or YCbCr).
    /// Timing is stopped; writing a bypass request does not prove its latch.
    pub pending: u16,
}
impl Layout {
    fn mpc_out(self, pipe: u8, r: u64) -> u64 {
        self.mpc_base + (r + u64::from(pipe) * 4) * 4
    }
    fn ogam(self, pipe: u8, r: u64) -> u64 {
        self.mpc_base + (r + u64::from(pipe) * 0x5e) * 4
    }
    fn mcm(self, pipe: u8, r: u64) -> u64 {
        self.mpc_base + (r + u64::from(pipe) * 0xb0) * 4
    }
    fn ocsc(self, pipe: u8) -> u64 {
        self.mpc_base + (0x30b + u64::from(pipe) * 0xd) * 4
    }
    /// The output CSC load of a converting stream, as mpc3_set_ocsc_default
    /// does it: fixed-point S2.13 coefficients (this pipe's
    /// MPC_OUT_CSC_COEF_FORMAT bit clear), set A, then mode A. `m` is a
    /// row of Linux's output_csc_matrix: C11..C14, C21..C24, C31..C34.
    fn ocsc_load(self, pipe: u8, m: [u32; 12]) -> [(u64, u32, u32); 8] {
        let coef = |r: u64| self.ocsc(pipe) + r * 4;
        let pair = |i: usize| m[i] | m[i + 1] << 16;
        [
            (self.mpc_base + 0x30a * 4, 1 << pipe, 0),
            (coef(1), u32::MAX, pair(0)),  // C11, C12
            (coef(2), u32::MAX, pair(2)),  // C13, C14
            (coef(3), u32::MAX, pair(4)),  // C21, C22
            (coef(4), u32::MAX, pair(6)),  // C23, C24
            (coef(5), u32::MAX, pair(8)),  // C31, C32
            (coef(6), u32::MAX, pair(10)), // C33, C34
            (self.ocsc(pipe), 3, 1),
        ]
    }
    /// The output CSC a stream needs: COLOR_SPACE_YCBCR709 for 4:2:0
    /// (YCBCR709_TYPE), COLOR_SPACE_SRGB_LIMITED for limited RGB (each
    /// channel scaled by 0x1B67 plus 0x201), none (bypass) for full RGB.
    fn ocsc_matrix(a: &MpcApplied) -> Option<[u32; 12]> {
        if a.ycbcr420 {
            Some([
                0xe04, 0xf345, 0xfeb7, 0x1004, // Cr
                0x5d3, 0x1399, 0x1fa, 0x201, // Y
                0xfcca, 0xf533, 0xe04, 0x1004, // Cb
            ])
        } else if a.limited {
            Some([
                0x1b67, 0, 0, 0x201, //
                0, 0x1b67, 0, 0x201, //
                0, 0, 0x1b67, 0x201,
            ])
        } else {
            None
        }
    }
    fn mpc_bypass(self, p: u8) -> [(u64, u32); 9] {
        [
            (self.mpcc(p, 9), 0x10),
            (self.ogam(p, 0x7e), 0x180),
            (self.ogam(p, 0xc9), 0x180),
            (self.mcm(p, 0x453), 0xc),
            (self.mcm(p, 0x48a), 0x300),
            (self.mcm(p, 0x493), 0x30),
            (self.mcm(p, 0x4de), 0x180),
            (self.mcm(p, 0x4ec), 0x180),
            (self.ocsc(p), 0x180),
        ]
    }
    /// The composition registers, then for a converting stream the output
    /// CSC load (after the bypass write of its mode, which it replaces).
    fn mpc_rgb(self, a: MpcApplied) -> impl Iterator<Item = (u64, u32, u32)> {
        let p = a.dpp.surface.request.pipe;
        let load = Self::ocsc_matrix(&a).map(|m| self.ocsc_load(p, m));
        let converting = load.is_some();
        self.mpc_full(a)
            .into_iter()
            .filter(move |&(at, _, _)| !(converting && at == self.ocsc(p)))
            .chain(load.into_iter().flatten())
    }
    fn mpc_full(self, a: MpcApplied) -> [(u64, u32, u32); 20] {
        let p = a.dpp.surface.request.pipe;
        let denorm = match a.depth {
            ColorDepth::Bpc8 => 2,
            ColorDepth::Bpc10 => 4,
            ColorDepth::Bpc12 => 6,
        };
        [
            // Top-layer-only, global opaque alpha, unity gains. XRGB's unused
            // byte must never become coverage. Disable inherited stereo too.
            (self.mpcc(p, 3), 0xffff0ff3, 0xffff0422),
            (self.mpcc(p, 4), 0x3033f, 0),
            (self.mpcc(p, 6), 0x7ffff, 0x1f000),
            (self.mpcc(p, 7), 0x7ffff, 0x1f000),
            (self.mpcc(p, 8), 0x7ffff, 0x1f000),
            (self.mpcc(p, 0xa), 0xfff, 0),
            (self.mpcc(p, 0xb), 0xfff, 0),
            (self.mpcc(p, 0xc), 0xfff, 0),
            (self.mpcc(p, 9), 1, 0),
            (self.ogam(p, 0x7e), 3, 0),
            (self.ogam(p, 0xc9), 3, 0),
            (self.mcm(p, 0x453), 3, 0),
            (self.mcm(p, 0x48a), 3, 0),
            (self.mcm(p, 0x493), 3, 0),
            (self.mcm(p, 0x4de), 3, 0),
            (self.mcm(p, 0x4ec), 3, 0),
            (self.ocsc(p), 3, 0),
            // Full 12-bit clamp domain, as Linux leaves it for limited range
            // too. The denormalizer selects the output depth, matching the
            // owned FMT.
            (self.mpc_out(p, 0x2f3), 0x7ffffff, denorm << 24 | 0xfff000),
            (self.mpc_out(p, 0x2f4), 0xffffff, 0xfff000),
            (self.mpc_out(p, 0x2f5), 0xffffff, 0xfff000),
        ]
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn verify_mpc(&mut self, a: MpcApplied) -> Result<u16, Error> {
        for (at, mask, value) in self.layout.mpc_rgb(a) {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        let mut pending = 0;
        for (bit, (at, mask)) in self
            .layout
            .mpc_bypass(a.dpp.surface.request.pipe)
            .into_iter()
            .enumerate()
        {
            let ocsc = at == self.layout.ocsc(a.dpp.surface.request.pipe);
            let converting = Layout::ocsc_matrix(&a).is_some();
            let want = if ocsc && converting { 1 << 7 } else { 0 };
            if self.read(at)? & mask != want {
                pending |= 1 << bit;
            }
        }
        Ok(pending)
    }
}
impl Surfaces {
    pub(super) fn verify_mpc_source<I: Io>(
        &self,
        e: &mut Engine<I>,
        a: MpcApplied,
        (clock, config): (dccg::Applied, DisplayContext),
    ) -> Result<(), Error> {
        let dpp = a.dpp;
        let pipe = dpp.surface.request.pipe;
        let slot = usize::from(pipe);
        let surface = self
            .0
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let blank = e.status.blanks[slot].ok_or(Error::Invalid)?;
        if e.status.surfaces[slot] != Some(surface.applied)
            || e.status.dpps[slot] != Some(dpp)
            || dpp.surface != surface.applied
            || dpp.timing != blank.timing
            || a.depth != blank.request.depth
            || a.limited != blank.request.limited
            || a.ycbcr420 != blank.request.ycbcr420
            || e.blank_timing(blank.request, clock)? != dpp.timing
            || e.status.memory[slot]
                != Some(MemoryApplied {
                    pipe,
                    framebuffer_base: config.fb_base,
                    framebuffer_top: config.fb_top,
                    framebuffer_offset: config.fb_offset,
                    page_table_base: config.root,
                })
        {
            return Err(Error::Invalid);
        }
        e.hubp_tree_stopped(Some(pipe))?;
        e.verify_surface(surface.applied)?;
        e.verify_memory(pipe, config)?;
        e.verify_blank(blank, blank.timing.request.plan()?, false)?;
        e.verify_dpp(dpp)
    }
    pub(in crate::amdgpu_dcn401_otg) fn prepare_mpc<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<MpcApplied, Error> {
        let slot = usize::from(pipe);
        self.0
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        if !e.status.state.reusable() || e.status.mpcs[slot].is_some() {
            return Err(Error::Busy);
        }
        let dpp = e.status.dpps[slot].ok_or(Error::Invalid)?;
        let blank = e.status.blanks[slot].ok_or(Error::Invalid)?;
        let (clock, config) = owners()?;
        let mut a = MpcApplied {
            dpp,
            depth: blank.request.depth,
            limited: blank.request.limited,
            ycbcr420: blank.request.ycbcr420,
            pending: 0,
        };
        self.verify_mpc_source(e, a, (clock, config))?;
        // No RAM or coefficient loads in bypass. Do not disturb LUT power,
        // banks, shared CSC coefficient format or any route selector.
        e.status.state = State::PreparingMpc(pipe);
        e.status.requestor = None;
        e.status.deadlines = None;
        let result = (|| {
            for (at, mask, value) in e.layout.mpc_rgb(a) {
                e.update(at, mask, value)?;
            }
            if owners()? != (clock, config) {
                return Err(Error::Busy);
            }
            self.verify_mpc_source(e, a, (clock, config))?;
            e.verify_mpc(a)
        })();
        match result {
            Ok(pending) => {
                a.pending = pending;
                e.status.mpcs[slot] = Some(a);
                e.status.state = State::MpcPrepared;
                Ok(a)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl Otg {
    /// Prepare opaque full-frame RGB composition while every route is detached.
    /// # Safety
    /// Retain all owners and inherited resources on every outcome. Exclude
    /// firmware/FAMS and concurrent display, hub/VM, clock, reset and power writers.
    pub unsafe fn prepare_mpc(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<MpcApplied, Error> {
        let regs = self.0.io.0;
        let (held, layout) = self.0.held();
        self.1.prepare_mpc(&mut self.0, pipe, || {
            Ok((
                dccg.timing_clock_except(regs, clocks, pipe, &|at| {
                    held_by_sibling(held, layout, at)
                })
                .map_err(Error::PipeClocks)?,
                gmc.display_context(regs).map_err(Error::Memory)?,
            ))
        })
    }
}

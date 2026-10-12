//! Native opaque RGB composition preparation. Linux DCN401 uses
//! mpc2_update_blending, mpc3 output denormalization/CSC/OGAM, mpc32 MCM
//! bypass and mpc401 gamut remapping. Route selectors stay disconnected.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcApplied {
    pub dpp: DppApplied,
    pub depth: ColorDepth,
    /// Historical non-bypass CURRENT selectors: location, OGAM, OGAM gamut,
    /// shaper, 3D LUT, post-1D LUT, first/second MCM gamut and output CSC.
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
    fn mpc_rgb(self, a: MpcApplied) -> [(u64, u32, u32); 20] {
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
            // Full 12-bit clamp domain, no limited-range conversion. The
            // denormalizer selects the output depth, matching the owned FMT.
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
            if self.read(at)? & mask != 0 {
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
        self.1.prepare_mpc(&mut self.0, pipe, || {
            Ok((
                dccg.timing_clock(regs, clocks, pipe)
                    .map_err(Error::PipeClocks)?,
                gmc.display_context(regs).map_err(Error::Memory)?,
            ))
        })
    }
}

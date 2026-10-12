//! DCN401 opaque, unscaled full-frame RGB preparation. Native references:
//! dpp401_dpp_setup, dpp401_dscl_set_scaler_manual_scale, dpp35 FCNV and
//! dpp3 CM programming. MPC remains disconnected; no pixels are fetched.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

const DPP_CLOCK: u64 = 0xcc5;
const RESET: u64 = 0xcc6;
const FORMAT_CONTROL: u64 = 0xcd0;
const DPP_CURSOR: u64 = 0xcf1;
const SCALER_PENDING: u64 = 0xd18;
const SCALER_POWER: u64 = 0xd24;
const SCALER_STATUS: u64 = 0xd25;
const ISHARP_POWER: u64 = 0xd62;
const CM_CONTROL: u64 = 0xd67;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DppApplied {
    pub surface: SurfaceApplied,
    pub timing: Applied,
    /// Native RGB line-buffer allocation, chosen for at least two unity-scale rows.
    pub line_buffer_config: u8,
    /// CNVC, scaler and CM pending bits, respectively. Timing is stopped, so
    /// staged programming may remain pending; zero is not presentation evidence.
    pub pending: u8,
}
impl Layout {
    fn dpp(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x16b) * 4
    }
}
// Native dscl401_calc_lb_num_partitions and dpp401_dscl_is_lb_conf_valid:
// RGB unity uses ceil(width/6) entries per row and one vertical tap; that
// needs at least two partitions. No per-pixel alpha, chroma or scaling.
fn line_buffer(width: u32) -> Result<u8, Error> {
    if width == 0 {
        return Err(Error::Invalid);
    }
    let row = width.div_ceil(6);
    for (config, entries) in [(1, 970), (2, 1290), (0, 3430)] {
        if entries / row >= 2 {
            return Ok(config);
        }
    }
    Err(Error::Unsupported)
}
fn registers(a: DppApplied) -> [(u64, u32, u32); 29] {
    let dimensions = a.surface.request.width | a.surface.request.height << 16;
    [
        (FORMAT_CONTROL, 0x3f033111, 0x24000101), // RGB crossbar; EXPANSION_MODE_ZERO = 1
        (0xccf, 0x17f, 8),                        // RGB8888, no separate alpha plane
        (0xcd7, 0x33, 0),                         // color/luma keying disabled
        (0xcde, 0x11, 0),
        (0xcee, 0x11, 0), // pre de/re-alpha off
        (0xced, 0x73, 0), // pre-degamma bypass (encoded RGB passes through)
        (0xcd1, 0x7ffff, 0),
        (0xcd2, 0x7ffff, 0),
        (0xcd3, 0x7ffff, 0),
        (0xcd4, 0x7ffff, 0x1f000),
        (0xcd5, 0x7ffff, 0x1f000),
        (0xcd6, 0x7ffff, 0x1f000),
        (CM_CONTROL, 1, 0),
        (0xd68, 3, 0),   // post CSC bypass
        (0xd77, 0xf, 0), // gamma correction bypass
        (0xdc5, 3, 0),   // CM de-alpha off
        (0xd75, 0xffff, 0),
        (0xd76, u32::MAX, 0),
        (0xdc1, 0x7ffff, 0x1f000), // unity HDR multiplier
        (0xd19, 0x3303, 0),        // no automatic scaling/centering/replication
        (0xd0a, 1, 0),             // native boundary mode
        (0xd1e, 0x3fff3fff, 0),    // full-frame origin
        (0xd1f, 0x3fff3fff, dimensions),
        (0xd20, 0x3fff3fff, dimensions),
        (0xd08, 7, 0),    // native SCALING_444_BYPASS, not full DSCL bypass (6)
        (0xd21, 0x11, 0), // float line buffer, no interleave or per-pixel alpha
        (0xd22, 0x3f03, 0x3f00 | u32::from(a.line_buffer_config)),
        (0xd28, 1, 0),
        (0xd29, 1, 0), // no adaptive filtering
    ]
}
impl<I: Io> Engine<I> {
    fn dpp_stopped(&mut self, pipe: u8, clocked: bool) -> Result<(), Error> {
        if !self.hubp_powered(pipe)? {
            return Err(Error::Busy);
        }
        let l = self.layout;
        for (r, mask, value) in [
            (DPP_CLOCK, 0x70000010, u32::from(clocked) << 4),
            (RESET, 0x1111, 0),
            (DPP_CURSOR, 0x10001, 0),
            // Native DSCL code manages LUT power, while LB groups use hardware
            // policy. Reject inherited forced/manual LB gating rather than
            // silently replacing that independent policy.
            (SCALER_POWER, 0x13333330, 0),
        ] {
            if self.read(l.dpp(pipe, r))? & mask != value {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn dpp_pending(&mut self, pipe: u8) -> Result<u8, Error> {
        let mut pending = 0;
        for (bit, (r, mask)) in [
            (FORMAT_CONTROL, 0x100000),
            (SCALER_PENDING, 1),
            (CM_CONTROL, 0x100),
        ]
        .into_iter()
        .enumerate()
        {
            if self.read(self.layout.dpp(pipe, r))? & mask != 0 {
                pending |= 1 << bit;
            }
        }
        Ok(pending)
    }
    async fn program_dpp(&mut self, applied: DppApplied) -> Result<(), Error> {
        let p = applied.surface.request.pipe;
        let l = self.layout;
        self.update(l.dpp(p, DPP_CLOCK), 0x10, 0x10)?;
        // Wake native scaler LUT and iSHARP RAM before their programming,
        // even though this restricted path bypasses both filtering features.
        self.update(l.dpp(p, SCALER_POWER), 7, 4)?;
        self.wait(l.dpp(p, SCALER_STATUS), 3, 0, 1000).await?;
        self.hubp_tree_stopped(Some(p))?;
        self.dpp_stopped(p, true)?;
        self.update(l.dpp(p, ISHARP_POWER), 7, 4)?;
        self.wait(l.dpp(p, ISHARP_POWER), 0x30, 0, 1000).await?;
        self.hubp_tree_stopped(Some(p))?;
        self.dpp_stopped(p, true)?;
        for (r, mask, value) in registers(applied) {
            self.update(l.dpp(p, r), mask, value)?;
        }
        // Native iSHARP off: leave LUT bank selection alone; no coefficient RAM
        // writes or toggles are needed in unity scaling mode.
        self.update(l.dpp(p, 0xd55), 0x0ffffa71, 0)?;
        self.update(l.dpp(p, DPP_CLOCK), 0x10, 0)?;
        Ok(())
    }
    fn verify_dpp(&mut self, applied: DppApplied) -> Result<(), Error> {
        let p = applied.surface.request.pipe;
        self.dpp_stopped(p, false)?;
        for (r, mask, value) in registers(applied).into_iter().chain([
            (SCALER_POWER, 7, 4),
            (SCALER_STATUS, 3, 0),
            (ISHARP_POWER, 0x37, 4),
            (0xd55, 0x0ffffa71, 0),
        ]) {
            let at = self.layout.dpp(p, r);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
}
impl Surfaces {
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_dpp<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<DppApplied, Error> {
        let slot = usize::from(pipe);
        let surface = self
            .0
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        if !e.status.state.reusable()
            || e.status.dpps[slot].is_some()
            || e.status.surfaces[slot] != Some(surface.applied)
        {
            return Err(Error::Busy);
        }
        let blank = e.status.blanks[slot].ok_or(Error::Invalid)?;
        let (clock, config) = owners()?;
        if e.blank_timing(blank.request, clock)? != blank.timing
            || surface.applied.request.width != blank.timing.request.timing.h_active
            || surface.applied.request.height != blank.timing.request.timing.v_active
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
        let plan = blank.timing.request.plan()?;
        let mut applied = DppApplied {
            surface: surface.applied,
            timing: blank.timing,
            line_buffer_config: line_buffer(surface.applied.request.width)?,
            pending: 0,
        };
        e.hubp_tree_stopped(Some(pipe))?;
        e.verify_surface(surface.applied)?;
        e.verify_memory(pipe, config)?;
        e.verify_blank(blank, plan, false)?;
        e.dpp_stopped(pipe, false)?;
        if e.dpp_pending(pipe)? != 0 {
            return Err(Error::Busy);
        }
        e.status.state = State::PreparingDpp(pipe);
        let result = e.program_dpp(applied).await.and_then(|()| {
            if owners()? != (clock, config) {
                return Err(Error::Busy);
            }
            e.hubp_tree_stopped(Some(pipe))?;
            e.verify_surface(surface.applied)?;
            e.verify_memory(pipe, config)?;
            e.verify_blank(blank, plan, false)?;
            e.verify_dpp(applied)?;
            e.dpp_pending(pipe)
        });
        match result {
            Ok(pending) => {
                applied.pending = pending;
                e.status.dpps[slot] = Some(applied);
                e.status.state = State::DppPrepared;
                Ok(applied)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl Otg {
    /// Stage native unscaled RGB conversion and line-buffer setup for a retained
    /// full-frame surface. Fetch, MPC and timing remain stopped.
    /// # Safety
    /// Retain all owners and inherited resources on every outcome. Exclude
    /// firmware/FAMS and concurrent display, hub/VM, clock, reset and power writers.
    pub async unsafe fn prepare_dpp(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<DppApplied, Error> {
        let regs = self.0.io.0;
        self.1
            .prepare_dpp(&mut self.0, pipe, || {
                Ok((
                    dccg.timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}

#[cfg(feature = "kernel-test")]
fn dcn401_dpp_line_buffer_capacity_boundaries() -> narf_kernel_test::TestResult {
    for (width, want) in [
        (1, 1),
        (2910, 1),
        (2911, 2),
        (3870, 2),
        (3871, 0),
        (7680, 0),
        (10290, 0),
    ] {
        assert_eq!(line_buffer(width), Ok(want));
    }
    assert_eq!(line_buffer(0), Err(Error::Invalid));
    for width in [10291, 16383, u32::MAX] {
        assert_eq!(line_buffer(width), Err(Error::Unsupported));
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_line_buffer_capacity_boundaries
);

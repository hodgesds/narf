//! DCN3.0 non-FAMS dynamic refresh: optc1_set_drr,
//! optc2_setup_manual_trigger and optc1_set_static_screen_control.
//! LFC (BTR) follows the DCN401 apply (`amdgpu_dcn401_drr::set_lfc` /
//! `lfc_progress` / `lfc_preflip`) on the same MIN/MAX totals, with the
//! frame count read from DCN30's OTG_STATUS_FRAME_COUNT
//! (`amdgpu_dcn30_flip`, 0x1b4c) instead of DCN401's OTG_FRAME_COUNT.
use super::*;
use crate::amdgpu_dcn30_flip::{FRAME_MASK, OTG_STATUS_FRAME_COUNT};
use crate::amdgpu_freesync::{Drr, Lfc, LfcConfig};

// linux-ctx: hdr=dcn seg=2
const V_TOTAL_MID: u64 = 0x1b32; // linux: mmOTG0_OTG_V_TOTAL_MID
const V_TOTAL_CONTROL: u64 = 0x1b33; // linux: mmOTG0_OTG_V_TOTAL_CONTROL
const TRIGA_CONTROL: u64 = 0x1b39; // linux: mmOTG0_OTG_TRIGA_CNTL
                                   // linux: mmOTG0_OTG_STATIC_SCREEN_CONTROL
const STATIC_SCREEN_CONTROL: u64 = 0x1b82;
// linux-ctx: reset
/// All writable DRR selection/MID fields; preserve active-period status.
const DRR_FIELDS: u32 = 0xffff_ff9f;
/// Writable static-screen fields, excluding status and interrupt-clear.
const STATIC_FIELDS: u32 = 0xd1ff_ffff;
const DRR_TRIGA: u32 = 3 | 2 << 16;
const STATIC_TRIGA: u32 = 0x0002_0800;

#[derive(Clone, Copy, Debug)]
pub(super) struct Applied {
    bounds: Drr,
    static_screen: u32,
    /// The totals actually programmed now: the admitted `bounds`, or the
    /// single total BTR repeats while it inserts frames (DCN401's `adjust`).
    adjust: Drr,
    lfc: Option<LfcRuntime>,
}

/// BTR state on a DCN30 stream (DCN401's `LfcRuntime`): the LFC math, the
/// frame count it last observed, and the last flip's monotonic time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LfcRuntime {
    math: Lfc,
    frame: u32,
    last_flip_us: Option<u32>,
}

impl<I: Io> Engine<I> {
    /// Retire a firmware variable-refresh context before starting a new
    /// fixed-rate mode. Equal MIN/MAX alone does not retire MID/event state.
    pub(super) fn reset_dcn30_drr(&mut self) -> Result<(), Error> {
        if self.profile.is_dcn30() {
            self.update(self.otg(V_TOTAL_CONTROL), DRR_FIELDS, 0)?;
            self.set(self.otg(V_TOTAL_MID), 0)?;
            self.set(self.otg(TRIGA_CONTROL), 0)?;
            self.update(self.otg(STATIC_SCREEN_CONTROL), STATIC_FIELDS, 0)?;
        }
        self.drr = None;
        self.drr_dirty = false;
        Ok(())
    }

    pub(super) fn configure_dcn30_drr(
        &mut self,
        requested: Option<Drr>,
    ) -> Result<Option<Drr>, Error> {
        if !self.profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        if self.state != State::Running || self.drr_dirty {
            return Err(Error::Busy);
        }
        let timing = self.timing.ok_or(Error::Invalid)?;
        if requested.is_some_and(|d| {
            d.v_total_min < timing.v_total
                || d.v_total_min > d.v_total_max
                || d.v_total_max > crate::amdgpu_freesync::MAX_V_TOTAL
        }) {
            return Err(Error::Invalid);
        }
        if self.drr.map(|d| d.bounds) == requested {
            return Ok(requested);
        }
        let static_reg = self.otg(STATIC_SCREEN_CONTROL);
        let saved = match self.drr {
            Some(d) => d.static_screen,
            None => {
                let value = self.access(|io| io.read(static_reg))?;
                if value == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                value
            }
        };
        // Any partial failure requires normal owner teardown before reuse.
        self.drr_dirty = true;
        let bounds = requested.unwrap_or(Drr {
            v_total_min: timing.v_total,
            v_total_max: timing.v_total,
        });
        // optc1_set_vtotal_min_max: MAX first, then MIN, both minus one.
        self.set(self.otg(OTG_V_TOTAL_MAX), bounds.v_total_max - 1)?;
        self.set(self.otg(OTG_V_TOTAL_MIN), bounds.v_total_min - 1)?;
        self.set(self.otg(V_TOTAL_MID), 0)?;
        self.update(
            self.otg(V_TOTAL_CONTROL),
            DRR_FIELDS,
            if requested.is_some() { DRR_TRIGA } else { 0 },
        )?;
        // TRIGA source 21, this pipe, rising edge, clear inherited trigger.
        let trigger = if requested.is_some() {
            21 | u32::from(self.instance) << 5 | 1 << 16 | 1 << 31
        } else {
            0
        };
        self.set(self.otg(TRIGA_CONTROL), trigger)?;
        self.update(
            static_reg,
            STATIC_FIELDS,
            if requested.is_some() {
                STATIC_TRIGA
            } else {
                saved
            },
        )?;
        self.drr = requested.map(|bounds| Applied {
            bounds,
            static_screen: saved,
            // New bounds retire any admitted BTR: it was admitted for the
            // old range and must be re-admitted for these totals.
            adjust: bounds,
            lfc: None,
        });
        self.drr_dirty = false;
        Ok(requested)
    }

    /// Write only the MIN/MAX totals of an admitted DRR range (the
    /// selectors and static-screen routing stay as `configure_dcn30_drr`
    /// programmed them). A failure after a hardware write marks the DRR
    /// dirty, so the owner tears it down before another request.
    fn dcn30_drr_adjust(&mut self, next: Drr) -> Result<(), Error> {
        let Some(mut applied) = self.drr else {
            return Err(Error::Invalid);
        };
        if applied.adjust == next {
            return Ok(());
        }
        applied.adjust = next;
        self.drr = Some(applied);
        let result = (|| {
            // optc1_set_vtotal_min_max: MAX first, then MIN, both minus one.
            self.set(self.otg(OTG_V_TOTAL_MAX), next.v_total_max - 1)?;
            self.set(self.otg(OTG_V_TOTAL_MIN), next.v_total_min - 1)
        })();
        if result.is_err() {
            self.drr_dirty = true;
        }
        result
    }

    /// Read back the programmed MIN/MAX totals and the DRR selectors
    /// against an admitted range. A mismatch is `Invalid`, as for the
    /// readback in `update`.
    fn dcn30_verify_adjust(&mut self) -> Result<(), Error> {
        let Some(applied) = self.drr else {
            return Ok(());
        };
        let at_max = self.otg(OTG_V_TOTAL_MAX);
        let at_min = self.otg(OTG_V_TOTAL_MIN);
        let at_control = self.otg(V_TOTAL_CONTROL);
        let (max, min, control) =
            self.access(|io| (io.read(at_max), io.read(at_min), io.read(at_control)))?;
        if max == u32::MAX || min == u32::MAX || control == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if max & 0x7fff != applied.adjust.v_total_max - 1
            || min & 0x7fff != applied.adjust.v_total_min - 1
            || control & DRR_FIELDS != DRR_TRIGA
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn dcn30_frame(&mut self) -> Result<u32, Error> {
        let at = self.otg(OTG_STATUS_FRAME_COUNT);
        let value = self.access(|io| io.read(at))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value & FRAME_MASK)
    }

    /// Whether BTR frame insertion is admitted on the running stream.
    pub(super) fn dcn30_lfc_active(&self) -> bool {
        self.drr.is_some_and(|a| a.lfc.is_some())
    }

    /// Admit (`Some`) or retire (`None`) BTR frame insertion on an
    /// admitted variable-refresh stream (DCN401's `set_lfc`). The config
    /// must be for this timing and these admitted bounds; a config for
    /// other totals is refused without writes. Retiring restores the
    /// admitted variable range. A reconfigure of the DRR bounds retires
    /// BTR first (see `configure_dcn30_drr`).
    pub(super) fn configure_dcn30_lfc(&mut self, config: Option<LfcConfig>) -> Result<(), Error> {
        if !self.profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        if self.state != State::Running || self.drr_dirty {
            return Err(Error::Busy);
        }
        let timing = self.timing.ok_or(Error::Invalid)?;
        let Some(mut applied) = self.drr else {
            return if config.is_none() {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        };
        if config.is_some_and(|c| c.timing() != timing || c.base() != applied.bounds) {
            return Err(Error::Invalid);
        }
        if applied.lfc.map(|r| r.math.config) == config {
            return Ok(());
        }
        self.dcn30_verify_adjust()?;
        let frame = self.dcn30_frame()?;
        applied.lfc = config.map(|c| LfcRuntime {
            math: Lfc::new(c),
            frame,
            last_flip_us: None,
        });
        self.drr = Some(applied);
        // Retiring BTR restores the admitted range at once; admitting it
        // leaves the admitted totals programmed.
        self.dcn30_drr_adjust(applied.bounds)
    }

    /// Service one observed VUPDATE while BTR is admitted (DCN401's
    /// `lfc_progress`): a single frame transition runs the LFC state
    /// machine (`hdmi` selects its HDMI ceiling / DP floor); no transition
    /// is a no-op, and a missed transition discards the BTR cycle and
    /// restores the admitted variable range, as replaying unknown frame
    /// history could shorten the wrong frame.
    pub(super) fn dcn30_lfc_progress(&mut self, hdmi: bool) -> Result<(), Error> {
        if self.state != State::Running {
            return Ok(());
        }
        let Some(mut applied) = self.drr.filter(|a| a.lfc.is_some()) else {
            return Ok(());
        };
        let result = (|| {
            self.dcn30_verify_adjust()?;
            let mut runtime = applied.lfc.unwrap();
            let frame = self.dcn30_frame()?;
            let delta = frame.wrapping_sub(runtime.frame) & FRAME_MASK;
            if delta == 0 {
                return Ok(());
            }
            runtime.frame = frame;
            let next = if delta != 1 {
                runtime.math.reset();
                runtime.last_flip_us = None;
                Some(applied.bounds)
            } else {
                runtime.math.vupdate(hdmi)
            };
            applied.lfc = Some(runtime);
            self.drr = Some(applied);
            self.dcn30_drr_adjust(next.unwrap_or(applied.adjust))
        })();
        if result.is_err() {
            self.drr_dirty = true;
        }
        result
    }

    /// Discard a BTR cycle after a lost frame wait and re-snapshot the
    /// frame count (DCN401's `lfc_resync`): the admitted range resumes.
    pub(super) fn dcn30_lfc_resync(&mut self) -> Result<(), Error> {
        if self.state != State::Running {
            return Err(Error::Busy);
        }
        let Some(mut applied) = self.drr.filter(|a| a.lfc.is_some()) else {
            return Ok(());
        };
        let result = (|| {
            self.dcn30_verify_adjust()?;
            let mut runtime = applied.lfc.unwrap();
            runtime.math.reset();
            runtime.last_flip_us = None;
            runtime.frame = self.dcn30_frame()?;
            applied.lfc = Some(runtime);
            self.drr = Some(applied);
            self.dcn30_drr_adjust(applied.bounds)
        })();
        if result.is_err() {
            self.drr_dirty = true;
        }
        result
    }

    /// Immediately before a flip, with the same owner and retained
    /// surfaces (DCN401's `lfc_preflip`): service any VUPDATE since the
    /// last call, then feed the render cadence (`now_us` monotonic) to
    /// the BTR state machine. A returned range applies at once; entering
    /// or changing BTR waits for the next VUPDATE, as Linux. No-op
    /// without admitted BTR.
    pub(super) fn dcn30_lfc_preflip(&mut self, now_us: u32, hdmi: bool) -> Result<(), Error> {
        if self.state != State::Running {
            return Ok(());
        }
        self.dcn30_lfc_progress(hdmi)?;
        let Some(mut applied) = self.drr.filter(|a| a.lfc.is_some()) else {
            return Ok(());
        };
        let mut runtime = applied.lfc.unwrap();
        let next = runtime
            .last_flip_us
            .and_then(|last| runtime.math.preflip(now_us.wrapping_sub(last)));
        runtime.last_flip_us = Some(now_us);
        applied.lfc = Some(runtime);
        self.drr = Some(applied);
        let result = self.dcn30_drr_adjust(next.unwrap_or(applied.adjust));
        if result.is_err() {
            self.drr_dirty = true;
        }
        result
    }
}

impl Otg {
    /// Change the bounds on an owned running DCN3.0 generator. Fixed refresh
    /// restores nominal totals and the previous static-screen control. An
    /// error after a hardware write requires teardown before another request.
    pub fn configure_dcn30_drr(&mut self, requested: Option<Drr>) -> Result<Option<Drr>, Error> {
        self.0.configure_dcn30_drr(requested)
    }

    /// Whether BTR frame insertion is admitted on this generator.
    pub fn dcn30_lfc_active(&self) -> bool {
        self.0.dcn30_lfc_active()
    }

    /// Admit (`Some`) or retire (`None`) BTR frame insertion on an admitted
    /// variable-refresh stream. The config must be for this timing and these
    /// admitted bounds; retiring restores the admitted variable range.
    pub fn configure_dcn30_lfc(
        &mut self,
        config: Option<crate::amdgpu_freesync::LfcConfig>,
    ) -> Result<(), Error> {
        self.0.configure_dcn30_lfc(config)
    }

    /// Service one observed VUPDATE while BTR is admitted. No-op without
    /// admitted BTR or while the generator is not running.
    pub fn dcn30_lfc_progress(&mut self, hdmi: bool) -> Result<(), Error> {
        self.0.dcn30_lfc_progress(hdmi)
    }

    /// Discard a BTR cycle after a lost frame wait and re-snapshot the
    /// frame count. No-op without admitted BTR.
    pub fn dcn30_lfc_resync(&mut self) -> Result<(), Error> {
        self.0.dcn30_lfc_resync()
    }

    /// Immediately before a flip: service any VUPDATE since the last call,
    /// then feed the render cadence (`now_us` monotonic) to the BTR state
    /// machine. No-op without admitted BTR or while not running.
    pub fn dcn30_lfc_preflip(&mut self, now_us: u32, hdmi: bool) -> Result<(), Error> {
        self.0.dcn30_lfc_preflip(now_us, hdmi)
    }
}

//! DCN3.0 non-FAMS dynamic refresh: optc1_set_drr,
//! optc2_setup_manual_trigger and optc1_set_static_screen_control.
use super::*;
use crate::amdgpu_freesync::Drr;

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
        });
        self.drr_dirty = false;
        Ok(requested)
    }
}

impl Otg {
    /// Change the bounds on an owned running DCN3.0 generator. Fixed refresh
    /// restores nominal totals and the previous static-screen control. An
    /// error after a hardware write requires teardown before another request.
    pub fn configure_dcn30_drr(&mut self, requested: Option<Drr>) -> Result<Option<Drr>, Error> {
        self.0.configure_dcn30_drr(requested)
    }
}

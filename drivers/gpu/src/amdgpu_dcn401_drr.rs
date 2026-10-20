//! Native DCN401 dynamic refresh (DRR) on a live scanout's timing generator.
//! Linux: dcn10_set_drr -> optc401_set_drr (the non-FAMS branch, since this
//! owner excludes DMUB FAMS) -> optc1_set_vtotal_min_max and
//! optc401_setup_manual_trigger, then optc1_set_static_screen_control with
//! the TRIGA event; flips fire optc2_program_manual_trigger after the
//! address update is unlocked (commit_planes_for_stream), so a stretched
//! vertical blank ends at the flip. V_TOTAL_MID, BTR/LFC frame insertion and
//! the FreeSync infopacket are not implemented.
use super::*;

const V_TOTAL_MAX: u64 = 0x1b31;
/// OTG_V_TOTAL_CONTROL: V_TOTAL_MIN_SEL, V_TOTAL_MAX_SEL,
/// FORCE_LOCK_ON_EVENT and SET_V_TOTAL_MIN_MASK.
const DRR_FIELDS: u32 = 0xffff_0013;
/// MIN_SEL = MAX_SEL = 1, FORCE_LOCK_ON_EVENT = 0, the TRIGA event (bit 1)
/// in SET_V_TOTAL_MIN_MASK (optc401_setup_manual_trigger).
const DRR_TRIGA: u32 = 0x0002_0003;
/// OTG_TRIGA_MANUAL_TRIG: a write strobe, never read back.
const TRIGA_MANUAL_TRIG: u64 = 0x1b3c;
/// OTG_STATIC_SCREEN_CONTROL's writable fields: event mask, frame count,
/// CPU interrupt enable and type, override and override value (the status
/// bits and the interrupt-clear strobe excluded).
const STATIC_SCREEN: u64 = 0x1b80;
const STATIC_SCREEN_FIELDS: u32 = 0xd1ff_ffff;
/// dcn10_set_drr's event_triggers 0x800 (OTG_TRIG_A) and num_frames 2.
const STATIC_SCREEN_TRIGA: u32 = 0x0002_0800;

/// Live DRR on one pipe's timing: the totals it stretches between and the
/// static-screen control it replaced, restored on return to fixed refresh.
/// Historical programming, not proof that a frame was stretched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrrApplied {
    pub pipe: u8,
    pub drr: crate::amdgpu_freesync::Drr,
    static_screen: u32,
}

#[cfg(feature = "kernel-test")]
impl DrrApplied {
    pub(in crate::amdgpu_dcn401_otg) fn for_test(
        pipe: u8,
        drr: crate::amdgpu_freesync::Drr,
    ) -> Self {
        Self {
            pipe,
            drr,
            static_screen: 0,
        }
    }
}

impl<I: Io> Engine<I> {
    /// The live scanout's prepared timing, if `pipe` scans out.
    fn drr_timing(&self, pipe: u8) -> Result<Timing, Error> {
        let running = self.status.scanout.ok_or(Error::Busy)?;
        if self.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let applied = self
            .status
            .pipes
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?;
        Ok(applied.request.timing)
    }
    /// optc401_set_drr with nonzero totals (programmed minus one): maximum
    /// then minimum (optc1_set_vtotal_min_max), the TRIGA selectors, then
    /// the static-screen TRIGA event. Totals below the mode's, inverted or
    /// beyond the 15-bit field are refused before any write, as is a pipe
    /// that does not scan out.
    pub(in crate::amdgpu_dcn401_otg) fn set_drr(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<Option<DrrApplied>, Error> {
        let timing = self.drr_timing(pipe)?;
        let Some(d) = drr else {
            return match self.drr_fixed(pipe) {
                Ok(()) => Ok(None),
                Err(e) => {
                    self.status.state = State::Failed(e);
                    Err(e)
                }
            };
        };
        if d.v_total_min < timing.v_total
            || d.v_total_max < d.v_total_min
            || d.v_total_max > crate::amdgpu_freesync::MAX_V_TOTAL
        {
            return Err(Error::Invalid);
        }
        let current = self.status.drr.filter(|a| a.pipe == pipe);
        if current.is_some_and(|a| a.drr == d) {
            return Ok(current);
        }
        let l = self.layout;
        let otg = |r| l.otg(pipe, r);
        let static_screen = match current {
            Some(a) => a.static_screen,
            None => self.read(otg(STATIC_SCREEN))? & STATIC_SCREEN_FIELDS,
        };
        let applied = DrrApplied {
            pipe,
            drr: d,
            static_screen,
        };
        // Recorded first: a partial failure still restores fixed refresh.
        self.status.drr = Some(applied);
        let result = (|| {
            self.update(otg(V_TOTAL_MAX), 0x7fff, d.v_total_max - 1)?;
            self.update(otg(V_MIN), 0x7fff, d.v_total_min - 1)?;
            self.update(otg(V_CONTROL), DRR_FIELDS, DRR_TRIGA)?;
            self.update(
                otg(STATIC_SCREEN),
                STATIC_SCREEN_FIELDS,
                STATIC_SCREEN_TRIGA,
            )
        })();
        match result {
            Ok(()) => Ok(Some(applied)),
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Back to the fixed refresh `program` set, if `pipe` runs DRR: the
    /// selectors cleared first (optc401_set_drr's disable branch), then
    /// V_TOTAL_MAX/MIN equal to V_TOTAL again (Linux writes zero, unused
    /// once the selectors are clear) and the replaced static-screen control.
    pub(in crate::amdgpu_dcn401_otg) fn drr_fixed(&mut self, pipe: u8) -> Result<(), Error> {
        let Some(a) = self.status.drr.filter(|a| a.pipe == pipe) else {
            return Ok(());
        };
        let total = self
            .status
            .pipes
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?
            .request
            .timing
            .v_total;
        let l = self.layout;
        let otg = |r| l.otg(pipe, r);
        self.update(otg(V_CONTROL), DRR_FIELDS, 0)?;
        self.update(otg(V_TOTAL_MAX), 0x7fff, total - 1)?;
        self.update(otg(V_MIN), 0x7fff, total - 1)?;
        self.update(otg(STATIC_SCREEN), STATIC_SCREEN_FIELDS, a.static_screen)?;
        self.status.drr = None;
        Ok(())
    }
    /// optc2_program_manual_trigger after a flip's address update was
    /// unlocked, only while DRR runs on `pipe`: the extended blank ends at
    /// the flip instead of the maximum total.
    pub(in crate::amdgpu_dcn401_otg) fn drr_trigger(&mut self, pipe: u8) -> Result<(), Error> {
        if self.status.drr.is_none_or(|a| a.pipe != pipe) {
            return Ok(());
        }
        let at = self.layout.otg(pipe, TRIGA_MANUAL_TRIG);
        self.access(|io| {
            io.write(at, 1);
            Ok(())
        })
    }
    /// A frame wait's bound on `pipe`: the nominal one, or under DRR three
    /// frames at the maximum total plus 5 ms, as `BlankApplied::timeout_us`
    /// bounds nominal frames.
    pub(in crate::amdgpu_dcn401_otg) fn frame_timeout_us(
        &self,
        pipe: u8,
        blank: BlankApplied,
    ) -> Result<u64, Error> {
        let nominal = blank.timeout_us()?;
        let Some(a) = self.status.drr.filter(|a| a.pipe == pipe) else {
            return Ok(nominal);
        };
        let t = blank.timing.request.timing;
        let frame_us = (u64::from(t.h_total) * u64::from(a.drr.v_total_max) * 1000)
            .div_ceil(u64::from(t.pixel_clock_khz));
        let timeout = frame_us * 3 + 5000;
        if timeout > 1_000_000 {
            return Err(Error::Invalid);
        }
        Ok(timeout.max(nominal))
    }
}

impl Otg {
    /// Stretch (`Some`) or fix (`None`) the vertical total of display
    /// `pipe`'s live scanout. `Busy` unless the pipe is `ScanoutRunning`;
    /// totals outside [mode total, 32767] are `Invalid` without writes. A
    /// register failure leaves `Failed` with the record retained, so the
    /// next stop still restores fixed refresh. Leaving scanout (stopping or
    /// recovering fetch) or the timing returns to fixed refresh first.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent timing writers.
    pub unsafe fn set_drr(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<Option<DrrApplied>, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        self.0.set_drr(pipe, drr)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_drr_tests.rs"]
mod tests;

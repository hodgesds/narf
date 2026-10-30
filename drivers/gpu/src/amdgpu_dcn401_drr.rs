//! Native DCN401 dynamic refresh (DRR) on a live scanout's timing generator.
//! Linux: dcn10_set_drr -> optc401_set_drr (the non-FAMS branch, since this
//! owner excludes DMUB FAMS) -> optc1_set_vtotal_min_max and
//! optc401_setup_manual_trigger, then optc1_set_static_screen_control with
//! the TRIGA event; flips fire optc2_program_manual_trigger after the
//! address update is unlocked (commit_planes_for_stream), so a stretched
//! vertical blank ends at the flip. BTR follows real observed frame updates;
//! MID has its own retained, bounded hardware sequence. FreeSync SPD has a
//! retained publication owner.
use super::*;

const V_TOTAL_MAX: u64 = 0x1b31;
const V_TOTAL_MID: u64 = 0x1b32;
const FRAME_COUNT: u64 = 0x1b4d;
const FRAME_MASK: u32 = 0xff_ffff;
/// OTG_V_TOTAL_CONTROL: V_TOTAL_MIN_SEL, V_TOTAL_MAX_SEL,
/// FORCE_LOCK_ON_EVENT and SET_V_TOTAL_MIN_MASK.
pub(super) const DRR_FIELDS: u32 = 0xffff_ff1f;
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
    /// Actual current MIN/MAX, which BTR temporarily fixes to one total.
    pub adjust: crate::amdgpu_freesync::Drr,
    pub mid: Option<DrrMid>,
    lfc: Option<LfcRuntime>,
}

/// DCN401's finite MID-for-MAX sequence. This is a hardware timing
/// operation, independent of Linux BTR's MIN/MAX frame-insertion policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrrMid {
    pub v_total: u32,
    pub frames: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LfcRuntime {
    math: crate::amdgpu_freesync::Lfc,
    frame: u32,
    last_flip_us: Option<u32>,
}

impl DrrApplied {
    pub fn lfc_enabled(self) -> bool {
        self.lfc.is_some()
    }
    pub fn lfc(self) -> Option<crate::amdgpu_freesync::Lfc> {
        self.lfc.map(|r| r.math)
    }
    pub(super) fn control(self) -> u32 {
        DRR_TRIGA | self.mid.map_or(0, |m| 4 | u32::from(m.frames) << 8)
    }
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
            adjust: drr,
            mid: None,
            lfc: None,
        }
    }
}

impl<I: Io> Engine<I> {
    /// The live scanout's prepared timing, if `pipe` scans out.
    pub(super) fn drr_timing(&self, pipe: u8) -> Result<Timing, Error> {
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
            adjust: d,
            mid: None,
            lfc: None,
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
    /// Native configuration waits for source retirement before changing a
    /// range (which resets BTR), or returning to fixed timing. A dropped
    /// source wait remains an owned stream transaction, never idle scanout.
    pub(super) async fn configure_drr(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<Option<DrrApplied>, Error> {
        let timing = self.drr_timing(pipe)?;
        if drr.is_some_and(|d| {
            d.v_total_min < timing.v_total
                || d.v_total_max < d.v_total_min
                || d.v_total_max > crate::amdgpu_freesync::MAX_V_TOTAL
        }) {
            return Err(Error::Invalid);
        }
        if self.status.drr.filter(|a| a.pipe == pipe).map(|a| a.drr) != drr {
            self.status.state = State::UpdatingStream(pipe);
            if let Err(e) = self.io.vupdate(pipe, false).await {
                self.status.state = State::Failed(e);
                return Err(e);
            }
            self.status.state = State::ScanoutRunning(pipe);
        }
        self.set_drr(pipe, drr)
    }
    pub(super) async fn configure_lfc(
        &mut self,
        pipe: u8,
        config: Option<crate::amdgpu_freesync::LfcConfig>,
    ) -> Result<(), Error> {
        self.drr_timing(pipe)?;
        if config.is_some() {
            self.set_lfc(pipe, config)?;
        }
        self.status.state = State::UpdatingStream(pipe);
        if let Err(e) = self.io.vupdate(pipe, config.is_some()).await {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        self.status.state = State::ScanoutRunning(pipe);
        if config.is_none() {
            self.set_lfc(pipe, None)?;
        }
        Ok(())
    }
    /// Back to the fixed refresh `program` set, if `pipe` runs DRR: the
    /// selectors cleared first (optc401_set_drr's disable branch), then
    /// V_TOTAL_MAX/MIN equal to V_TOTAL again (Linux writes zero, unused
    /// once the selectors are clear) and the replaced static-screen control.
    pub(in crate::amdgpu_dcn401_otg) fn drr_fixed(&mut self, pipe: u8) -> Result<(), Error> {
        self.freesync_off(pipe)?;
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
        if a.mid.is_some() {
            self.update(otg(V_TOTAL_MID), 0x7fff, 0)?;
        }
        self.update(otg(V_TOTAL_MAX), 0x7fff, total - 1)?;
        self.update(otg(V_MIN), 0x7fff, total - 1)?;
        self.update(otg(STATIC_SCREEN), STATIC_SCREEN_FIELDS, a.static_screen)?;
        self.status.drr = None;
        Ok(())
    }
    pub(super) fn restore_drr(&mut self, pipe: u8) -> Result<(), Error> {
        let Some(a) = self.status.drr.filter(|a| a.pipe == pipe) else {
            return Ok(());
        };
        self.drr_timing(pipe)?;
        let l = self.layout;
        let result = (|| {
            self.update(l.otg(pipe, V_TOTAL_MAX), 0x7fff, a.adjust.v_total_max - 1)?;
            self.update(l.otg(pipe, V_MIN), 0x7fff, a.adjust.v_total_min - 1)?;
            self.update(l.otg(pipe, V_CONTROL), DRR_FIELDS, a.control())?;
            self.update(
                l.otg(pipe, STATIC_SCREEN),
                STATIC_SCREEN_FIELDS,
                STATIC_SCREEN_TRIGA,
            )
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
        }
        result
    }
    /// Apply the retained actual timing. Record-before-write lets stop or
    /// recovery restore fixed timing after any partial hardware failure.
    fn drr_adjust(
        &mut self,
        mut a: DrrApplied,
        next: crate::amdgpu_freesync::Drr,
    ) -> Result<(), Error> {
        let changed = a.adjust != next;
        a.adjust = next;
        self.status.drr = Some(a);
        if !changed {
            return Ok(());
        }
        let result = (|| {
            self.update(
                self.layout.otg(a.pipe, V_TOTAL_MAX),
                0x7fff,
                next.v_total_max - 1,
            )?;
            self.update(self.layout.otg(a.pipe, V_MIN), 0x7fff, next.v_total_min - 1)
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
        }
        result
    }
    fn verify_drr_adjust(&mut self, a: DrrApplied) -> Result<(), Error> {
        for (reg, mask, expected) in [
            (V_MIN, 0x7fff, a.adjust.v_total_min - 1),
            (V_TOTAL_MAX, 0x7fff, a.adjust.v_total_max - 1),
            (V_CONTROL, DRR_FIELDS, a.control()),
            (STATIC_SCREEN, STATIC_SCREEN_FIELDS, STATIC_SCREEN_TRIGA),
        ] {
            let at = self.layout.otg(a.pipe, reg);
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        self.verify_drr_mid(a.pipe)
    }
    /// Start/stop BTR on an admitted, pinned variable-refresh stream.
    /// Same configuration preserves render cadence and pending repeats.
    pub(in crate::amdgpu_dcn401_otg) fn set_lfc(
        &mut self,
        pipe: u8,
        config: Option<crate::amdgpu_freesync::LfcConfig>,
    ) -> Result<(), Error> {
        let timing = self.drr_timing(pipe)?;
        let Some(mut a) = self.status.drr.filter(|a| a.pipe == pipe) else {
            return if config.is_none() {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        };
        if config.is_some_and(|c| c.timing() != timing || c.base() != a.drr) {
            return Err(Error::Invalid);
        }
        if config.is_some() && a.mid.is_some() {
            return Err(Error::Busy);
        }
        if a.lfc.map(|r| r.math.config) == config {
            return Ok(());
        }
        if let Err(e) = self.verify_drr_adjust(a) {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        a.lfc = match config {
            Some(c) => Some(LfcRuntime {
                math: crate::amdgpu_freesync::Lfc::new(c),
                frame: self.read(self.layout.otg(pipe, FRAME_COUNT))? & FRAME_MASK,
                last_flip_us: None,
            }),
            None => None,
        };
        self.drr_adjust(a, a.drr)
    }
    /// An actual observed VUPDATE (FRAME_COUNT transition), never an
    /// elapsed-time estimate. A missed transition discards the BTR cycle
    /// and render timestamp and restores the admitted variable range;
    /// replaying unknown frame history could shorten the wrong frame.
    pub(in crate::amdgpu_dcn401_otg) fn lfc_progress(&mut self, pipe: u8) -> Result<(), Error> {
        if !matches!(self.status.state, State::ScanoutRunning(p) | State::Flipping(p) if p == pipe)
        {
            return Ok(());
        }
        let Some(mut a) = self
            .status
            .drr
            .filter(|a| a.pipe == pipe && a.lfc.is_some())
        else {
            return Ok(());
        };
        let result = (|| {
            self.verify_drr_adjust(a)?;
            let mut runtime = a.lfc.unwrap();
            let frame = self.read(self.layout.otg(pipe, FRAME_COUNT))? & FRAME_MASK;
            let delta = frame.wrapping_sub(runtime.frame) & FRAME_MASK;
            if delta == 0 {
                return Ok(());
            }
            runtime.frame = frame;
            let next = if delta != 1 {
                runtime.math.reset();
                runtime.last_flip_us = None;
                Some(a.drr)
            } else {
                let signal = self.status.pipes[usize::from(pipe)]
                    .ok_or(Error::Invalid)?
                    .request
                    .signal;
                runtime
                    .math
                    .vupdate(matches!(signal, Signal::Tmds | Signal::HdmiFrl))
            };
            a.lfc = Some(runtime);
            self.drr_adjust(a, next.unwrap_or(a.adjust))
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
        }
        result
    }
    pub(super) fn lfc_resync(&mut self, pipe: u8) -> Result<(), Error> {
        if self.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        let Some(mut a) = self
            .status
            .drr
            .filter(|a| a.pipe == pipe && a.lfc.is_some())
        else {
            return Ok(());
        };
        let result = (|| {
            self.verify_drr_adjust(a)?;
            let mut runtime = a.lfc.unwrap();
            runtime.math.reset();
            runtime.last_flip_us = None;
            runtime.frame = self.read(self.layout.otg(pipe, FRAME_COUNT))? & FRAME_MASK;
            a.lfc = Some(runtime);
            self.drr_adjust(a, a.drr)
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
        }
        result
    }
    /// The idle service cannot resume a cancelled address/stream transaction.
    pub(in crate::amdgpu_dcn401_otg) fn lfc_idle(&mut self, pipe: u8) -> Result<(), Error> {
        if self.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        self.lfc_progress(pipe)
    }
    /// Immediately before the actual address transaction, with the same
    /// owner and retained surfaces. A cancelled flip leaves Flipping and
    /// its timing ownership quarantined; the idle service cannot advance it.
    pub(super) fn lfc_preflip(&mut self, pipe: u8, now_us: u32) -> Result<(), Error> {
        self.lfc_progress(pipe)?;
        let Some(mut a) = self
            .status
            .drr
            .filter(|a| a.pipe == pipe && a.lfc.is_some())
        else {
            return Ok(());
        };
        let mut runtime = a.lfc.unwrap();
        let next = runtime
            .last_flip_us
            .and_then(|last| runtime.math.preflip(now_us.wrapping_sub(last)));
        runtime.last_flip_us = Some(now_us);
        a.lfc = Some(runtime);
        self.drr_adjust(a, next.unwrap_or(a.adjust))
    }
    /// optc401_set_drr MID branch; refuse concurrent BTR so two independent
    /// frame-count policies never compete. Zero/foreign/out-of-range MID
    /// cannot be written. Explicit removal clears both selectors/count.
    pub(in crate::amdgpu_dcn401_otg) fn set_drr_mid(
        &mut self,
        pipe: u8,
        mid: Option<DrrMid>,
    ) -> Result<(), Error> {
        self.drr_timing(pipe)?;
        let mut a = self
            .status
            .drr
            .filter(|a| a.pipe == pipe)
            .ok_or(Error::Busy)?;
        if a.lfc.is_some() {
            return Err(Error::Busy);
        }
        if mid.is_some_and(|m| {
            m.frames == 0 || m.v_total < a.drr.v_total_min || m.v_total > a.drr.v_total_max
        }) {
            return Err(Error::Invalid);
        }
        if a.mid == mid {
            return Ok(());
        }
        a.mid = mid;
        self.status.drr = Some(a);
        let result = (|| {
            if let Some(m) = mid {
                self.update(self.layout.otg(pipe, V_TOTAL_MID), 0x7fff, m.v_total - 1)?;
            }
            self.update(self.layout.otg(pipe, V_CONTROL), DRR_FIELDS, a.control())?;
            if mid.is_none() {
                self.update(self.layout.otg(pipe, V_TOTAL_MID), 0x7fff, 0)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
        }
        result
    }
    pub(super) fn verify_drr_mid(&mut self, pipe: u8) -> Result<(), Error> {
        if let Some(m) = self
            .status
            .drr
            .filter(|a| a.pipe == pipe)
            .and_then(|a| a.mid)
        {
            let at = self.layout.otg(pipe, V_TOTAL_MID);
            if self.read(at)? & 0x7fff != m.v_total - 1 {
                return Err(Error::Readback(at));
            }
        }
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
    /// Restore native refresh limits after an acknowledged FAMS2 disable.
    /// # Safety
    /// Firmware no longer schedules this timing; caller holds its HW lock
    /// and pinned clocks, and retains the scanout owner.
    pub(crate) unsafe fn restore_drr(&mut self, pipe: u8) -> Result<(), Error> {
        self.0.select_display(pipe)?;
        self.0.restore_drr(pipe)
    }

    /// Stretch (`Some`) or fix (`None`) the vertical total of display
    /// `pipe`'s live scanout. `Busy` unless the pipe is `ScanoutRunning`;
    /// totals outside [mode total, 32767] are `Invalid` without writes. A
    /// register failure leaves `Failed` with the record retained, so the
    /// next stop still restores fixed refresh. Leaving scanout (stopping or
    /// recovering fetch) or the timing returns to fixed refresh first.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent timing writers.
    pub async unsafe fn set_drr(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<Option<DrrApplied>, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        self.0.configure_drr(pipe, drr).await
    }
    /// Configure admitted BTR frame insertion; UCLK must remain pinned.
    /// # Safety
    /// As for `set_drr`; retain the scanout owner across every frame update.
    pub async unsafe fn set_lfc(
        &mut self,
        pipe: u8,
        config: Option<crate::amdgpu_freesync::LfcConfig>,
    ) -> Result<(), Error> {
        self.0.select_display(pipe)?;
        self.0.configure_lfc(pipe, config).await
    }
    /// Service a real frame transition while the retained owner is idle.
    /// # Safety
    /// As for `set_drr`; call only for ScanoutRunning, never a cancelled operation.
    pub unsafe fn lfc_progress(&mut self, pipe: u8, lost: bool) -> Result<(), Error> {
        self.0.select_display(pipe)?;
        if lost {
            self.0.lfc_resync(pipe)
        } else {
            self.0.lfc_idle(pipe)
        }
    }
    /// Program a finite hardware MID sequence independently of BTR.
    /// # Safety
    /// As for `set_drr`; the same owner must retain the timing until cleared.
    pub unsafe fn set_drr_mid(&mut self, pipe: u8, mid: Option<DrrMid>) -> Result<(), Error> {
        self.0.select_display(pipe)?;
        self.0.set_drr_mid(pipe, mid)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_drr_tests.rs"]
pub(super) mod tests;

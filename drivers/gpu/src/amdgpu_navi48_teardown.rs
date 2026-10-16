//! Durable progress through a modeset's teardown. Completed native steps are
//! never replayed; the unfinished step still enforces its own hardware guards.
use super::{ColdBoot, Modeset, ModesetError, Selection};
use crate::amdgpu_dcn401_otg as otg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeardownStep {
    Audio,
    Scanout,
    Video,
    Scdc,
    Payload,
    Frontend,
    Link,
    Timing,
    DscClock,
    Planes,
    Release,
    Complete,
}

/// Historical orchestration progress, never permission to reuse memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeardownStatus {
    pub next: TeardownStep,
    /// A dropped native phase has no completion witness and cannot be replayed.
    pub in_flight: bool,
    /// An activation has not returned a Modeset; abort still checks native proof.
    pub activation: bool,
    /// DP link shutdown keeps physical-removal semantics on every resume.
    pub unplugged: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Tmds,
    Frl,
    Sst,
    Uhbr,
    Mst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanoutWitness {
    address: u64,
    stream: u8,
    frames: (u32, u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request {
    pipe: u8,
    port: usize,
    protocol: Protocol,
    audio: bool,
    scdc: bool,
    dsc: bool,
    // The original modeset witness, not the changing front address after flips.
    scanout: Option<ScanoutWitness>,
}
impl Request {
    fn of(m: &Modeset) -> Self {
        Self {
            scanout: Some(ScanoutWitness {
                address: m.scanout.address,
                stream: m.scanout.stream,
                frames: (m.scanout.frame_before, m.scanout.frame_after),
            }),
            ..Self::activation(m.pipe, &m.selection)
        }
    }
    fn activation(pipe: u8, s: &Selection) -> Self {
        Self {
            pipe,
            port: s.port,
            protocol: if s.frl.is_some() {
                Protocol::Frl
            } else if s.hdmi {
                Protocol::Tmds
            } else if s.uhbr() {
                Protocol::Uhbr
            } else if s.mst.is_some() {
                Protocol::Mst
            } else {
                Protocol::Sst
            },
            audio: s.audio.is_some() && !s.uhbr() && s.frl.is_none(),
            scdc: s.scdc,
            dsc: s.dsc.is_some(),
            scanout: None,
        }
    }
    fn first(self) -> TeardownStep {
        if self.scanout.is_none() {
            TeardownStep::Timing
        } else if self.audio {
            TeardownStep::Audio
        } else {
            TeardownStep::Scanout
        }
    }
    fn after(self, step: TeardownStep) -> TeardownStep {
        use TeardownStep::*;
        match step {
            Audio => Scanout,
            Scanout => Video,
            Video => match self.protocol {
                Protocol::Tmds | Protocol::Frl => Scdc,
                Protocol::Mst => Payload,
                Protocol::Sst => Frontend,
                Protocol::Uhbr => Link,
            },
            Scdc | Frontend => Link,
            Payload => Frontend,
            Link => Timing,
            Timing if self.dsc => DscClock,
            Timing | DscClock => Planes,
            Planes if self.scanout.is_none() => Release,
            Planes | Release | Complete => Complete,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Progress {
    request: Request,
    status: TeardownStatus,
}
#[derive(Debug)]
pub(super) struct Teardowns([Option<Progress>; 4]);
impl Teardowns {
    pub(super) fn new() -> Self {
        Self([None; 4])
    }
    fn begin(&mut self, request: Request, unplugged: bool) -> Result<(), ModesetError> {
        let slot = self
            .0
            .get_mut(usize::from(request.pipe))
            .ok_or(otg::Error::Invalid)?;
        if slot.is_some_and(|p| p.request != request) {
            return Err(otg::Error::Busy.into());
        }
        let progress = slot.get_or_insert(Progress {
            request,
            status: TeardownStatus {
                next: request.first(),
                in_flight: false,
                activation: request.scanout.is_none(),
                unplugged,
            },
        });
        progress.status.unplugged |= unplugged;
        Ok(())
    }
    fn start_activation(&mut self, request: Request) -> Result<(), ModesetError> {
        self.rearm(request.pipe)?;
        self.begin(request, false)?;
        // Covers the entire activation, including compound AUX/SCDC work and
        // retry delays whose native owner may look idle during cancellation.
        self.0[usize::from(request.pipe)]
            .as_mut()
            .unwrap()
            .status
            .in_flight = true;
        Ok(())
    }
    pub(super) fn begin_activation(
        &mut self,
        pipe: u8,
        selection: &Selection,
    ) -> Result<(), ModesetError> {
        self.start_activation(Request::activation(pipe, selection))
    }
    /// Record the inverse of a completed startup phase, without a suspension
    /// between its native completion and this checkpoint. This is not permission
    /// to replay a cancelled startup or bypass a failed native owner. Retraining
    /// also uses start_link, but has no unpublished activation to checkpoint.
    pub(super) fn checkpoint_activation(&mut self, pipe: u8, next: TeardownStep) {
        if let Some(p) = self.0[usize::from(pipe)]
            .as_mut()
            .filter(|p| p.status.activation)
        {
            assert!(p.status.in_flight);
            p.status.next = next;
        }
    }
    pub(super) fn finish_activation(&mut self, pipe: u8, succeeded: bool) {
        let slot = &mut self.0[usize::from(pipe)];
        if succeeded {
            *slot = None;
        } else {
            slot.as_mut().unwrap().status.in_flight = false;
        }
    }
    fn status(&self, pipe: u8) -> Option<TeardownStatus> {
        self.0
            .get(usize::from(pipe))
            .and_then(|p| p.map(|p| p.status))
    }
    pub(super) fn check_idle(&self) -> Result<(), ModesetError> {
        if self
            .0
            .iter()
            .flatten()
            .any(|p| p.status.next != TeardownStep::Complete)
        {
            return Err(otg::Error::Busy.into());
        }
        Ok(())
    }
    /// A new activation may replace only a completely retired incarnation.
    pub(super) fn rearm(&mut self, pipe: u8) -> Result<(), ModesetError> {
        let slot = self
            .0
            .get_mut(usize::from(pipe))
            .ok_or(otg::Error::Invalid)?;
        if slot.is_some_and(|p| p.status.next != TeardownStep::Complete) {
            return Err(otg::Error::Busy.into());
        }
        *slot = None;
        Ok(())
    }
}

trait Backend {
    fn teardowns(&mut self) -> &mut Teardowns;
    fn completed(&mut self, request: Request) -> Result<(), ModesetError>;
    /// # Safety
    /// As for ColdBoot::stop_modeset, including CPU withdrawal and ownership.
    async unsafe fn step(
        &mut self,
        request: Request,
        status: TeardownStatus,
    ) -> Result<(), ModesetError>;
}

async unsafe fn run(
    b: &mut impl Backend,
    request: Request,
    unplugged: bool,
) -> Result<(), ModesetError> {
    b.teardowns().begin(request, unplugged)?;
    loop {
        let status = b
            .teardowns()
            .status(request.pipe)
            .ok_or(otg::Error::Invalid)?;
        if status.next == TeardownStep::Complete {
            return b.completed(request);
        }
        if status.in_flight {
            return Err(otg::Error::Busy.into());
        }
        b.teardowns().0[usize::from(request.pipe)]
            .as_mut()
            .unwrap()
            .status
            .in_flight = true;
        // SAFETY: caller retains exclusive owners and has drained CPU writers.
        // Native operations still reject failed/in-flight owners on a resume.
        let result = unsafe { b.step(request, status) }.await;
        b.teardowns().0[usize::from(request.pipe)]
            .as_mut()
            .unwrap()
            .status
            .in_flight = false;
        result?;
        // No await between completion and recording it. Cancellation leaves
        // exactly the unfinished step; it cannot forget an earlier success.
        b.teardowns().0[usize::from(request.pipe)]
            .as_mut()
            .unwrap()
            .status
            .next = request.after(status.next);
    }
}

async unsafe fn abort(b: &mut impl Backend, pipe: u8) -> Result<(), ModesetError> {
    let request = b
        .teardowns()
        .0
        .get(usize::from(pipe))
        .and_then(|p| *p)
        .filter(|p| p.request.scanout.is_none())
        .ok_or(otg::Error::Invalid)?
        .request;
    // SAFETY: caller retains the unpublished activation and all exclusions.
    unsafe { run(b, request, false) }.await?;
    // No suspension after release: a new activation can reuse this slot only
    // after the final fresh proof and allocation release both succeeded.
    b.teardowns().rearm(pipe)
}

impl Backend for ColdBoot {
    fn teardowns(&mut self) -> &mut Teardowns {
        &mut self.teardowns
    }
    fn completed(&mut self, r: Request) -> Result<(), ModesetError> {
        if r.protocol == Protocol::Mst {
            if let Some(link) = self.display_mst(r.port) {
                link.require_transaction_idle::<super::dmub::Error>()?;
            }
        }
        self.select_display(r.pipe)?;
        // A raw low-level restart/power operation invalidates completion.
        // This is a lifecycle check, not the fresh proof used to free VRAM.
        if self.display_timing_status()?.state != otg::State::PlanesRetired {
            return Err(otg::Error::Busy.into());
        }
        Ok(())
    }
    async unsafe fn step(
        &mut self,
        r: Request,
        status: TeardownStatus,
    ) -> Result<(), ModesetError> {
        use TeardownStep::*;
        // Payload transactions span AUX and native source owners. A returned
        // error can leave native state looking settled while remote state is
        // uncertain; no startup checkpoint permits tearing that ownership down.
        if r.protocol == Protocol::Mst {
            if let Some(link) = self.display_mst(r.port) {
                link.require_transaction_idle::<super::dmub::Error>()?;
            }
        }
        self.select_display(r.pipe)?;
        // SAFETY: the caller supplies the same exclusions as stop_modeset;
        // each native operation checks its retained owner and current hardware.
        unsafe {
            match status.next {
                Audio => {
                    self.stop_display_audio(r.port, r.protocol == Protocol::Tmds)
                        .await?
                }
                Scanout => self.stop_display_scanout(r.pipe).await?,
                Video => match r.protocol {
                    Protocol::Tmds => self.stop_display_hdmi_video(r.port).await?,
                    Protocol::Frl => self.stop_display_frl_video(r.port).await?,
                    Protocol::Uhbr => self.stop_display_uhbr_video(r.port).await?,
                    Protocol::Sst | Protocol::Mst => self.stop_display_dp_video(r.port).await?,
                },
                Scdc => {
                    if r.protocol == Protocol::Frl {
                        self.stop_frl_sink(r.port).await;
                    } else if r.scdc {
                        // Preserve the native best-effort legacy TMDS write,
                        // including unplug (the sink may already be back).
                        let _ = self
                            .display_scdc_write(r.port, super::modeset::scdc::TMDS_CONFIG, 0)
                            .await;
                    }
                }
                Payload => self.remove_display_mst_payload(r.port, r.pipe).await?,
                Frontend => self.stop_display_dp_frontend(r.port).await?,
                Link => match r.protocol {
                    Protocol::Tmds => self.stop_display_hdmi_link(r.port).await?,
                    Protocol::Frl => self.stop_display_frl_link(r.port).await?,
                    Protocol::Uhbr => {
                        self.stop_display_uhbr_link(r.port, status.unplugged)
                            .await?
                    }
                    Protocol::Mst => {
                        self.finish_mst_stream(r.port, r.pipe, status.unplugged)
                            .await?
                    }
                    Protocol::Sst if status.unplugged => {
                        self.stop_unplugged_display_dp_link(r.port).await?
                    }
                    Protocol::Sst => self.stop_display_dp_link(r.port).await?,
                },
                Timing => self.retire_display_timing(r.pipe).await?,
                DscClock => self.stop_display_dscclk(r.pipe)?,
                Planes => {
                    self.retire_display_planes().await?;
                }
                Release => {
                    self.release_display_surfaces(r.pipe)?;
                }
                Complete => {}
            }
        }
        Ok(())
    }
}

impl ColdBoot {
    /// Abort a recorded activation which returned an error before publication.
    /// Unwind checkpointed link/video/scanout phases, then retire timing/DSC,
    /// planes and allocations using fresh native proofs. Uncheckpointed live
    /// work, failed owners and cancelled operations remain blocked. Completed
    /// abort phases are not replayed on a retry.
    /// # Safety
    /// As for modeset_display. The activation must remain unpublished to CPU
    /// writers and other engines; drain any views from earlier incarnations
    /// before activation, and retain exclusive ownership throughout the abort.
    pub async unsafe fn abort_modeset_activation(&mut self, pipe: u8) -> Result<(), ModesetError> {
        // SAFETY: caller supplies the unpublished activation's exclusions.
        unsafe { abort(self, pipe) }.await
    }
    /// Record the intended teardown before an async CPU-writer withdrawal.
    /// No hardware is touched. Keep the Modeset for every subsequent resume.
    pub fn begin_modeset_teardown(
        &mut self,
        m: &Modeset,
        unplugged: bool,
    ) -> Result<(), ModesetError> {
        self.teardowns.begin(Request::of(m), unplugged)
    }
    /// Resume the same modeset from its first unfinished teardown step.
    /// # Safety
    /// As for stop_modeset. Progress is historical: surface release still
    /// requires its independent fresh CPU/hardware retirement proof.
    pub(super) async unsafe fn teardown_modeset(
        &mut self,
        m: &Modeset,
        unplugged: bool,
    ) -> Result<(), ModesetError> {
        // SAFETY: caller supplies CPU withdrawal and exclusive device ownership.
        unsafe { run(self, Request::of(m), unplugged) }.await
    }
    pub fn display_teardown_status(&self, pipe: u8) -> Option<TeardownStatus> {
        self.teardowns.status(pipe)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_teardown_tests.rs"]
mod tests;

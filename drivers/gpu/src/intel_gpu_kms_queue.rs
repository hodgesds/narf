//! Owned FIFO for fixed-mode Intel KMS. User memory and descriptor lookup are
//! confined to admission; only retained buffers, fences and copied state cross
//! the worker boundary. Linux drm_atomic_helper_setup_commit/commit_tail model.
use super::*;
use alloc::collections::{BTreeMap, VecDeque};
use narf_filesystem::{DrmFence, InstallFdError};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

const MAX_COMMITS: usize = 32;
static QUEUES: IrqSafeSpinLock<BTreeMap<u32, Arc<Queue>>> = IrqSafeSpinLock::new(BTreeMap::new());

pub(super) fn for_card(index: u32, mode: ModeState) -> Arc<Queue> {
    QUEUES
        .lock()
        .entry(index)
        .or_insert_with(|| Arc::new(Queue::new(mode)))
        .clone()
}

pub(super) struct Completion {
    result: IrqSafeSpinLock<Option<Result<FlipStamp, FsError>>>,
}
impl Completion {
    fn new() -> Self {
        Self {
            result: IrqSafeSpinLock::new(None),
        }
    }
    fn finish(&self, result: Result<FlipStamp, FsError>) {
        let mut state = self.result.lock();
        if state.is_none() {
            *state = Some(result);
        }
    }
    pub(super) fn result(&self) -> Option<Result<FlipStamp, FsError>> {
        *self.result.lock()
    }
    pub(super) async fn result_async(&self) -> Result<FlipStamp, FsError> {
        loop {
            if let Some(result) = self.result() {
                return result;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
}
impl DrmFence for Completion {
    fn is_signalled(&self) -> bool {
        self.result().is_some()
    }
    fn status(&self) -> i32 {
        match self.result() {
            None => 0,
            Some(Ok(_)) => 1,
            Some(Err(FsError::TimedOut)) => -110,
            Some(Err(FsError::NoDevice)) => -19,
            // Cancellation, stale state and hardware failure never masquerade
            // as successful presentation to SYNC_IOC_FILE_INFO.
            Some(Err(_)) => -5,
        }
    }
    fn wait(&self, timeout_ms: u64) -> bool {
        let deadline =
            narf_time::monotonic_ns().saturating_add(timeout_ms.saturating_mul(1_000_000));
        loop {
            if self.is_signalled() {
                return true;
            }
            if narf_time::monotonic_ns() >= deadline {
                return false;
            }
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
    }
    // No shared ordered dma_fence context: a failed predecessor must not let
    // dma_resv/unwrap discard another still-live commit's error or dependency.
    fn driver_name(&self) -> &str {
        "intel-gpu"
    }
    fn timeline_name(&self) -> &str {
        "primary"
    }
    fn timestamp_ns(&self) -> Option<u64> {
        self.result().and_then(Result::ok).map(|stamp| stamp.ns)
    }
}

struct BlobPin {
    mode: ModeState,
    id: u32,
}
impl Drop for BlobPin {
    fn drop(&mut self) {
        self.mode.lock().intel_release_blob(self.id);
    }
}

struct DumbPin {
    mode: ModeState,
    handle: u32,
}
impl Drop for DumbPin {
    fn drop(&mut self) {
        let freed = self.mode.lock().remove_dumb_backing(self.handle);
        if let Some((phys, order)) = freed {
            narf_memory::frame::free_pages(
                narf_memory::frame::PhysFrame::new(narf_memory::PhysAddr::new(phys)),
                order,
            );
        }
    }
}

pub(super) struct Job {
    plan: Plan,
    open: u64,
    epoch: u64,
    dependencies: Vec<Arc<dyn DrmFence>>,
    reservation: Option<FlipEventReservation>,
    owner: Option<Events>,
    completion: Arc<Completion>,
    predecessor: Option<Arc<Completion>>,
    _dumb: Option<DumbPin>,
    _blob: Option<BlobPin>,
}
impl Drop for Job {
    fn drop(&mut self) {
        // A worker's task cancellation cannot strand an exported fd forever.
        // Any armed surface remains retained by the display owner itself.
        self.completion.finish(Err(FsError::Busy));
    }
}
struct State {
    jobs: VecDeque<Job>,
    running: bool,
    projected: Option<(u64, Crtc, u32, Arc<Completion>)>,
}
pub(super) struct Queue {
    mode: ModeState,
    admission: Mutex<()>,
    state: IrqSafeSpinLock<State>,
}
#[derive(Debug)]
pub(super) enum SubmitError {
    Io(FsError),
    NoDescriptor,
}
impl From<FsError> for SubmitError {
    fn from(error: FsError) -> Self {
        Self::Io(error)
    }
}
pub(super) type Submitted = Option<(Arc<Completion>, bool, bool)>;
impl Queue {
    pub(super) fn new(mode: ModeState) -> Self {
        Self {
            mode,
            admission: Mutex::new(()),
            state: IrqSafeSpinLock::new(State {
                jobs: VecDeque::new(),
                running: false,
                projected: None,
            }),
        }
    }
    pub(super) fn is_master(&self, open: u64) -> bool {
        self.mode.lock().is_master(open)
    }
    pub(super) async fn submit(
        &self,
        open: u64,
        request: Request,
        geometry: Geometry,
        epoch: u64,
        context: &dyn IoctlContext,
        events: Option<&Events>,
    ) -> Result<Submitted, SubmitError> {
        let _admission = self.admission.lock().await;
        let (previous, previous_ctm, predecessor) = {
            let state = self.state.lock();
            match &state.projected {
                Some((owner, next, ctm, last))
                    if *owner == open && !matches!(last.result(), Some(Err(_))) =>
                {
                    (Some(next.clone()), Some(*ctm), Some(last.clone()))
                }
                _ => (None, None, None),
            }
        };
        let mut plan = {
            let card = self.mode.lock();
            if matches!(request, Request::SetMaster) {
                if card.has_master() && !card.is_master(open) {
                    return Err(FsError::Busy.into());
                }
            } else if !card.is_master(open) {
                return Err(FsError::PermissionDenied.into());
            }
            Plan::stage_from(&card, request, geometry, previous, previous_ctm)?
        };
        let mut dependencies = if let Some(fd) = plan.fence.take() {
            context.sync_file_fences(fd).ok_or(FsError::InvalidData)?
        } else {
            Vec::new()
        };
        if plan.test {
            return Ok(None);
        }
        let blob = if let Action::Color { blob, .. } = plan.action {
            if blob != 0 {
                if !self.mode.lock().intel_retain_blob(blob) {
                    return Err(FsError::NotFound.into());
                }
                Some(BlobPin {
                    mode: self.mode.clone(),
                    id: blob,
                })
            } else {
                None
            }
        } else {
            None
        };
        dependencies.extend(plan_dependencies(&plan, &self.mode)?);
        let dumb = if let Some(fb) = plan.framebuffer.as_ref().filter(|fb| fb.intel.is_none()) {
            self.mode
                .lock()
                .retain_dumb_backing(fb.gem_handle)
                .ok_or(FsError::NotFound)?;
            Some(DumbPin {
                mode: self.mode.clone(),
                handle: fb.gem_handle,
            })
        } else {
            None
        };
        let reservation = if plan.event {
            Some(
                FlipEventReservation::reserve(events.ok_or(FsError::InvalidData)?)
                    .map_err(|_| FsError::OutOfMemory)?,
            )
        } else {
            None
        };
        // Admission is serialized. Reserve capacity before exporting any fd;
        // only the worker removes entries while the foreground copies out.
        {
            let mut state = self.state.lock();
            if state.jobs.len() + usize::from(state.running) >= MAX_COMMITS {
                return Err(FsError::WouldBlock.into());
            }
            state
                .jobs
                .try_reserve(1)
                .map_err(|_| FsError::OutOfMemory)?;
        }
        let completion = Arc::new(Completion::new());
        if let Some(ptr) = plan.out.take() {
            context.write(ptr, &(-1i32).to_le_bytes())?;
            match context
                .install_sync_file(vec![completion.clone() as Arc<dyn DrmFence>], &mut |fd| {
                    context.write(ptr, &fd.to_le_bytes())
                }) {
                Ok(_) => {}
                Err(InstallFdError::NoDescriptor) => return Err(SubmitError::NoDescriptor),
                Err(InstallFdError::Report(error)) => {
                    // Installation may fail after a successful report copy.
                    // The ioctl fails and no descriptor owns this number.
                    let _ = context.write(ptr, &(-1i32).to_le_bytes());
                    return Err(error.into());
                }
            }
        }
        let nonblock = plan.nonblock;
        let mut state = self.state.lock();
        state.projected = Some((open, plan.next.clone(), plan.next_ctm, completion.clone()));
        state.jobs.push_back(Job {
            plan,
            open,
            epoch,
            dependencies,
            reservation,
            owner: events.cloned(),
            completion: completion.clone(),
            predecessor,
            _dumb: dumb,
            _blob: blob,
        });
        let start = !state.running;
        state.running = true;
        Ok(Some((completion, start, nonblock)))
    }

    pub(super) async fn run<W: Worker>(&self, worker: &mut W) {
        let mut guard = RunGuard {
            queue: self,
            armed: true,
        };
        loop {
            let next = {
                let mut state = self.state.lock();
                let next = state.jobs.pop_front();
                if next.is_none() {
                    guard.armed = false;
                    state.projected = None;
                    state.running = false;
                }
                next
            };
            let Some(mut job) = next else {
                return;
            };
            let result = async {
                if job
                    .predecessor
                    .as_ref()
                    .is_some_and(|f| matches!(f.result(), Some(Err(_))))
                {
                    return Err(FsError::Busy);
                }
                self.wait_dependencies(&job, worker).await?;
                worker
                    .process(
                        &self.mode,
                        job.open,
                        job.epoch,
                        &job.plan,
                        job.reservation.take(),
                    )
                    .await
            }
            .await;
            job.completion.finish(result);
        }
    }
    async fn wait_dependencies<W: Worker>(&self, job: &Job, worker: &W) -> Result<(), FsError> {
        let deadline = narf_time::monotonic_ns().saturating_add(15_000_000_000);
        loop {
            if worker.lost() || worker.epoch() != job.epoch {
                return Err(FsError::NoDevice);
            }
            if job
                .owner
                .as_ref()
                .is_some_and(|events| events.lock().is_closed())
            {
                return Err(FsError::Busy);
            }
            if !matches!(job.plan.action, Action::SetMaster)
                && !self.mode.lock().is_master(job.open)
            {
                return Err(FsError::PermissionDenied);
            }
            if job.dependencies.iter().all(|f| f.is_signalled()) {
                if job.dependencies.iter().any(|f| f.status() < 0) {
                    return Err(crate::intel_gpu_user::io_error());
                }
                return Ok(());
            }
            if narf_time::monotonic_ns() >= deadline {
                return Err(FsError::TimedOut);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
}
struct RunGuard<'a> {
    queue: &'a Queue,
    armed: bool,
}
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let abandoned = {
            let mut state = self.queue.state.lock();
            state.running = false;
            state.projected = None;
            core::mem::take(&mut state.jobs)
        };
        // Drop reservations/pins outside the queue lock (pins take Card lock).
        drop(abandoned);
    }
}

pub(super) trait Worker {
    fn lost(&self) -> bool;
    fn epoch(&self) -> u64;
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp>;
}
pub(super) struct DisplayWorker {
    pub(super) display: Arc<crate::intel_gpu_kms::Display>,
    pub(super) mode: ModeState,
}
impl Worker for DisplayWorker {
    fn lost(&self) -> bool {
        self.display.reset_lost()
    }
    fn epoch(&self) -> u64 {
        self.display.epoch()
    }
    fn process<'a>(
        &'a mut self,
        _mode: &'a ModeState,
        open: u64,
        epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        alloc::boxed::Box::pin(async move {
            let mut session = self.display.session().await?;
            if self.display.reset_lost() || self.display.epoch() != epoch {
                return Err(FsError::NoDevice);
            }
            // Saved geometry may change only during verified owner recovery.
            if session.console_geometry().width != plan.geometry.width
                || session.console_geometry().height != plan.geometry.height
            {
                return Err(FsError::Busy);
            }
            execute_plan(&mut session, &self.mode, open, plan, reservation).await
        })
    }
}

//! Retained interrupt service, independent of the firmware/display owner lock.
//! Every drained vector is recorded, given to the fault monitor (evidence
//! before acknowledgement) and then routed by amdgpu_navi48_dispatch to its
//! registered owner. Vectors only wake owners; no fence is completed from an
//! IV payload. A service failure is delivered to every waiter as terminal.
use crate::{
    amdgpu_ih7 as ih, amdgpu_navi48_dispatch as dispatch, amdgpu_navi48_faults as faults,
    amdgpu_navi48_msi as msi, amdgpu_navi48_sources as src,
};
use narf_lib::mutex::Mutex;

static SERVICE: Mutex<Option<Service>> = Mutex::new(None);
static HALTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BLOCKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static FAILED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub(crate) fn failed() -> bool {
    FAILED.load(core::sync::atomic::Ordering::Acquire)
}
/// Synchronous fence readers freeze retirement as soon as containment is seen.
pub(crate) fn blocked() -> bool {
    BLOCKED.load(core::sync::atomic::Ordering::Acquire)
}
#[path = "amdgpu_navi48_interrupts_recovery.rs"]
mod recovery;
pub(crate) use recovery::{begin_recovery, finish_recovery, quarantine, recovery_needed};
pub(crate) fn lose() {
    FAILED.store(true, core::sync::atomic::Ordering::Release);
    BLOCKED.store(true, core::sync::atomic::Ordering::Release);
    HALTED.store(true, core::sync::atomic::Ordering::Release);
    dispatch::TABLE
        .lock()
        .fail_all(dispatch::Terminal::DeviceGone);
}
static GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Stop and detach the old service before mode1. Its published IH storage
/// remains quarantined; the old worker's generation can never drain a new IH.
pub(crate) async fn stop_for_reset() {
    let mut slot = SERVICE.lock().await;
    GENERATION.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    if let Some(mut service) = slot.take() {
        service.stop(dispatch::Terminal::DeviceGone);
        // Drop quarantines published ring storage; no hardware teardown.
        drop(service);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: ih::State,
    pub report: Option<ih::Report>,
    pub route: Result<Option<u8>, msi::Error>,
    pub received: u64,
    pub evicted: u64,
    pub vm_faults: u64,
    pub last_fault: Option<ih::Event>,
    pub kernel_eop: [u64; 2],
    pub sdma0_traps: u64,
    pub vcn0_traps: u64,
    pub jpeg0_traps: u64,
    pub faults: faults::Status,
    /// Kernel graphics, compute and SDMA0 owners registered by the service.
    pub kernel: [Option<dispatch::Endpoint>; 3],
    pub dispatch: dispatch::Summary,
    /// Recovered IH ring0 overflows (vectors were lost).
    pub overflows: u64,
    pub wakes: Wakes,
}
/// Why the worker drained. Kept so MSI delivery on the card is observable
/// rather than inferred from the watchdog quietly doing the work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    Start,
    Pending,
    Irq,
    Watchdog,
    Poll,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wakes {
    /// Drains after a CPU MSI on the routed vector.
    pub irq: u64,
    /// MSI wakes that found no vector: spurious, or already drained by a
    /// proof's own synchronous drain.
    pub irq_empty: u64,
    /// Drains after the 100 ms MSI watchdog expired.
    pub watchdog: u64,
    /// Watchdog drains that found vectors: an MSI was lost or not rearmed.
    pub watchdog_found: u64,
    /// Timer-polled drains without an MSI route.
    pub polls: u64,
}
impl Wakes {
    fn record(&mut self, cause: Cause, drained: usize) {
        let add = |n: &mut u64| *n = n.saturating_add(1);
        match cause {
            Cause::Irq => {
                add(&mut self.irq);
                if drained == 0 {
                    add(&mut self.irq_empty);
                }
            }
            Cause::Watchdog => {
                add(&mut self.watchdog);
                if drained != 0 {
                    add(&mut self.watchdog_found);
                }
            }
            Cause::Poll => add(&mut self.polls),
            Cause::Start | Cause::Pending => {}
        }
    }
}
/// The kernel queues the cold boot owns, registered as dispatch owners so
/// their completions and faults are attributed like any other owner's.
const KERNEL: [dispatch::Key; 3] = [
    dispatch::Key::Cp(src::Queue {
        me: 0,
        pipe: 0,
        queue: 0,
    }),
    dispatch::Key::Cp(src::Queue {
        me: 1,
        pipe: 0,
        queue: 0,
    }),
    dispatch::Key::Sdma {
        instance: 0,
        queue: 0,
    },
];
#[derive(Debug)]
struct History {
    entries: [Option<ih::Event>; 64],
    head: usize,
    len: usize,
    received: u64,
    evicted: u64,
    vm_faults: u64,
    last_fault: Option<ih::Event>,
    kernel_eop: [u64; 2],
    sdma0_traps: u64,
    vcn0_traps: u64,
    jpeg0_traps: u64,
}
impl History {
    fn new() -> Self {
        Self {
            entries: [None; 64],
            head: 0,
            len: 0,
            received: 0,
            evicted: 0,
            vm_faults: 0,
            last_fault: None,
            kernel_eop: [0; 2],
            sdma0_traps: 0,
            vcn0_traps: 0,
            jpeg0_traps: 0,
        }
    }
    fn push(&mut self, event: ih::Event) {
        self.received = self.received.saturating_add(1);
        // Linux gfx_v12_0_eop_irq resolves kernel queues by exact ME/pipe/queue,
        // not the doorbell payload used for user queues. VMID/PASID must also
        // name this bootstrap's kernel context.
        if event.vector.client == 0x0a
            && event.vector.source == 181
            && event.vector.vmid == 0
            && event.vector.pasid == 0
        {
            let pipe = match event.vector.ring & 0x7f {
                0 => Some(0),
                4 => Some(1),
                _ => None,
            };
            if let Some(pipe) = pipe {
                self.kernel_eop[pipe] = self.kernel_eop[pipe].saturating_add(1);
            }
        }
        // SDMA7 encodes instance in the high nibble and queue in the low
        // nibble. Unlike CP, bit 7 is not reserved. Only SDMA0 queue0 is owned.
        if event.vector.client == 0x0a
            && event.vector.source == 49
            && event.vector.ring == 0
            && event.vector.vmid == 0
            && event.vector.pasid == 0
        {
            self.sdma0_traps = self.sdma0_traps.saturating_add(1);
        }
        // vcn_v5_0_0_process_interrupt: the client instance and source
        // identify the unified queue; the ring field has no queue selector.
        if event.vector.client == src::CLIENT_VCN
            && event.vector.source == 119
            && event.vector.vmid == 0
            && event.vector.pasid == 0
        {
            self.vcn0_traps = self.vcn0_traps.saturating_add(1);
        }
        if event.vector.client == src::CLIENT_VCN
            && event.vector.source == 153
            && event.vector.vmid == 0
            && event.vector.pasid == 0
        {
            self.jpeg0_traps = self.jpeg0_traps.saturating_add(1);
        }
        if matches!(event.vector.client, 0x0a | 0x12) && event.vector.source == 0 {
            self.vm_faults = self.vm_faults.saturating_add(1);
            self.last_fault = Some(event);
        }
        if self.len == self.entries.len() {
            self.head = (self.head + 1) % self.entries.len();
            self.len -= 1;
            self.evicted = self.evicted.saturating_add(1);
        }
        self.entries[(self.head + self.len) % self.entries.len()] = Some(event);
        self.len += 1;
    }
    fn count(&self, source: Source) -> u64 {
        match source {
            Source::Graphics => self.kernel_eop[0],
            Source::Compute => self.kernel_eop[1],
            Source::Sdma0 => self.sdma0_traps,
            Source::Vcn0 => self.vcn0_traps,
            Source::Jpeg0 => self.jpeg0_traps,
        }
    }
    fn pop(&mut self) -> ih::Batch {
        let mut entries = [None; 32];
        for slot in entries.iter_mut().take(self.len.min(32)) {
            *slot = self.entries[self.head].take();
            self.head = (self.head + 1) % self.entries.len();
            self.len -= 1;
        }
        ih::Batch::from_entries(entries, self.len != 0)
    }
}
#[derive(Debug)]
struct Service {
    rings: ih::Rings,
    route: Option<msi::Route>,
    routing: Result<Option<u8>, msi::Error>,
    history: History,
    faults: faults::Monitor,
    kernel: [Option<dispatch::Handle>; 3],
    wakes: Wakes,
    drained: usize,
}
impl Service {
    fn status(&self) -> Status {
        Status {
            state: self.rings.state(),
            report: self.rings.report(),
            route: self.routing,
            received: self.history.received,
            evicted: self.history.evicted,
            vm_faults: self.history.vm_faults,
            last_fault: self.history.last_fault,
            kernel_eop: self.history.kernel_eop,
            sdma0_traps: self.history.sdma0_traps,
            vcn0_traps: self.history.vcn0_traps,
            jpeg0_traps: self.history.jpeg0_traps,
            faults: self.faults.status(),
            kernel: self
                .kernel
                .map(|h| h.and_then(|h| dispatch::endpoint(h).ok())),
            dispatch: dispatch::summary(),
            overflows: self.rings.overflows(),
            wakes: self.wakes,
        }
    }
    fn drain(&mut self) -> Result<bool, ih::Error> {
        if HALTED.load(core::sync::atomic::Ordering::Acquire) {
            return Err(ih::Error::DeviceGone);
        }
        self.drained = 0;
        match self.rings.drain() {
            Ok(batch) => {
                self.drained = batch.events().count();
                for event in batch.events() {
                    self.history.push(*event);
                }
                // Retain the whole batch first: a register/capability failure
                // while decoding one fault must not discard already-drained IVs.
                let mut failed = None;
                for event in batch.events() {
                    if let Err(e) = self.faults.handle(*event) {
                        failed.get_or_insert(e);
                    }
                }
                if self.faults.status().state != faults::State::Armed {
                    BLOCKED.store(true, core::sync::atomic::Ordering::Release);
                }
                // Deliver after the monitor captured and acknowledged its
                // evidence, so a woken owner never races the latch.
                {
                    let mut table = dispatch::TABLE.lock();
                    for event in batch.events() {
                        table.route(event, src::classify(event));
                    }
                }
                if batch.lost {
                    // Overwritten vectors may have held completions, display
                    // events or faults: wake every owner to re-check, and
                    // read the VM latches whose IVs may be gone.
                    dispatch::TABLE.lock().lost();
                    match self.faults.sweep() {
                        Ok(found) => {
                            if self.faults.status().state != faults::State::Armed {
                                BLOCKED.store(true, core::sync::atomic::Ordering::Release);
                            }
                            let mut table = dispatch::TABLE.lock();
                            for (mm_hub, vmid) in [false, true].into_iter().zip(found) {
                                if let Some(vmid) = vmid {
                                    table.latched(vmid, mm_hub);
                                }
                            }
                        }
                        Err(e) => {
                            failed.get_or_insert(e);
                        }
                    }
                }
                if let Some(e) = failed {
                    self.stop(match e {
                        faults::Error::DeviceGone => dispatch::Terminal::DeviceGone,
                        _ => dispatch::Terminal::Interrupts(ih::Error::Protocol),
                    });
                    return Err(ih::Error::Protocol);
                }
                Ok(batch.pending)
            }
            Err(e) => {
                self.stop(terminal(e));
                Err(e)
            }
        }
    }
    /// Stop draining for good: mask sources and CPU delivery where authority
    /// permits, then release every waiter with the terminal cause.
    fn stop(&mut self, cause: dispatch::Terminal) {
        // Nothing attributes IVs by PASID any more.
        crate::amdgpu_vmid::track_ih_drains(false);
        FAILED.store(true, core::sync::atomic::Ordering::Release);
        BLOCKED.store(true, core::sync::atomic::Ordering::Release);
        self.faults.stop();
        if let Some(route) = &mut self.route {
            self.routing = route.disable().map(|()| None);
        }
        dispatch::TABLE.lock().fail_all(cause);
    }
}
fn terminal(e: ih::Error) -> dispatch::Terminal {
    match e {
        ih::Error::DeviceGone => dispatch::Terminal::DeviceGone,
        e => dispatch::Terminal::Interrupts(e),
    }
}
/// # Safety
/// Called once after cold boot with initialized CPU interrupt control/executor.
/// All objects describe the same exclusively owned physical GPU. Ownership is
/// transferred only after claiming the permanent service slot; errors before
/// that leave the caller's owners intact. No future GPU reset/PM may race it.
pub(crate) unsafe fn install(
    rings: &mut Option<ih::Rings>,
    route: &mut Option<Result<msi::Route, msi::Error>>,
    faults: &mut Option<faults::Monitor>,
    gmc: &mut crate::amdgpu_gmc_navi48::Gmc,
) -> Result<(), ih::Error> {
    let mut slot = SERVICE.try_lock().ok_or(ih::Error::Busy)?;
    if slot.is_some()
        || rings.as_ref().is_none_or(|r| r.state() != ih::State::Ready)
        || faults
            .as_ref()
            .is_none_or(|f| f.status().state != faults::State::Prepared)
    {
        return Err(ih::Error::Busy);
    }
    let prepared = route.take().ok_or(ih::Error::Invalid)?;
    let (route, routing) = match prepared {
        Ok(r) => (Some(r), Ok(None)),
        Err(e) => (None, Err(e)),
    };
    HALTED.store(false, core::sync::atomic::Ordering::Release);
    *slot = Some(Service {
        rings: rings.take().unwrap(),
        route,
        routing,
        history: History::new(),
        faults: faults.take().unwrap(),
        kernel: [None; 3],
        wakes: Wakes::default(),
        drained: 0,
    });
    let service = slot.as_mut().unwrap();
    for (handle, key) in service.kernel.iter_mut().zip(KERNEL) {
        // VMID0/PASID0 kernel context. A refused registration only loses
        // attribution: its vectors stay counted as unowned.
        *handle = dispatch::register(dispatch::Owner {
            key,
            vmid: 0,
            pasid: 0,
        })
        .ok();
    }
    // SAFETY: matching initialized hubs/queues/IH; the permanent service now
    // retains the monitor before the first source enable or CPU MSI delivery.
    if unsafe { service.faults.enable(gmc) }.is_err() {
        FAILED.store(true, core::sync::atomic::Ordering::Release);
        BLOCKED.store(true, core::sync::atomic::Ordering::Release);
        // No consumer will run: release the owners registered above.
        dispatch::TABLE
            .lock()
            .fail_all(dispatch::Terminal::Interrupts(ih::Error::Protocol));
        return Err(ih::Error::Protocol);
    }
    BLOCKED.store(false, core::sync::atomic::Ordering::Release);
    FAILED.store(false, core::sync::atomic::Ordering::Release);
    if let Some(route) = &mut service.route {
        // SAFETY: service slot already retains both owners and the consumer is
        // spawned below. It drains first, so an early IRQ is not lost.
        service.routing = unsafe { route.enable(&mut service.rings) }.map(Some);
        if service.routing.is_err() && route.state() != msi::State::Prepared {
            // Keep the original setup error visible, but disable any partial
            // MSI programming. Unsupported untouched routes simply use polling.
            let _ = route.disable();
        }
    }
    if let ih::State::Failed(e) = service.rings.state() {
        service.stop(terminal(e));
        return Err(e);
    }
    drop(slot);
    let generation = GENERATION.load(core::sync::atomic::Ordering::Acquire);
    // Released PASIDs now wait for a drain of IVs that may still name them.
    crate::amdgpu_vmid::track_ih_drains(true);
    narf_scheduler::spawn(worker(generation));
    Ok(())
}
async fn worker(generation: u64) {
    let mut cause = Cause::Start;
    loop {
        let vector = {
            let slot = SERVICE.lock().await;
            if GENERATION.load(core::sync::atomic::Ordering::Acquire) != generation {
                return;
            }
            let Some(service) = slot.as_ref() else {
                return;
            };
            service.routing.ok().flatten()
        };
        // Snapshot the IRQ counter BEFORE draining. An IRQ arriving while we
        // drain or before the first wait poll will then make the wait ready.
        let wait = vector.map(narf_interrupts::wait_for_irq);
        let pending = {
            let mut slot = SERVICE.lock().await;
            if GENERATION.load(core::sync::atomic::Ordering::Acquire) != generation {
                return;
            }
            let Some(service) = slot.as_mut() else {
                return;
            };
            match service.drain() {
                Ok(pending) => {
                    service.wakes.record(cause, service.drained);
                    if !pending {
                        crate::amdgpu_vmid::ih_drained();
                    }
                    pending
                }
                Err(_) => return,
            }
        };
        if pending {
            narf_scheduler::yield_now().await;
            cause = Cause::Pending;
            continue;
        }
        cause = if let Some(wait) = wait {
            // A watchdog drain also covers an unexpectedly lost device MSI.
            match narf_time::timeout(narf_time::Deadline::after_ms(100), wait).await {
                Ok(_) => Cause::Irq,
                Err(_) => Cause::Watchdog,
            }
        } else {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
            Cause::Poll
        };
    }
}
/// None means absent or currently draining. Diagnostic history is bounded and
/// evictions are counted; this is not a completion queue for user submissions.
pub fn status() -> Option<Status> {
    SERVICE.try_lock()?.as_ref().map(Service::status)
}
/// Consume retained diagnostic history without stealing hardware entries from
/// the service. Sticky fault information survives history reads and eviction.
pub async fn poll() -> Result<ih::Batch, ih::Error> {
    SERVICE
        .lock()
        .await
        .as_mut()
        .map(|s| s.history.pop())
        .ok_or(ih::Error::Busy)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Graphics,
    Compute,
    Sdma0,
    Vcn0,
    Jpeg0,
}
pub(crate) trait Observer {
    async fn sample(&mut self, source: Source) -> Result<Sample, ih::Error>;
    async fn observed(&mut self, sample: Sample) -> Result<bool, ih::Error>;
}
pub(crate) struct NativeObserver;
impl Observer for NativeObserver {
    async fn sample(&mut self, source: Source) -> Result<Sample, ih::Error> {
        sample(source).await
    }
    async fn observed(&mut self, sample: Sample) -> Result<bool, ih::Error> {
        observed(sample).await
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub source: Source,
    pub count: u64,
    pub cpu: u64,
    pub vector: Option<u8>,
}
impl Sample {
    fn observed(
        self,
        count: u64,
        vector: Option<u8>,
        cpu: u64,
        pending: bool,
        faults: u64,
    ) -> Result<bool, ih::Error> {
        let expected = self.count.checked_add(1).ok_or(ih::Error::Invalid)?;
        if vector != self.vector || count > expected || faults != 0 {
            return Err(ih::Error::Protocol);
        }
        // Drain all already-published IVs before declaring success: a later
        // batch may contain a duplicate EOP or VM fault for this submission.
        Ok(!pending && count == expected && (vector.is_none() || cpu != self.cpu))
    }
}
async fn sample(source: Source) -> Result<Sample, ih::Error> {
    let mut slot = SERVICE.lock().await;
    let service = slot.as_mut().ok_or(ih::Error::Busy)?;
    if service.drain()? {
        return Err(ih::Error::Busy);
    }
    if service.faults.status().state != faults::State::Armed || service.faults.status().count != 0 {
        return Err(ih::Error::Protocol);
    }
    let vector = service.routing.ok().flatten();
    if vector.is_some() && !narf_arch::interrupts_enabled() {
        return Err(ih::Error::Busy);
    }
    let count = service.history.count(source);
    count.checked_add(1).ok_or(ih::Error::Invalid)?;
    Ok(Sample {
        source,
        count,
        cpu: vector.map_or(0, narf_interrupts::fire_count),
        vector,
    })
}
async fn observed(sample: Sample) -> Result<bool, ih::Error> {
    let mut slot = SERVICE.lock().await;
    let service = slot.as_mut().ok_or(ih::Error::Busy)?;
    let pending = service.drain()?;
    if service.faults.status().state != faults::State::Armed {
        return Err(ih::Error::Protocol);
    }
    let vector = service.routing.ok().flatten();
    sample.observed(
        service.history.count(sample.source),
        vector,
        vector.map_or(0, narf_interrupts::fire_count),
        pending,
        service.faults.status().count,
    )
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_interrupts_tests.rs"]
mod tests;

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
    pub faults: faults::Status,
    /// Kernel graphics, compute and SDMA0 owners registered by the service.
    pub kernel: [Option<dispatch::Endpoint>; 3],
    pub dispatch: dispatch::Summary,
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
            faults: self.faults.status(),
            kernel: self
                .kernel
                .map(|h| h.and_then(|h| dispatch::endpoint(h).ok())),
            dispatch: dispatch::summary(),
        }
    }
    fn drain(&mut self) -> Result<bool, ih::Error> {
        match self.rings.drain() {
            Ok(batch) => {
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
                // Deliver after the monitor captured and acknowledged its
                // evidence, so a woken owner never races the latch.
                {
                    let mut table = dispatch::TABLE.lock();
                    for event in batch.events() {
                        table.route(event, src::classify(event));
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
    *slot = Some(Service {
        rings: rings.take().unwrap(),
        route,
        routing,
        history: History::new(),
        faults: faults.take().unwrap(),
        kernel: [None; 3],
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
    if unsafe { service.faults.enable() }.is_err() {
        // No consumer will run: release the owners registered above.
        dispatch::TABLE
            .lock()
            .fail_all(dispatch::Terminal::Interrupts(ih::Error::Protocol));
        return Err(ih::Error::Protocol);
    }
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
    narf_scheduler::spawn(worker());
    Ok(())
}
async fn worker() {
    loop {
        let vector = {
            let slot = SERVICE.lock().await;
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
            let Some(service) = slot.as_mut() else {
                return;
            };
            match service.drain() {
                Ok(pending) => pending,
                Err(_) => return,
            }
        };
        if pending {
            narf_scheduler::yield_now().await;
            continue;
        }
        if let Some(wait) = wait {
            // A watchdog drain also covers an unexpectedly lost device MSI.
            let _ = narf_time::timeout(narf_time::Deadline::after_ms(100), wait).await;
        } else {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
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

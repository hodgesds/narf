//! Retained interrupt service, independent of the firmware/display owner lock.
//! Raw events remain diagnostic until their engine provides a validated fence
//! or fault consumer. No user fence is completed from an unchecked IV payload.
use crate::{amdgpu_ih7 as ih, amdgpu_navi48_faults as faults, amdgpu_navi48_msi as msi};
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
    pub faults: faults::Status,
}
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
            faults: self.faults.status(),
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
                let mut failed = false;
                for event in batch.events() {
                    failed |= self.faults.handle(*event).is_err();
                }
                if failed {
                    self.stop();
                    return Err(ih::Error::Protocol);
                }
                Ok(batch.pending)
            }
            Err(e) => {
                self.stop();
                Err(e)
            }
        }
    }
    fn stop(&mut self) {
        self.faults.stop();
        if let Some(route) = &mut self.route {
            self.routing = route.disable().map(|()| None);
        }
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
    });
    let service = slot.as_mut().unwrap();
    // SAFETY: matching initialized hubs/queues/IH; the permanent service now
    // retains the monitor before the first source enable or CPU MSI delivery.
    unsafe { service.faults.enable() }.map_err(|_| ih::Error::Protocol)?;
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
        service.stop();
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub pipe: usize,
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
pub(crate) async fn sample(pipe: usize) -> Result<Sample, ih::Error> {
    if pipe >= 2 {
        return Err(ih::Error::Invalid);
    }
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
    let count = service.history.kernel_eop[pipe];
    count.checked_add(1).ok_or(ih::Error::Invalid)?;
    Ok(Sample {
        pipe,
        count,
        cpu: vector.map_or(0, narf_interrupts::fire_count),
        vector,
    })
}
pub(crate) async fn observed(sample: Sample) -> Result<bool, ih::Error> {
    let mut slot = SERVICE.lock().await;
    let service = slot.as_mut().ok_or(ih::Error::Busy)?;
    let pending = service.drain()?;
    if service.faults.status().state != faults::State::Armed {
        return Err(ih::Error::Protocol);
    }
    let vector = service.routing.ok().flatten();
    sample.observed(
        service.history.kernel_eop[sample.pipe],
        vector,
        vector.map_or(0, narf_interrupts::fire_count),
        pending,
        service.faults.status().count,
    )
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_interrupts_tests.rs"]
mod tests;

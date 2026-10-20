//! Ordered SDMA5.2 kernel VRAM work. A reset never completes a clear:
//! the whole front request is replayed before any later recycled-range clear.
use crate::amdgpu_navi22_submit::{KernelOp, MAX_PACKET_BYTES};
use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{DrmFence, FsError};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
struct Completion(AtomicBool);
impl DrmFence for Completion {
    fn is_signalled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn wait(&self, timeout_ms: u64) -> bool {
        let deadline =
            narf_time::monotonic_ns().saturating_add(timeout_ms.saturating_mul(1_000_000));
        while !self.is_signalled() {
            if narf_time::monotonic_ns() >= deadline {
                return false;
            }
            narf_scheduler::block_on_spin(narf_time::SleepUntil::new(
                narf_time::Deadline::after_us(100).as_instant(),
            ));
        }
        true
    }
    fn driver_name(&self) -> &str {
        "amdgpu"
    }
}
struct Request {
    op: KernelOp,
    done: Arc<Completion>,
    held: Option<Arc<dyn Send + Sync>>,
    upload: Option<(Arc<crate::amdgpu_gem::GemPlacement>, u64)>,
}
impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("op", &self.op)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Default)]
struct State {
    queued: VecDeque<Request>,
    draining: bool,
    /// Enqueues and recovery publication wake a failed drain without losing
    /// a kick that raced its final error check.
    pulse: u64,
}
impl State {
    fn kick(&mut self) -> bool {
        self.pulse = self.pulse.wrapping_add(1);
        !self.queued.is_empty() && !core::mem::replace(&mut self.draining, true)
    }
    fn failed(&mut self, pulse: u64) -> bool {
        if self.pulse != pulse {
            return true;
        }
        self.draining = false;
        false
    }
    fn complete(&mut self) {
        let request = self.queued.pop_front().expect("one drain owns the front");
        drop(request.held);
        drop(request.upload);
        request.done.0.store(true, Ordering::Release);
    }
}
#[derive(Debug)]
pub(crate) struct Engine {
    state: IrqSafeSpinLock<State>,
    active: AtomicBool,
}
struct Binding {
    card: u32,
    stage: crate::amdgpu_vram::Reservation,
    access: narf_lib::mutex::Mutex<()>,
    last: IrqSafeSpinLock<Option<Arc<dyn DrmFence>>>,
}
static BINDING: IrqSafeSpinLock<Option<Arc<Binding>>> = IrqSafeSpinLock::new(None);

pub(crate) fn publish(
    card: u32,
    boot: &crate::amdgpu_navi22_boot::ColdBoot,
) -> Result<(), FsError> {
    let mut binding = BINDING.lock();
    if let Some(bound) = binding.as_ref() {
        if bound.card != card {
            return Err(FsError::NoDevice);
        }
    } else {
        let mut stage = boot
            .reserve_transfer_stage()
            .map_err(|_| FsError::NoSpace)?;
        stage.publish();
        *binding = Some(Arc::new(Binding {
            card,
            stage,
            access: narf_lib::mutex::Mutex::new(()),
            last: IrqSafeSpinLock::new(None),
        }));
    }
    engine().active.store(true, Ordering::Release);
    Ok(())
}
pub(crate) fn suspend() {
    if let Some(engine) = ENGINE.lock().as_ref() {
        engine.active.store(false, Ordering::Release);
    }
}
static ENGINE: IrqSafeSpinLock<Option<Arc<Engine>>> = IrqSafeSpinLock::new(None);

pub(crate) fn engine() -> Arc<Engine> {
    ENGINE
        .lock()
        .get_or_insert_with(|| {
            Arc::new(Engine {
                state: IrqSafeSpinLock::new(State::default()),
                active: AtomicBool::new(false),
            })
        })
        .clone()
}

fn valid(op: KernelOp) -> bool {
    let (src, dst, bytes) = match op {
        KernelOp::Fill { dst, bytes, .. } => (None, dst, bytes),
        KernelOp::Copy { src, dst, bytes } => (Some(src), dst, bytes),
    };
    let bounds = |at: u64| at.checked_add(bytes).is_some_and(|end| end <= 1 << 48);
    bytes != 0
        && bounds(dst)
        && src.is_none_or(bounds)
        && (src.is_some() || (dst % 4 == 0 && bytes % 4 == 0))
        && src.is_none_or(|from| from.abs_diff(dst) >= bytes)
}
fn chunk(op: KernelOp, offset: u64) -> Option<KernelOp> {
    match op {
        KernelOp::Fill { dst, bytes, value } => (offset < bytes).then(|| KernelOp::Fill {
            dst: dst + offset,
            bytes: (bytes - offset).min(MAX_PACKET_BYTES),
            value,
        }),
        KernelOp::Copy { src, dst, bytes } => (offset < bytes).then(|| KernelOp::Copy {
            src: src + offset,
            dst: dst + offset,
            bytes: (bytes - offset).min(MAX_PACKET_BYTES),
        }),
    }
}
impl Engine {
    pub(crate) fn kick(self: &Arc<Self>) {
        let start = {
            let mut state = self.state.lock();
            state.kick()
        };
        if start {
            narf_scheduler::spawn(self.clone().drain());
        }
    }
    fn enqueue(
        self: &Arc<Self>,
        op: KernelOp,
        held: Option<Arc<dyn Send + Sync>>,
        upload: Option<(Arc<crate::amdgpu_gem::GemPlacement>, u64)>,
    ) -> Result<Arc<dyn DrmFence>, FsError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(FsError::NoDevice);
        }
        if !valid(op) {
            return Err(FsError::InvalidData);
        }
        let done = Arc::new(Completion(AtomicBool::new(false)));
        {
            let mut state = self.state.lock();
            state.queued.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            state.queued.push_back(Request {
                op,
                done: done.clone(),
                held,
                upload,
            });
        }
        self.kick();
        Ok(done)
    }
    async fn drain(self: Arc<Self>) {
        loop {
            let front = {
                let mut state = self.state.lock();
                match state.queued.front() {
                    Some(request) => Some((request.op, state.pulse, request.upload.clone())),
                    None => {
                        state.draining = false;
                        None
                    }
                }
            };
            let Some((op, pulse, upload)) = front else {
                return;
            };
            let mut offset = 0;
            let mut success = true;
            while let Some(op) = chunk(op, offset) {
                if run(op, upload.as_ref()).await.is_err() {
                    success = false;
                    break;
                }
                offset += MAX_PACKET_BYTES;
            }
            drop(upload);
            let mut state = self.state.lock();
            if success {
                state.complete();
            } else if !state.failed(pulse) {
                return;
            }
            // Otherwise a recovery/enqueue raced the failure; retry the
            // complete front request on the newly published owner.
        }
    }
}

#[derive(Debug)]
struct Clearer(Arc<Engine>);
impl crate::amdgpu_gem::VramClear for Clearer {
    fn clear(&self, address: u64, bytes: u64) -> Result<Arc<dyn DrmFence>, FsError> {
        self.0.enqueue(
            KernelOp::Fill {
                dst: address,
                bytes,
                value: 0,
            },
            None,
            None,
        )
    }
}
pub(crate) fn clearer() -> Arc<dyn crate::amdgpu_gem::VramClear> {
    Arc::new(Clearer(engine()))
}

/// Copy an idle invisible BO through the kernel's reserved BAR window into
/// private System backing. Caller holds card placement admission throughout.
async fn readback(
    card: u32,
    object: &Arc<crate::amdgpu_gem::GemObject>,
    source: &Arc<crate::amdgpu_gem::GemPlacement>,
    destination: &mut crate::amdgpu_gem::GemPlacement,
) -> Result<(), FsError> {
    let address = source.hidden_address().ok_or(FsError::InvalidData)?;
    let binding = BINDING
        .lock()
        .as_ref()
        .filter(|bound| bound.card == card)
        .cloned()
        .ok_or(FsError::Unsupported)?;
    let _stage = binding.access.lock().await;
    await_last(&binding).await?;
    let map = binding.stage.mapping();
    let mut offset = 0;
    while offset < source.byte_len {
        let bytes = (source.byte_len - offset).min(map.len);
        let epoch = crate::amdgpu_fence_navi22::generation();
        // The queued request owns the source independently of this future.
        // Abandoning a wait cannot return memory still reached by SDMA.
        let done = engine().enqueue(
            KernelOp::Copy {
                src: address + offset,
                dst: binding.stage.address(),
                bytes,
            },
            Some(Arc::new((object.clone(), source.clone())) as Arc<dyn Send + Sync>),
            None,
        )?;
        object
            .dma_buf()
            .resv
            .add_fence(done.clone(), narf_filesystem::dma_buf::DmaResvUsage::Kernel);
        *binding.last.lock() = Some(done.clone());
        await_done(&done).await?;
        {
            let _power = crate::amdgpu_navi22_gfxoff::Reference::acquire()
                .await
                .map_err(|_| FsError::NoDevice)?;
            let owner = crate::amdgpu_navi22_platform::owner().await;
            if !engine().active.load(Ordering::Acquire)
                || epoch != crate::amdgpu_fence_navi22::generation()
            {
                return Err(FsError::NoDevice);
            }
            let boot = owner.as_ref().ok_or(FsError::NoDevice)?;
            let reader = boot.client_fence_reader().ok_or(FsError::NoDevice)?;
            reader.completed(2).map_err(|_| FsError::NoDevice)?;
            boot.access_vram(|| {
                // SAFETY: stage admission excludes reuse; OWNER excludes reset,
                // the current-generation SDMA fence completed and HDP was
                // invalidated. Both ranges are bounded and privately retained.
                unsafe { destination.read_staging(offset, map.virt as *const u8, bytes as usize) }
            })?;
        }
        offset += bytes;
        narf_scheduler::yield_now().await;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    Ok(())
}

async fn await_done(done: &Arc<dyn DrmFence>) -> Result<(), FsError> {
    let deadline = narf_time::monotonic_ns().saturating_add(5_000_000_000);
    while !done.is_signalled() {
        if narf_time::monotonic_ns() >= deadline {
            return Err(FsError::TimedOut);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
    }
    Ok(())
}
async fn await_last(binding: &Binding) -> Result<(), FsError> {
    let last = binding.last.lock().clone();
    if let Some(last) = last {
        await_done(&last).await?;
    }
    Ok(())
}

async fn upload(
    card: u32,
    object: &Arc<crate::amdgpu_gem::GemObject>,
    source: &Arc<crate::amdgpu_gem::GemPlacement>,
    destination: &Arc<crate::amdgpu_gem::GemPlacement>,
) -> Result<(), FsError> {
    let address = destination.hidden_address().ok_or(FsError::InvalidData)?;
    let binding = BINDING
        .lock()
        .as_ref()
        .filter(|bound| bound.card == card)
        .cloned()
        .ok_or(FsError::Unsupported)?;
    let _stage = binding.access.lock().await;
    // A cancelled predecessor may still have DMA in flight on the shared
    // stage. Never overwrite its bytes on the strength of a dropped waiter.
    await_last(&binding).await?;
    let mut offset = 0;
    while offset < source.byte_len {
        let bytes = (source.byte_len - offset).min(binding.stage.size());
        let held =
            Arc::new((object.clone(), source.clone(), destination.clone())) as Arc<dyn Send + Sync>;
        let done = engine().enqueue(
            KernelOp::Copy {
                src: binding.stage.address(),
                dst: address + offset,
                bytes,
            },
            Some(held),
            Some((source.clone(), offset)),
        )?;
        object
            .dma_buf()
            .resv
            .add_fence(done.clone(), narf_filesystem::dma_buf::DmaResvUsage::Kernel);
        *binding.last.lock() = Some(done.clone());
        await_done(&done).await?;
        offset += bytes;
        narf_scheduler::yield_now().await;
    }
    Ok(())
}

#[derive(Debug)]
struct Reader(u32);
impl crate::amdgpu_gem::VramTransfer for Reader {
    fn read<'a>(
        &'a self,
        object: Arc<crate::amdgpu_gem::GemObject>,
        source: Arc<crate::amdgpu_gem::GemPlacement>,
        destination: &'a mut crate::amdgpu_gem::GemPlacement,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    > {
        alloc::boxed::Box::pin(async move { readback(self.0, &object, &source, destination).await })
    }
    fn write<'a>(
        &'a self,
        object: Arc<crate::amdgpu_gem::GemObject>,
        source: Arc<crate::amdgpu_gem::GemPlacement>,
        destination: Arc<crate::amdgpu_gem::GemPlacement>,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    > {
        alloc::boxed::Box::pin(async move { upload(self.0, &object, &source, &destination).await })
    }
}
pub(crate) fn reader(card: u32) -> Arc<dyn crate::amdgpu_gem::VramTransfer> {
    Arc::new(Reader(card))
}

async fn run(
    op: KernelOp,
    upload: Option<&(Arc<crate::amdgpu_gem::GemPlacement>, u64)>,
) -> Result<(), FsError> {
    if !engine().active.load(Ordering::Acquire) {
        return Err(FsError::NoDevice);
    }
    let _power = crate::amdgpu_navi22_gfxoff::Reference::acquire()
        .await
        .map_err(|_| FsError::NoDevice)?;
    let (reader, epoch, seq) = loop {
        let observed = crate::amdgpu_fence_navi22::change_sequence();
        let result = {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            if !engine().active.load(Ordering::Acquire) {
                return Err(FsError::NoDevice);
            }
            let boot = owner.as_mut().ok_or(FsError::NoDevice)?;
            let reader = boot.client_fence_reader().ok_or(FsError::NoDevice)?;
            let epoch = crate::amdgpu_fence_navi22::generation();
            if let Some((source, offset)) = upload {
                let binding = BINDING.lock().as_ref().cloned().ok_or(FsError::NoDevice)?;
                let map = binding.stage.mapping();
                let KernelOp::Copy { src, bytes, .. } = op else {
                    return Err(FsError::InvalidData);
                };
                if src != binding.stage.address() || bytes > map.len {
                    return Err(FsError::InvalidData);
                }
                boot.access_vram(|| {
                    // SAFETY: source is retained and its move fence excludes user
                    // jobs. FIFO stage ownership excludes readers until completion;
                    // OWNER excludes reset while this CPU preparation runs.
                    unsafe { source.write_staging(*offset, map.virt as *mut u8, bytes as usize) }
                })?;
            }
            // SAFETY: callers queue only their owned allocator ranges. The
            // front remains retained/ordered until its real fence completes.
            match unsafe { boot.submit_vram(&[op]) } {
                Ok(seq) => Some(Ok((reader, epoch, seq))),
                Err(crate::amdgpu_navi22_boot::Error::Queues(
                    crate::amdgpu_cp_navi22::Error::Busy,
                )) => None,
                Err(_) => Some(Err(FsError::NoDevice)),
            }
        };
        if let Some(result) = result {
            break result?;
        }
        crate::amdgpu_fence_navi22::wait_change(
            observed,
            narf_time::monotonic_ns().saturating_add(100_000_000),
        )
        .await;
    };
    loop {
        let observed = crate::amdgpu_fence_navi22::change_sequence();
        if !engine().active.load(Ordering::Acquire)
            || epoch != crate::amdgpu_fence_navi22::generation()
        {
            return Err(FsError::NoDevice);
        }
        let done = reader.completed(2).map_err(|_| FsError::NoDevice)?;
        if !engine().active.load(Ordering::Acquire)
            || epoch != crate::amdgpu_fence_navi22::generation()
        {
            return Err(FsError::NoDevice);
        }
        if crate::amdgpu_fence_navi22::signaled(done, seq) {
            return Ok(());
        }
        // Retain power and request ownership while a submitted job can still
        // run. Reset/loss wakes this waiter; a timeout is never completion.
        crate::amdgpu_fence_navi22::wait_change(
            observed,
            narf_time::monotonic_ns().saturating_add(100_000_000),
        )
        .await;
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn rdna2_cancelled_copy_retains_backing_until_completion() -> TestResult {
        struct Held(Arc<AtomicBool>, Arc<Completion>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(!self.1.is_signalled(), Ordering::Release);
            }
        }
        let done = Arc::new(Completion(AtomicBool::new(false)));
        let retired = Arc::new(AtomicBool::new(false));
        let held = Arc::new(Held(retired.clone(), done.clone()));
        let mut state = State::default();
        state.queued.push_back(Request {
            op: KernelOp::Copy {
                src: 0x1000,
                dst: 0x2000,
                bytes: 4096,
            },
            done: done.clone(),
            held: Some(held.clone()),
            upload: None,
        });
        drop(held);
        state.kick();
        state.failed(state.pulse);
        if retired.load(Ordering::Acquire) || done.is_signalled() {
            return TestResult::Fail("failed or abandoned copy released live backing");
        }
        state.kick();
        state.complete();
        if !retired.load(Ordering::Acquire) || !done.is_signalled() {
            return TestResult::Fail("completion published before backing lease retirement");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2",
        rdna2_cancelled_copy_retains_backing_until_completion
    );

    fn rdna2_vram_queue_orders_recycled_ranges_across_recovery() -> TestResult {
        let first = Arc::new(Completion(AtomicBool::new(false)));
        let recycled = Arc::new(Completion(AtomicBool::new(false)));
        let op = KernelOp::Fill {
            dst: 0x9_0000_0000,
            bytes: MAX_PACKET_BYTES + 4096,
            value: 0,
        };
        let mut state = State::default();
        state.queued.push_back(Request {
            op,
            done: first.clone(),
            held: None,
            upload: None,
        });
        state.queued.push_back(Request {
            op,
            done: recycled.clone(),
            held: None,
            upload: None,
        });
        if !state.kick() {
            return TestResult::Fail("first clear did not start a drain");
        }
        let pulse = state.pulse;
        // Recovery publishes while the old drain is detecting its stale
        // generation. Its kick must survive the subsequent failure path.
        if state.kick()
            || !state.failed(pulse)
            || !state.draining
            || first.is_signalled()
            || recycled.is_signalled()
            || state.queued.len() != 2
        {
            return TestResult::Fail("recovery lost a kick or prematurely completed a clear");
        }
        if state.failed(state.pulse) || state.draining || !state.kick() {
            return TestResult::Fail("failed drain could not be restarted");
        }
        if chunk(op, MAX_PACKET_BYTES)
            != Some(KernelOp::Fill {
                dst: 0x9_4000_0000,
                bytes: 4096,
                value: 0,
            })
            || chunk(op, MAX_PACKET_BYTES + 4096).is_some()
        {
            return TestResult::Fail("large clear lost its final chunk");
        }
        state.complete();
        if !first.is_signalled()
            || recycled.is_signalled()
            || state.queued.front().unwrap().op != op
        {
            return TestResult::Fail("recycled-range clear overtook its predecessor");
        }
        state.complete();
        if !recycled.is_signalled() || !state.queued.is_empty() {
            return TestResult::Fail("last ordered clear did not retire");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2",
        rdna2_vram_queue_orders_recycled_ranges_across_recovery
    );
}

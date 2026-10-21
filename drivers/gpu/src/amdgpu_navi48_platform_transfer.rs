//! Migration of `NO_CPU_ACCESS` buffers between VRAM past the BAR and private
//! system backing (`amdgpu_gem::VramTransfer`), as the RX 6000 path does:
//! SDMA0 copies each chunk through a CPU-visible stage. Copies share the
//! clear FIFO, so one never overtakes an earlier clear of the same range,
//! and an SDMA0 reset requeues (and re-stages) them like skipped clears.
//! GFX12 DCC buffers move the same way from any VRAM (visible or past the
//! BAR), with amdgpu_ttm_copy_mem_to_mem's copy flags: SDMA0 reads VRAM
//! decompressed into the stage, and writes VRAM compressed from it with
//! the buffer's tiling-flag DCC parameters (sdma_v7_0_emit_copy_buffer's
//! DCC word), as Linux's move blit reads and writes it.
use super::*;
use narf_filesystem::{dma_buf::DmaResvUsage, FsError};

/// The kernel's CPU-mapped transfer window. Each queued/inflight request
/// retains it independently of its mover or caller. Once its last owner
/// drops, the published reservation stays retired until a proven reset.
struct Stage {
    _window: crate::amdgpu_vram::Reservation,
    address: u64,
    virt: usize,
    len: u64,
    /// One migration uses the window at a time.
    access: Mutex<()>,
    /// The last chunk queued through the window, cancelled waiter or not.
    last: narf_lib::sync::IrqSafeSpinLock<Option<Arc<ClearFence>>>,
}
#[derive(Clone)]
struct Mover {
    clearer: VramClearer,
    stage: Arc<Stage>,
}
impl core::fmt::Debug for Mover {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mover")
            .field("stage", &self.stage.address)
            .finish_non_exhaustive()
    }
}
pub(super) fn mover(
    clearer: VramClearer,
    mut window: crate::amdgpu_vram::Reservation,
) -> Arc<dyn crate::amdgpu_gem::VramTransfer> {
    // Published for good: SDMA0 may reach it after any waiter is dropped.
    window.publish();
    let map = window.mapping();
    let stage = Stage {
        address: window.address(),
        virt: map.virt as usize,
        len: map.len.min(window.size()),
        _window: window,
        access: Mutex::new(()),
        last: narf_lib::sync::IrqSafeSpinLock::new(None),
    };
    Arc::new(Mover {
        clearer,
        stage: Arc::new(stage),
    })
}

impl VramClearer {
    /// Queue one copy behind every earlier fill/copy; `held` stays retained
    /// until the copy leaves the ring.
    fn enqueue(&self, work: Work, held: Arc<dyn Send + Sync>) -> Result<Arc<ClearFence>, FsError> {
        let Work::Copy {
            src, dst, bytes, ..
        } = work
        else {
            return Err(FsError::InvalidData);
        };
        if bytes == 0
            || bytes > crate::amdgpu_sdma_navi48::MAX_PACKET_BYTES
            || src.max(dst) - src.min(dst) < bytes
        {
            return Err(FsError::InvalidData);
        }
        if crate::amdgpu_navi48_interrupts::failed() || (self.0.progress)().is_none() {
            return Err(FsError::NoDevice);
        }
        let fence = Arc::new(ClearFence::new(self.0.progress.clone()));
        let start = {
            let mut state = self.0.state.lock();
            state.queued.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            state.queued.push_back(Clear {
                work,
                fence: fence.clone(),
                _held: Some(held),
            });
            !core::mem::replace(&mut state.draining, true)
        };
        if start {
            narf_scheduler::spawn(self.clone().drain());
        }
        Ok(fence)
    }
}

/// Transfer completion needs a same-generation hardware sequence. The
/// generic fence's lost-device wakeup releases waiters but cannot prove
/// that the copy landed. A blocked ring must not be sampled.
fn completed(done: &ClearFence, blocked: bool) -> Result<bool, FsError> {
    if done.gone.load(Ordering::Acquire) {
        return Err(FsError::NoDevice);
    }
    if blocked {
        return Ok(false);
    }
    let progress = (done.progress)().ok_or(FsError::NoDevice)?;
    let seq = done.seq.load(Ordering::Acquire);
    Ok(seq != u64::MAX && progress.wrapping_sub(seq as u32) as i32 >= 0)
}

/// The chunk's fence, bounded like the RX 6000 mover. A refused job or a
/// lost generation is an error, never a completed copy.
async fn await_done(clearer: &VramClearer, done: &ClearFence) -> Result<(), FsError> {
    let deadline = narf_time::monotonic_ns().saturating_add(5_000_000_000);
    loop {
        if completed(done, crate::amdgpu_navi48_interrupts::blocked())? {
            let owner = OWNER.lock().await;
            owner.as_ref().ok_or(FsError::NoDevice)?;
            if crate::amdgpu_navi48_interrupts::blocked() {
                return Err(FsError::NoDevice);
            }
            let progress = clearer.live_progress()?;
            let seq = done.seq.load(Ordering::Acquire);
            if done.gone.load(Ordering::Acquire) {
                return Err(FsError::NoDevice);
            }
            // A partial-ring reset can requeue a previously sampled slot.
            // Recheck its current sequence under OWNER before retirement.
            if seq != u64::MAX && progress.wrapping_sub(seq as u32) as i32 >= 0 {
                clearer.retire_completed(progress);
                return Ok(());
            }
        }
        if narf_time::monotonic_ns() >= deadline {
            return Err(FsError::TimedOut);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
    }
}

impl Mover {
    /// A cancelled predecessor may still have DMA in flight on the window.
    async fn settle(&self) -> Result<(), FsError> {
        let last = self.stage.last.lock().clone();
        if let Some(last) = last {
            await_done(&self.clearer, &last).await?;
        }
        Ok(())
    }
    fn queue(
        &self,
        object: &Arc<crate::amdgpu_gem::GemObject>,
        work: Work,
        held: Arc<dyn Send + Sync>,
    ) -> Result<Arc<ClearFence>, FsError> {
        let held = Arc::new((held, self.stage.clone())) as Arc<dyn Send + Sync>;
        let done = self.clearer.enqueue(work, held)?;
        object
            .dma_buf()
            .resv
            .add_fence(done.clone(), DmaResvUsage::Kernel);
        *self.stage.last.lock() = Some(done.clone());
        Ok(done)
    }
    async fn read(
        &self,
        object: &Arc<crate::amdgpu_gem::GemObject>,
        source: &Arc<crate::amdgpu_gem::GemPlacement>,
        destination: &mut crate::amdgpu_gem::GemPlacement,
    ) -> Result<(), FsError> {
        let address = source.vram_address().ok_or(FsError::InvalidData)?;
        // VRAM to system memory: the stage stands in for the GTT side.
        let flags = crate::amdgpu_gem::ttm_copy_flags(object, true, false);
        let _stage = self.stage.access.lock().await;
        self.settle().await?;
        let mut offset = 0;
        while offset < source.byte_len {
            let bytes = (source.byte_len - offset).min(self.stage.len);
            let held = Arc::new((object.clone(), source.clone())) as Arc<dyn Send + Sync>;
            let work = Work::Copy {
                src: address + offset,
                dst: self.stage.address,
                bytes,
                flags,
                upload: None,
            };
            let done = self.queue(object, work, held)?;
            await_done(&self.clearer, &done).await?;
            {
                let owner = OWNER.lock().await;
                let boot = owner.as_ref().ok_or(FsError::NoDevice)?;
                // The fence is this generation's: a reset since would have
                // made progress None and the request gone or requeued.
                if crate::amdgpu_navi48_interrupts::blocked()
                    || (self.clearer.0.progress)().is_none()
                {
                    return Err(FsError::NoDevice);
                }
                boot.access_vram(|| {
                    // SAFETY: the stage lock excludes reuse, the chunk's SDMA0
                    // fence completed and OWNER excludes reset. Both ranges
                    // are bounded and privately retained.
                    unsafe {
                        destination.read_staging(
                            offset,
                            self.stage.virt as *const u8,
                            bytes as usize,
                        )
                    }
                })?;
            }
            offset += bytes;
            narf_scheduler::yield_now().await;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn write(
        &self,
        object: &Arc<crate::amdgpu_gem::GemObject>,
        source: &Arc<crate::amdgpu_gem::GemPlacement>,
        destination: &Arc<crate::amdgpu_gem::GemPlacement>,
    ) -> Result<(), FsError> {
        let address = destination.vram_address().ok_or(FsError::InvalidData)?;
        // System memory to VRAM: the stage stands in for the GTT side.
        let flags = crate::amdgpu_gem::ttm_copy_flags(object, false, true);
        let _stage = self.stage.access.lock().await;
        self.settle().await?;
        let mut offset = 0;
        while offset < source.byte_len {
            let bytes = (source.byte_len - offset).min(self.stage.len);
            let held = Arc::new((object.clone(), source.clone(), destination.clone()))
                as Arc<dyn Send + Sync>;
            let work = Work::Copy {
                src: self.stage.address,
                dst: address + offset,
                bytes,
                flags,
                upload: Some((source.clone(), offset, self.stage.virt)),
            };
            let done = self.queue(object, work, held)?;
            await_done(&self.clearer, &done).await?;
            offset += bytes;
            narf_scheduler::yield_now().await;
        }
        // A reset may have happened after the final chunk signalled but
        // before this task resumed. Validate under OWNER before relocation
        // can publish the new placement/PTEs; the old source stays intact
        // on a lost generation.
        let owner = OWNER.lock().await;
        owner.as_ref().ok_or(FsError::NoDevice)?;
        if crate::amdgpu_navi48_interrupts::blocked() {
            return Err(FsError::NoDevice);
        }
        self.clearer.with_live_progress(|| Ok(()))?;
        Ok(())
    }
}
impl crate::amdgpu_gem::VramTransfer for Mover {
    fn read<'a>(
        &'a self,
        object: Arc<crate::amdgpu_gem::GemObject>,
        source: Arc<crate::amdgpu_gem::GemPlacement>,
        destination: &'a mut crate::amdgpu_gem::GemPlacement,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    > {
        alloc::boxed::Box::pin(
            async move { Mover::read(self, &object, &source, destination).await },
        )
    }
    fn write<'a>(
        &'a self,
        object: Arc<crate::amdgpu_gem::GemObject>,
        source: Arc<crate::amdgpu_gem::GemPlacement>,
        destination: Arc<crate::amdgpu_gem::GemPlacement>,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    > {
        alloc::boxed::Box::pin(
            async move { Mover::write(self, &object, &source, &destination).await },
        )
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_transfer_tests.rs"]
mod tests;

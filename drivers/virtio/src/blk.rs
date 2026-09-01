//! narf-drivers-virtio — virtio-blk device driver.
//!
//! Spec: VirtIO 1.2 §5.2 (Block Device).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! MSI-X queue mapping (VirtIO 1.2 §4.1.5.1.3 — `queue_msix_vector`):
//! the modern PCI transport's common-cfg lets us bind one MSI-X
//! vector per virtqueue. virtio-blk has a single request virtqueue
//! (queue 0), so this driver allocates one IDT vector and writes
//! `queue_msix_vector = 0` against `queue_select = 0`. After
//! `enable_msix`, `submit_async` builds the `WaitForIrq` future
//! BEFORE ringing the queue-notify doorbell — required so a
//! synchronously-delivered MSI-X (QEMU completes virtio-blk reads
//! inline on `kick`) cannot slip past the waiter's baseline.
//!
//! The polled `poll()` path is preserved unchanged for callers that
//! drive completion from a pump task instead of an IRQ.

use alloc::collections::BTreeMap;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::pci::{discover, map_cap, VirtioPciError};
use crate::{
    queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE},
    VirtioMmioDevice,
};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};
use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};
use narf_bus::{BusDevice, BusDeviceCap, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer, GetPhysAddr};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// Virtqueue index for the virtio-blk request queue. virtio-blk has
/// a single request queue per VirtIO 1.2 §5.2.2.
const REQUEST_QUEUE: u16 = 0;

/// A VirtIO block device.
#[derive(Debug)]
pub struct VirtioBlkDevice {
    mmio: VirtioMmioDevice,
    /// Shared state between submit and completion.
    inner: IrqSafeSpinLock<Option<VirtioBlkInner>>,
    /// DMA buffer backing the virtqueue.
    queue_buf: Option<DmaBuffer>,
    /// DMA pool for request headers and status bytes.
    pool: Option<DmaPool>,
    /// IDT vector bound to the request virtqueue when MSI-X is
    /// enabled. `None` means polled-only completion. Async callers
    /// observe completion via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())`.
    pub irq_vector: Option<u8>,
    /// MSI-X table mapping kept alive for the lifetime of the device
    /// so the programmed vector stays delivered.
    msix: Option<MsixTable>,
}

#[derive(Debug)]
struct VirtioBlkInner {
    queue: Virtqueue,
    /// In-flight requests, keyed by the head descriptor index.
    requests: BTreeMap<u16, InFlightRequest>,
}

// SAFETY: VirtioBlkInner owns its Virtqueue (already Send) and a BTreeMap of
// bookkeeping; the only raw pointers are inside the Virtqueue, which controls
// its own DMA memory. Moving the struct across threads moves these owned values
// without creating aliases, so transferring ownership is sound.
unsafe impl Send for VirtioBlkInner {}
// SAFETY: VirtioBlkInner is only ever accessed behind the device's
// IrqSafeSpinLock, which serialises all shared access, so &VirtioBlkInner is
// never used to mutate the rings concurrently.
unsafe impl Sync for VirtioBlkInner {}
// SAFETY: VirtioBlkDevice owns MMIO/DMA resources (mmio register window, queue
// buffer, DMA pool, MSI-X table) plus an IrqSafeSpinLock guarding the inner
// state. These are owned, not borrowed, so moving the device to another thread
// does not alias any of them.
unsafe impl Send for VirtioBlkDevice {}
// SAFETY: all mutable device state lives behind `inner`'s IrqSafeSpinLock;
// MMIO register accesses are volatile and the spinlock serialises queue
// submission/completion, so &VirtioBlkDevice can be shared across threads.
unsafe impl Sync for VirtioBlkDevice {}

#[derive(Debug)]
struct InFlightRequest {
    _user_tag: u64,
    waker: Option<Waker>,
    /// Index in the DmaPool for header and status.
    pool_idx: usize,
}

#[derive(Debug)]
pub enum VirtioError {
    NoMemory,
    DeviceRejectedFeatures,
    NoQueues,
    UnsupportedVersion,
    QueueTooLarge,
    /// MSI-X programming failed — typically because the underlying
    /// transport isn't PCIe (virtio-mmio uses a single legacy IRQ
    /// line and has no MSI-X capability).
    NoMsix,
}

/// A simple pool of DMA-safe buffers for virtio-blk request headers
/// and status bytes. Each request needs a header (16 bytes) and a
/// status byte (1 byte).
#[derive(Debug)]
struct DmaPool {
    buf: DmaBuffer,
    /// Bitmap of free slots. Each slot is 64 bytes to ensure alignment.
    free: narf_lib::bitmap::Bitmap<64>, // 64 * 64 = 4096 (one page)
}

impl DmaPool {
    fn new(buf: DmaBuffer) -> Self {
        Self {
            buf,
            free: narf_lib::bitmap::Bitmap::new_full(),
        }
    }

    fn alloc(&mut self) -> Option<usize> {
        let idx = self.free.first_set()?;
        self.free.clear(idx);
        Some(idx)
    }

    fn free(&mut self, idx: usize) {
        self.free.set(idx);
    }

    /// CPU-side pointers. These are dereferenced HERE, so they must be
    /// direct-map; `header_phys`/`status_phys` below are the DEVICE side and
    /// stay physical. Previously both pairs came off `dma_addr()`, so the
    /// header/status writes landed at the physical address interpreted as a
    /// virtual one — which silently worked on a kernel CR3 and, once user
    /// address spaces stopped carrying the identity map, wrote into user
    /// memory while the device still read a stale header.
    fn header_ptr(&self, idx: usize) -> *mut VirtioBlkHeader {
        self.buf
            .cpu_mut_ptr_at::<VirtioBlkHeader>((idx * 64) as u64)
    }

    fn status_ptr(&self, idx: usize) -> *mut u8 {
        self.buf.cpu_mut_ptr_at::<u8>((idx * 64 + 16) as u64)
    }

    fn header_phys(&self, idx: usize) -> u64 {
        self.buf.dma_addr().raw() + (idx * 64) as u64
    }

    fn status_phys(&self, idx: usize) -> u64 {
        self.buf.dma_addr().raw() + (idx * 64 + 16) as u64
    }
}

impl VirtioBlkDevice {
    /// Create a new VirtIO block device from a probed transport.
    pub fn new(mmio: VirtioMmioDevice) -> Self {
        Self {
            mmio,
            inner: IrqSafeSpinLock::new(None),
            queue_buf: None,
            pool: None,
            irq_vector: None,
            msix: None,
        }
    }

    /// Initialise the device and its primary virtqueue.
    ///
    /// # Safety
    /// The `mmio` transport captured by this device must point at a live,
    /// correctly mapped virtio-blk MMIO register window (a real virtio-blk
    /// device probed via [`VirtioMmioDevice`]); this function performs the
    /// device reset/feature-negotiation handshake and programs queue base
    /// addresses by writing to those registers. `domain` must be a valid IOMMU
    /// domain for the DMA allocations. Calling this with bogus MMIO or while
    /// another agent drives the same device is undefined behaviour.
    pub unsafe fn init(&mut self, domain: DomainId) -> Result<(), VirtioError> {
        // 1. Reset device.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, 0);
        // 2. Set ACKNOWLEDGE status bit.
        self.mmio
            .write_u32(VirtioMmioDevice::REG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        // 3. Set DRIVER status bit.
        self.mmio.write_u32(
            VirtioMmioDevice::REG_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // 4. Feature negotiation.
        let features = self.mmio.read_u32(VirtioMmioDevice::REG_DEVICE_FEATURES);
        if (features & (VIRTIO_F_VERSION_1 as u32)) == 0 {
            return Err(VirtioError::UnsupportedVersion);
        }
        self.mmio.write_u32(
            VirtioMmioDevice::REG_DRIVER_FEATURES,
            VIRTIO_F_VERSION_1 as u32,
        );

        // 5. Set FEATURES_OK.
        self.mmio.write_u32(
            VirtioMmioDevice::REG_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        );
        if (self.mmio.read_u32(VirtioMmioDevice::REG_STATUS) & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return Err(VirtioError::DeviceRejectedFeatures);
        }

        // 6. Virtqueue setup.
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_SEL, 0);
        let max_size = self.mmio.read_u32(VirtioMmioDevice::REG_QUEUE_NUM_MAX);
        if max_size == 0 {
            return Err(VirtioError::NoQueues);
        }
        let queue_size = core::cmp::min(max_size as u16, 64);
        self.mmio
            .write_u32(VirtioMmioDevice::REG_QUEUE_NUM, queue_size as u32);

        let q_buf = alloc_coherent(4096, domain).map_err(|_| VirtioError::NoMemory)?;
        let q_ptr = q_buf.dma_addr().raw();

        let layout = VirtqueueLayout::new(queue_size, q_ptr).ok_or(VirtioError::QueueTooLarge)?;

        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DESC_LOW,
            layout.desc_table as u32,
        );
        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DESC_HIGH,
            (layout.desc_table >> 32) as u32,
        );
        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DRIVER_LOW,
            layout.avail_ring as u32,
        );
        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DRIVER_HIGH,
            (layout.avail_ring >> 32) as u32,
        );
        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DEVICE_LOW,
            layout.used_ring as u32,
        );
        self.mmio.write_u32(
            VirtioMmioDevice::REG_QUEUE_DEVICE_HIGH,
            (layout.used_ring >> 32) as u32,
        );

        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_READY, 1);

        // 7. Set DRIVER_OK.
        self.mmio.write_u32(
            VirtioMmioDevice::REG_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );

        let p_buf = alloc_coherent(4096, domain).map_err(|_| VirtioError::NoMemory)?;
        self.pool = Some(DmaPool::new(p_buf));
        self.queue_buf = Some(q_buf);
        *self.inner.lock() = Some(VirtioBlkInner {
            // SAFETY: `layout` was just produced by VirtqueueLayout::new over
            // `q_buf`, a freshly allocated DMA-coherent page that we own and
            // keep alive in `self.queue_buf`, so the memory it describes is
            // device-accessible for the queue's lifetime.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            queue: unsafe { Virtqueue::new(layout) },
            requests: BTreeMap::new(),
        });

        Ok(())
    }

    /// Bind the request virtqueue (queue 0) to a fresh MSI-X vector.
    /// After this call, completion is observable via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())` and
    /// `submit_async` uses the IRQ path. The polled `poll()` keeps
    /// working unchanged.
    ///
    /// Per VirtIO 1.2 §4.1.5.1.3, this writes `queue_select = 0`
    /// followed by `queue_msix_vector = 0` on the modern PCI common
    /// configuration so the device delivers the MSI-X it was
    /// programmed with on used-ring activity for queue 0. The actual
    /// programming is delegated to `crate::pci::enable_msix_queue`,
    /// the canonical virtio MSI-X path shared with virtio-net etc.
    ///
    /// Returns `VirtioError::NoMsix` if the device lacks MSI-X (most
    /// commonly: `device.kind` is `BusKind::VirtioMmio` rather than
    /// PCIe). The legacy MMIO transport has no MSI-X capability and
    /// callers should keep using the polled `poll()` drain.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively for the
    /// duration of this call.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioError> {
        // Discover the virtio-PCI capability list and map the
        // common-cfg region. Both fail cleanly (and surface as
        // `NoMsix`) if the device isn't a virtio-PCI transport.
        // SAFETY: caller asserts exclusive ownership of cfg-space.
        let caps = unsafe { discover(device) }.map_err(|_| VirtioError::NoMsix)?;
        // SAFETY: caller-owned device; cap describes a real BAR slot.
        let common = unsafe { map_cap(device, &caps.common) }.map_err(|_| VirtioError::NoMsix)?;
        let (vector, table) =
            // SAFETY: caller-owned device; common is a freshly mapped
            // BAR-backed region we exclusively reference through the local
            // `common` binding.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { crate::pci::enable_msix_queue(&common, cap, device, REQUEST_QUEUE) }
                .map_err(map_msix_err)?;

        // Install a no-op sync handler. `wait_for_irq` is driven by
        // the dispatch table's `fire_count` bump that happens
        // unconditionally inside `on_irq`, so the handler body can be
        // empty — the async submit path drains the used ring after
        // the await resolves.
        narf_interrupts::install_handler(vector, blk_irq_noop);

        self.irq_vector = Some(vector);
        self.msix = Some(table);
        Ok(vector)
    }

    /// Poll for completions.
    pub fn poll(&self) {
        let mut inner_guard = self.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard {
            i
        } else {
            return;
        };

        while let Some((id, _len)) = inner.queue.poll_used() {
            if let Some(mut req) = inner.requests.remove(&(id as u16)) {
                // SAFETY: `inner_guard` (the IrqSafeSpinLock on `self.inner`)
                // is held for this whole function, serialising every path that
                // touches `self.pool`; thus this raw &mut to the Option is the
                // only live mutable access. The pointer is to our own field.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                let pool_slot = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() };
                if let Some(ref mut pool) = pool_slot {
                    pool.free(req.pool_idx);
                }

                if let Some(waker) = req.waker.take() {
                    waker.wake();
                }
                inner.queue.free_chain(id as u16);
            }
        }
    }

    /// Submit a request and await completion via MSI-X. The
    /// `WaitForIrq` future is constructed BEFORE the queue-notify
    /// doorbell write so a synchronously-delivered MSI-X (QEMU
    /// completes virtio-blk reads inline on `kick`) cannot fire
    /// between submit + await — the future's baseline snapshot of
    /// `fire_count` happens in `wait_for_irq()`'s constructor before
    /// the device sees the avail-ring update.
    ///
    /// Falls back to the polled completion path (just calls
    /// `submit().await`, relying on an external pump to call
    /// `poll()`) when MSI-X is not enabled.
    pub async fn submit_async(&self, req: BlockRequest) -> BlockCompletion {
        // Take a snapshot of the IRQ vector before submitting so the
        // waiter exists with the correct baseline fire-count even if
        // the device completes the request synchronously inside the
        // doorbell write (QEMU virtio-blk does this for cached I/O).
        // Pattern mirrors `drivers/nvme/src/lib.rs::submit_io_irq` and
        // `drivers/virtio/src/blk_pci.rs::read_sector_irq_async`.
        //
        // 5-second deadline on the IRQ wait — typical virtio-blk
        // completions land in microseconds; this is the "device
        // wedged / lost MSI / EC quirk" fallback that keeps a dead
        // device from parking the await forever.
        let waiter = self
            .irq_vector
            .map(|v| narf_interrupts::wait_for_irq_until(v, narf_time::Deadline::after_ms(5_000)));
        let fut = self.submit(req);
        if let Some(w) = waiter {
            // Await the IRQ (or timeout) first so we don't busy-poll
            // the used ring. The sync handler is a no-op, but
            // `on_irq` bumps `fire_count` which resolves the
            // inner `WaitForIrq`. On timeout we still attempt the
            // ring drain — the request may have completed but the
            // MSI never landed (wedged interrupt remap, EC quirk),
            // and `self.poll()` can still surface it.
            let _ = w.await;
            // Drain the used ring + wake the per-request waker.
            self.poll();
        }
        // The Future returned by `submit` is the source of truth for
        // the completion. Whether MSI-X drove the wake or the caller's
        // pump did, the future resolves once `poll()` removes the
        // request from `requests`.
        fut.await
    }
}

fn map_msix_err(e: VirtioPciError) -> VirtioError {
    match e {
        VirtioPciError::NotPcie | VirtioPciError::NoVendorCap | VirtioPciError::NoCommonCfg => {
            VirtioError::NoMsix
        }
        _ => VirtioError::NoMsix,
    }
}

/// Sync ISR for the virtio-blk request virtqueue. Body intentionally
/// empty: `narf_interrupts::dispatch::on_irq` increments `fire_count`
/// before invoking this handler, which is the only thing
/// `wait_for_irq.await` observes. The async submit path drains the
/// used ring after the await resolves.
fn blk_irq_noop() {}

impl BlockDevice for VirtioBlkDevice {
    fn logical_block_size(&self) -> u32 {
        512
    }
    fn physical_block_size(&self) -> u32 {
        512
    }
    fn capacity_blocks(&self) -> u64 {
        0
    }
    fn supports(&self, _feat: BlockFeature) -> bool {
        false
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> {
        let mut inner_guard = self.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard {
            i
        } else {
            return BlkRequestFuture::error(req.user_tag, BlockError::DeviceRemoved);
        };

        let pool_idx = if let Some(ref mut pool) =
            // SAFETY: `inner_guard` is held for the rest of `submit`, serialising
            // all access to `self.pool`; this raw &mut to our own field's Option is
            // therefore the only live mutable borrow.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() }
        {
            if let Some(idx) = pool.alloc() {
                idx
            } else {
                return BlkRequestFuture::error(req.user_tag, BlockError::IOError);
            }
        } else {
            return BlkRequestFuture::error(req.user_tag, BlockError::DeviceRemoved);
        };

        let type_tag = match req.op {
            BlockOp::Read => VIRTIO_BLK_T_IN,
            BlockOp::Write { .. } => VIRTIO_BLK_T_OUT,
            BlockOp::WriteZeroes => VIRTIO_BLK_T_OUT,
            BlockOp::Trim => VIRTIO_BLK_T_DISCARD,
        };

        let pool = self.pool.as_ref().unwrap();
        let header_phys = pool.header_phys(pool_idx);
        let status_phys = pool.status_phys(pool_idx);

        // SAFETY: `pool_idx` was just returned by `pool.alloc()`, so slot
        // `pool_idx` is reserved for this request. `header_ptr`/`status_ptr`
        // compute in-bounds, correctly aligned offsets (idx*64 / idx*64+16)
        // into the DMA-coherent pool page we own, and the lock guarantees no
        // other writer touches this slot.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let h_ptr = pool.header_ptr(pool_idx);
            *h_ptr = VirtioBlkHeader {
                type_tag,
                reserved: 0,
                sector: req.lba,
            };
            let s_ptr = pool.status_ptr(pool_idx);
            *s_ptr = 0xFF; // Pending
        }

        let buffer_phys = match req.buffer.invoke(GetPhysAddr) {
            Ok(p) => p.raw(),
            Err(_) => {
                // SAFETY: `inner_guard` is still held, serialising all
                // access to `self.pool`; this raw &mut to our own field is the
                // only live mutable borrow as we roll back the allocation.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                let pool_slot = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() };
                if let Some(ref mut pool) = pool_slot {
                    pool.free(pool_idx);
                }
                return BlkRequestFuture::error(req.user_tag, BlockError::PermissionDenied);
            }
        };

        let mut descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: buffer_phys,
                len: req.blocks * 512,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];

        if req.op == BlockOp::Read {
            descs[1].flags |= VIRTQ_DESC_F_WRITE;
        }

        if let Some(id) = inner.queue.add_buffer(&descs) {
            inner.requests.insert(
                id,
                InFlightRequest {
                    _user_tag: req.user_tag,
                    waker: None,
                    pool_idx,
                },
            );

            self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_NOTIFY, 0);

            BlkRequestFuture {
                device: Some(self),
                head_id: Some(id),
                user_tag: req.user_tag,
            }
        } else {
            // SAFETY: `inner_guard` is still held, serialising all access to
            // `self.pool`; this raw &mut to our own field is the only live
            // mutable borrow as we roll back the allocation.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            if let Some(ref mut pool) = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() } {
                pool.free(pool_idx);
            }
            BlkRequestFuture::error(req.user_tag, BlockError::IOError)
        }
    }

    fn flush(&self) -> impl Future<Output = ()> {
        core::future::ready(())
    }
    fn discard(&self, _range: LbaRange) -> impl Future<Output = ()> {
        core::future::ready(())
    }
    fn cancel(&self, _tag: u64) -> impl Future<Output = CancelResult> {
        core::future::ready(CancelResult::NotFound)
    }
}

struct BlkRequestFuture<'a> {
    device: Option<&'a VirtioBlkDevice>,
    head_id: Option<u16>,
    user_tag: u64,
}

impl<'a> BlkRequestFuture<'a> {
    fn error(user_tag: u64, _err: BlockError) -> Self {
        Self {
            device: None,
            head_id: None,
            user_tag,
        }
    }
}

impl<'a> Future for BlkRequestFuture<'a> {
    type Output = BlockCompletion;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (device, id) = match (self.device, self.head_id) {
            (Some(d), Some(id)) => (d, id),
            _ => {
                return Poll::Ready(BlockCompletion {
                    tag: 0,
                    user_tag: self.user_tag,
                    result: Err(BlockError::DeviceRemoved),
                })
            }
        };

        let mut inner_guard = device.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard {
            i
        } else {
            return Poll::Ready(BlockCompletion {
                tag: 0,
                user_tag: self.user_tag,
                result: Err(BlockError::DeviceRemoved),
            });
        };

        if let Some(req) = inner.requests.get_mut(&id) {
            req.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(BlockCompletion {
                tag: id as u64,
                user_tag: self.user_tag,
                result: Ok(()),
            })
        }
    }
}

/// VirtIO Block Device Identification.
pub const VIRTIO_ID_BLOCK: u32 = 2;

/// Request types for virtio-blk.
pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;

/// Request header for virtio-blk.
/// VirtIO 1.2 §5.2.6.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioBlkHeader {
    /// VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, etc.
    pub type_tag: u32,
    pub reserved: u32,
    /// Sector to read from or write to.
    pub sector: u64,
}

/// Status byte for virtio-blk.
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

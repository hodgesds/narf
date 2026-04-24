//! narf-drivers-virtio — virtio-blk device driver.
//!
//! Spec: `drivers/virtio/specification/spec.md`. Stage 3 subset:
//! block-device trait implementation, feature negotiation skeleton,
//! and request submission via virtqueue.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use alloc::collections::BTreeMap;

use narf_block::{BlockCompletion, BlockDevice, BlockFeature, BlockRequest, CancelResult, LbaRange, BlockError, BlockOp};
use crate::{VirtioMmioDevice, queue::{Virtqueue, VirtqDesc, VIRTQ_DESC_F_WRITE, VirtqueueLayout}};
use crate::{VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_FEATURES_OK, VIRTIO_STATUS_DRIVER_OK, VIRTIO_F_VERSION_1};
use narf_io::{DmaBuffer, alloc_coherent, GetPhysAddr};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

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
}

#[derive(Debug)]
struct VirtioBlkInner {
    queue: Virtqueue,
    /// In-flight requests, keyed by the head descriptor index.
    requests: BTreeMap<u16, InFlightRequest>,
}

unsafe impl Send for VirtioBlkInner {}
unsafe impl Sync for VirtioBlkInner {}
unsafe impl Send for VirtioBlkDevice {}
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
        Self { buf, free: narf_lib::bitmap::Bitmap::new_full() }
    }

    fn alloc(&mut self) -> Option<usize> {
        let idx = self.free.first_set()?;
        self.free.clear(idx);
        Some(idx)
    }

    fn free(&mut self, idx: usize) {
        self.free.set(idx);
    }

    fn header_ptr(&self, idx: usize) -> *mut VirtioBlkHeader {
        (self.buf.phys_addr().raw() + (idx * 64) as u64) as *mut _
    }

    fn status_ptr(&self, idx: usize) -> *mut u8 {
        (self.buf.phys_addr().raw() + (idx * 64 + 16) as u64) as *mut _
    }

    fn header_phys(&self, idx: usize) -> u64 {
        self.buf.phys_addr().raw() + (idx * 64) as u64
    }

    fn status_phys(&self, idx: usize) -> u64 {
        self.buf.phys_addr().raw() + (idx * 64 + 16) as u64
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
        }
    }

    /// Initialise the device and its primary virtqueue.
    pub unsafe fn init(&mut self, domain: DomainId) -> Result<(), VirtioError> {
        // 1. Reset device.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, 0);
        // 2. Set ACKNOWLEDGE status bit.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        // 3. Set DRIVER status bit.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        // 4. Feature negotiation.
        let features = self.mmio.read_u32(VirtioMmioDevice::REG_DEVICE_FEATURES);
        if (features & (VIRTIO_F_VERSION_1 as u32)) == 0 {
            return Err(VirtioError::UnsupportedVersion);
        }
        self.mmio.write_u32(VirtioMmioDevice::REG_DRIVER_FEATURES, VIRTIO_F_VERSION_1 as u32);
        
        // 5. Set FEATURES_OK.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
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
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_NUM, queue_size as u32);

        let q_buf = alloc_coherent(4096, domain).map_err(|_| VirtioError::NoMemory)?;
        let q_ptr = q_buf.phys_addr().raw();

        let layout = VirtqueueLayout::new(queue_size, q_ptr).ok_or(VirtioError::QueueTooLarge)?;

        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DESC_LOW, layout.desc_table as u32);
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DESC_HIGH, (layout.desc_table >> 32) as u32);
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DRIVER_LOW, layout.avail_ring as u32);
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DRIVER_HIGH, (layout.avail_ring >> 32) as u32);
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DEVICE_LOW, layout.used_ring as u32);
        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_DEVICE_HIGH, (layout.used_ring >> 32) as u32);

        self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_READY, 1);

        // 7. Set DRIVER_OK.
        self.mmio.write_u32(VirtioMmioDevice::REG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

        let p_buf = alloc_coherent(4096, domain).map_err(|_| VirtioError::NoMemory)?;
        self.pool = Some(DmaPool::new(p_buf));
        self.queue_buf = Some(q_buf);
        *self.inner.lock() = Some(VirtioBlkInner {
            queue: unsafe { Virtqueue::new(layout) },
            requests: BTreeMap::new(),
        });

        Ok(())
    }

    /// Poll for completions.
    pub fn poll(&self) {
        let mut inner_guard = self.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard { i } else { return; };

        while let Some((id, _len)) = inner.queue.poll_used() {
            if let Some(mut req) = inner.requests.remove(&(id as u16)) {
                if let Some(ref mut pool) = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() } {
                    pool.free(req.pool_idx);
                }

                if let Some(waker) = req.waker.take() {
                    waker.wake();
                }
                inner.queue.free_chain(id as u16);
            }
        }
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn logical_block_size(&self) -> u32 { 512 }
    fn physical_block_size(&self) -> u32 { 512 }
    fn capacity_blocks(&self) -> u64 { 0 }
    fn supports(&self, _feat: BlockFeature) -> bool { false }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> {
        let mut inner_guard = self.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard { i } else {
            return BlkRequestFuture::error(req.user_tag, BlockError::DeviceRemoved);
        };

        let pool_idx = if let Some(ref mut pool) = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() } {
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

        unsafe {
            let h_ptr = pool.header_ptr(pool_idx);
            *h_ptr = VirtioBlkHeader { type_tag, reserved: 0, sector: req.lba };
            let s_ptr = pool.status_ptr(pool_idx);
            *s_ptr = 0xFF; // Pending
        }

        let buffer_phys = match req.buffer.invoke(GetPhysAddr) {
            Ok(p) => p.raw(),
            Err(_) => {
                if let Some(ref mut pool) = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() } {
                    pool.free(pool_idx);
                }
                return BlkRequestFuture::error(req.user_tag, BlockError::PermissionDenied);
            }
        };

        let mut descs = [
            VirtqDesc { addr: header_phys, len: 16, flags: 0, next: 0 },
            VirtqDesc { addr: buffer_phys, len: req.blocks * 512, flags: 0, next: 0 },
            VirtqDesc { addr: status_phys, len: 1, flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];

        if req.op == BlockOp::Read {
            descs[1].flags |= VIRTQ_DESC_F_WRITE;
        }

        if let Some(id) = inner.queue.add_buffer(&descs) {
            inner.requests.insert(id, InFlightRequest {
                _user_tag: req.user_tag,
                waker: None,
                pool_idx,
            });

            self.mmio.write_u32(VirtioMmioDevice::REG_QUEUE_NOTIFY, 0);

            BlkRequestFuture {
                device: Some(self),
                head_id: Some(id),
                user_tag: req.user_tag,
            }
        } else {
            if let Some(ref mut pool) = unsafe { &mut *core::ptr::addr_of!(self.pool).cast_mut() } {
                pool.free(pool_idx);
            }
            BlkRequestFuture::error(req.user_tag, BlockError::IOError)
        }
    }

    fn flush(&self) -> impl Future<Output = ()> { core::future::pending() }
    fn discard(&self, _range: LbaRange) -> impl Future<Output = ()> { core::future::pending() }
    fn cancel(&self, _tag: u64) -> impl Future<Output = CancelResult> { core::future::pending() }
}

struct BlkRequestFuture<'a> {
    device: Option<&'a VirtioBlkDevice>,
    head_id: Option<u16>,
    user_tag: u64,
}

impl<'a> BlkRequestFuture<'a> {
    fn error(user_tag: u64, _err: BlockError) -> Self {
        Self { device: None, head_id: None, user_tag }
    }
}

impl<'a> Future for BlkRequestFuture<'a> {
    type Output = BlockCompletion;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (device, id) = match (self.device, self.head_id) {
            (Some(d), Some(id)) => (d, id),
            _ => return Poll::Ready(BlockCompletion { tag: 0, user_tag: self.user_tag, result: Err(BlockError::DeviceRemoved) }),
        };

        let mut inner_guard = device.inner.lock();
        let inner = if let Some(ref mut i) = *inner_guard { i } else {
            return Poll::Ready(BlockCompletion { tag: 0, user_tag: self.user_tag, result: Err(BlockError::DeviceRemoved) });
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
pub const VIRTIO_BLK_T_IN:     u32 = 0;
pub const VIRTIO_BLK_T_OUT:    u32 = 1;
pub const VIRTIO_BLK_T_FLUSH:  u32 = 4;
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
    pub sector:   u64,
}

/// Status byte for virtio-blk.
pub const VIRTIO_BLK_S_OK:      u8 = 0;
pub const VIRTIO_BLK_S_IOERR:   u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP:  u8 = 2;

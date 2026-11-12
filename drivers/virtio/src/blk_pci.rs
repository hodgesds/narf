//! virtio-blk over modern virtio-PCI transport.
//!
//! The driver shape mirrors `blk.rs` (virtio-mmio); the only
//! difference is where register reads / writes land. Probe registers
//! itself with `bus::register_pci_driver` for vendor 0x1AF4, device
//! 0x1041 (modern virtio-blk).

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_CONFIG_GENERATION,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE,
    CC_DRIVER_FEATURE_SELECT, CC_NUM_QUEUES, CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER,
    CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{Virtqueue, VirtqueueLayout};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

/// QEMU `virtio-blk-pci` modern device id. The modern transport
/// formula is `0x1040 + virtio_device_id`; virtio-blk's type is 2
/// (per VirtIO 1.2 §5.2), so the PCI device id is 0x1042.
pub const VIRTIO_BLK_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_BLK_PCI_DEVICE: u16 = 0x1042;

/// virtio-blk request types.
pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// virtio-blk cache-flush request type (VirtIO 1.2 §5.2.6; mirrors
/// `crate::blk::VIRTIO_BLK_T_FLUSH` — this file keeps its own copy
/// by the same convention as T_IN/T_OUT above).
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;

/// virtio-blk feature bit for cache-flush support (VirtIO 1.2
/// §5.2.3). Negotiated when the device offers it; `flush_cache`
/// issues T_FLUSH only then (#841).
pub const VIRTIO_BLK_F_FLUSH: u64 = 9;

/// Max sectors per virtio-blk read round-trip. 128 × 512 B = 64 KiB, the
/// size of one contiguous coherent payload (order-4 buddy block). Bounds
/// how much `read_sectors` transfers per submit; a fallback drops to 8
/// sectors if the 64 KiB contiguous DMA buffer can't be allocated.
/// Maximum sectors in one synchronous request. Keep the payload within one
/// 4 KiB DMA page until multi-page virtio-blk transfers have a completion
/// integration test; the 64 KiB experiment could leave QEMU without a used
/// entry during Fedora's large DSO reads.
pub const MAX_READ_SECTORS: u16 = 8;
/// Most sectors one request moves (128 KiB): the chain is one payload
/// descriptor, so this is a per-request DMA allocation bound, not a
/// device limit (`seg_max` is not negotiated).
pub const MAX_IO_SECTORS: u16 = 256;

/// virtio-blk completion status.
pub const VIRTIO_BLK_S_OK: u8 = 0;

/// A bounded configuration snapshot, not a device-completion wait. Continual
/// config changes leave capacity unknown instead of publishing a torn value.
fn stable_capacity(mut sample: impl FnMut() -> (u8, u32, u32, u8)) -> Option<u64> {
    for _ in 0..8 {
        let (before, low, high, after) = sample();
        if before == after {
            return Some(u64::from(low) | (u64::from(high) << 32));
        }
    }
    None
}

mod capacity_tests {
    use super::stable_capacity;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_blk_pci_capacity_64bit_sectors() -> TestResult {
        // Do not scale by a block-size feature or truncate the high word.
        if stable_capacity(|| (7, 0x1234_5678, 2, 7)) != Some(0x2_1234_5678)
            || stable_capacity(|| (0, 0, 0, 0)) != Some(0)
        {
            return TestResult::Fail("block capacity lost its sector units or high word");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/virtio", smoke_blk_pci_capacity_64bit_sectors);

    fn smoke_blk_pci_capacity_resize_retry() -> TestResult {
        let mut reads = 0;
        let capacity = stable_capacity(|| {
            reads += 1;
            if reads == 1 {
                (254, u32::MAX, 2, 255) // resize crossed the two word reads
            } else {
                (255, 0, 3, 255)
            }
        });
        if capacity != Some(0x3_0000_0000) || reads != 2 {
            return TestResult::Fail("block capacity accepted a torn resize snapshot");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/virtio", smoke_blk_pci_capacity_resize_retry);

    fn smoke_blk_pci_capacity_unstable_bounded() -> TestResult {
        let mut reads = 0;
        let capacity = stable_capacity(|| {
            reads += 1;
            (255, 0, 1, 0) // generation wrap is still a changed snapshot
        });
        if capacity.is_some() || reads != 8 {
            return TestResult::Fail("unstable block config was accepted or retried without bound");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/virtio", smoke_blk_pci_capacity_unstable_bounded);

    fn smoke_blk_pci_sync_write_bounds() -> TestResult {
        use narf_block::{BlockDeviceSync, BlockIoError};
        let device = super::VirtioBlkBlockSync;
        if device.write(u64::MAX, 0, &[]) != Ok(())
            || device.write(0, 2, &[0; 512]) != Err(BlockIoError::BufferTooSmall)
            || device.write(u64::MAX, 1, &[0; 512]) != Err(BlockIoError::OutOfRange)
        {
            return TestResult::Fail("sync block write bounds/no-op contract changed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/virtio", smoke_blk_pci_sync_write_bounds);
}

// Written only after a request has already failed to complete for one second,
// then read by the feature-gated fatal stall watchdog. Keeping diagnostics off
// the normal submit/poll path avoids perturbing timing-sensitive failures.
pub(crate) static STALLED_QUEUE_STATE: AtomicU64 = AtomicU64::new(0);
pub(crate) static STALLED_REQUEST: AtomicU64 = AtomicU64::new(0);

/// Last virtio-blk timeout snapshot for the fatal stall watchdog.
///
/// Returns `(sector, head, avail_idx, last_used_idx, device_used_idx,
/// num_free, status)`, or `None` if no request has crossed the stall
/// threshold ([`crate::blk_mq::STALL_REPORT_MS`]). `sector` is 0: the
/// queued request table reports by slot, not sector.
pub fn stalled_queue_snapshot() -> Option<(u64, u16, u16, u16, u16, u16, u8)> {
    let state = STALLED_QUEUE_STATE.load(Ordering::Acquire);
    if state == 0 {
        return None;
    }
    let request = STALLED_REQUEST.load(Ordering::Relaxed);
    Some((
        request >> 16,
        request as u16,
        (state >> 48) as u16,
        (state >> 32) as u16,
        (state >> 16) as u16,
        state as u16,
        (request >> 8) as u8,
    ))
}

/// Probed live virtio-blk-pci controller. Holds the live
/// register-region maps + DMA buffers for the queue + per-request
/// header/status pool.
pub struct VirtioBlkPci {
    common: VirtioRegion,
    /// Mandatory block configuration; capacity is always in 512-byte sectors.
    device_cfg: VirtioRegion,
    /// Queue 0 with its queued request table (chains, header/status
    /// slots, completion matching) — see [`crate::blk_mq`].
    mq: alloc::sync::Arc<crate::blk_mq::BlkQueue>,
    /// DMA buffer holding the descriptor table + avail + used rings.
    _q_buf: DmaBuffer,
    /// Negotiated queue size.
    qsize: u16,
    /// IDT vector allocated for queue-0 MSI-X delivery, or `None`
    /// when the driver is running in polled mode.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table, kept alive so completion-time notifications
    /// keep flowing.
    msix: Option<narf_bus::MsixTable>,
    /// True once the wire-up is done. `false` when the device
    /// rejected our feature set or the queue couldn't be sized.
    pub ready: bool,
    /// True when the device offered VIRTIO_BLK_F_FLUSH and the
    /// driver negotiated it. `flush_cache` issues T_FLUSH only
    /// then; otherwise the device has no guest-drainable cache
    /// and the write-through treatment is honest (#841).
    flush_supported: bool,
}

impl core::fmt::Debug for VirtioBlkPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlkPci")
            .field("ready", &self.ready)
            .field("flush_supported", &self.flush_supported)
            .field("qsize", &self.qsize)
            .finish_non_exhaustive()
    }
}

impl VirtioBlkPci {
    /// Bring up the device on its first virtqueue. Returns Err on
    /// any spec-mandated failure.
    ///
    /// # Safety
    /// Caller owns the device's BAR window exclusively for the
    /// duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // 1. Walk the cap list.
        // SAFETY: bounded walk against identity-mapped cfg.
        let caps: VirtioCaps = unsafe { discover(device) }?;

        // 2. Map the regions we need.
        // SAFETY: caller-asserted.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;
        let device_cap = caps
            .device_cfg
            .as_ref()
            .ok_or(VirtioPciError::NoVendorCap)?;
        // SAFETY: caller owns the device; map_cap validates the BAR window.
        let device_cfg = unsafe { map_cap(device, device_cap) }?;
        if device_cfg.length < 8 || common.length <= CC_CONFIG_GENERATION {
            return Err(VirtioPciError::InvalidArgument);
        }

        // 3. Reset device.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
        }
        // 4. ACK + DRIVER status bits.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // 5. Feature negotiation. We need at least VIRTIO_F_VERSION_1.
        //    Read device features first (low 32 then high 32), pick
        //    the bits we want, write them back.
        // SAFETY: identity-mapped MMIO.
        let feats_lo = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            common.read32(CC_DEVICE_FEATURE)
        };
        // SAFETY: same.
        let feats_hi = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 1);
            common.read32(CC_DEVICE_FEATURE)
        };
        let feats = (feats_hi as u64) << 32 | feats_lo as u64;
        if feats & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        // Driver agrees to VERSION_1 plus VIRTIO_BLK_F_FLUSH when
        // the device offers it. Without the flush negotiation the
        // driver could not drain a device write cache, and the
        // SyncBlock Flush/Fua advertisement would be a lie (#841).
        // Stage-4 follow-ups can opt into RING_PACKED,
        // VIRTIO_BLK_F_SIZE_MAX, etc. Bit 9 sits in the low word.
        let flush_supported = feats & (1u64 << VIRTIO_BLK_F_FLUSH) != 0;
        let driver_feats_lo: u32 = if flush_supported {
            1u32 << (VIRTIO_BLK_F_FLUSH as u32)
        } else {
            0
        };
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, driver_feats_lo);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, 1u32 << (VIRTIO_F_VERSION_1 - 32));
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: same.
        let post_feat = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post_feat & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // 6. Queue 0 setup.
        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q == 0 {
            return Err(VirtioPciError::NoQueues);
        }
        // SAFETY: queue_select=0; queue_size returns max for q0.
        let qsize_max = unsafe {
            common.write16(CC_QUEUE_SELECT, 0);
            common.read16(CC_QUEUE_SIZE)
        };
        if qsize_max == 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let qsize = qsize_max.min(64).next_power_of_two() / 2;
        let qsize = if qsize == 0 { 4 } else { qsize.min(qsize_max) };

        // Allocate the queue backing page.
        let q_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let q_phys = q_buf.dma_addr().raw();
        let layout = VirtqueueLayout::new(qsize, q_phys).ok_or(VirtioPciError::QueueTooSmall)?;

        // Program queue addresses. Use the 64-bit split-write helper.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write16(CC_QUEUE_SIZE, qsize);
            common.write64_split(CC_QUEUE_DESC, layout.desc_table);
            common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
            common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
        }
        // SAFETY: same.
        let queue_notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
        // SAFETY: same.
        unsafe {
            common.write16(CC_QUEUE_ENABLE, 1);
        }

        // 7. DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // 8. Per-request header/status slots: one per chain the queue can
        //    hold (three descriptors each), 64 bytes per slot.
        let slots = (qsize / 3).max(1) as usize;
        let pool = alloc_coherent(
            (slots * crate::blk_mq::SLOT_BYTES).max(4096),
            DomainId::DRIVER_0,
        )
        .map_err(|_| VirtioPciError::BarMapFailed)?;

        // SAFETY: Virtqueue::new wipes the layout regions; the
        // backing pages may be recycled (alloc_frame doesn't zero).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let queue = unsafe { Virtqueue::new(layout) };
        let notify_off = (queue_notify_off as u64) * (notify_off_multiplier as u64);
        let mq = crate::blk_mq::BlkQueue::new(queue, qsize, notify, notify_off, pool);

        Ok(Self {
            common,
            device_cfg,
            mq,
            _q_buf: q_buf,
            qsize,
            irq_vector: None,
            msix: None,
            ready: true,
            flush_supported,
        })
    }

    /// VirtIO 1.2 §5.2.4: the first little-endian u64 in block config is
    /// capacity in 512-byte sectors, independent of optional block-size fields.
    /// Bracket both halves with config_generation so a resize cannot tear it.
    fn capacity_sectors(&self) -> u64 {
        stable_capacity(|| {
            // SAFETY: bring_up checks the generation byte and both capacity
            // halves fit their mapped regions; the installed request gate
            // keeps the controller reference exclusive during this read.
            unsafe {
                let before = self.common.read8(CC_CONFIG_GENERATION);
                let low = self.device_cfg.read32(0);
                let high = self.device_cfg.read32(4);
                compiler_fence(Ordering::Acquire);
                let after = self.common.read8(CC_CONFIG_GENERATION);
                (before, low, high, after)
            }
        })
        .unwrap_or(0)
    }

    /// Switch the controller to MSI-X-driven completion. Walks the
    /// MSI-X cap, allocates an IDT vector, programs MSI-X table
    /// entry 0 to deliver to APIC 0, flips global enable, then
    /// writes `queue_msix_vector = 0` so the device delivers MSI-X
    /// vector 0 on used-ring activity.
    ///
    /// After this call, completion is observed via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())`.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // 1. Walk MSI-X cap.
        let mut table =
            narf_bus::msix::enable_msix(cap, device).map_err(|_| VirtioPciError::BarMapFailed)?;
        // 2. Alloc IDT vector + reserve table slot 0.
        let v = narf_interrupts::vector::alloc().map_err(|_| VirtioPciError::BarMapFailed)?;
        let _ = table.alloc_vector().ok_or(VirtioPciError::BarMapFailed)?;
        // 3. Program slot 0 to fire on this CPU. SAFETY: x2APIC
        //    online by the time any driver is brought up.
        // Hardcoded `target_apic_id=0` here was wrong: with -smp >1
        // sockets, the BSP's APIC ID may not be 0, and the MSI-X
        // would route to a CPU that isn't running the driver.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
        // SAFETY: caller-authority, exclusive ownership.
        let _ = unsafe { table.program_vector(0, target_apic, v) }
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| VirtioPciError::BarMapFailed)?;
        // 4. Tell the device which MSI-X vector queue 0 should fire.
        //    Common Cfg `queue_select=0` was already written during
        //    bring_up; re-write to be safe + then queue_msix_vector.
        // SAFETY: identity-mapped MMIO common-cfg region.
        unsafe {
            self.common.write16(CC_QUEUE_SELECT, 0);
            self.common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0);
        }
        // The device may write VIRTIO_MSI_NO_VECTOR (0xFFFF) back if
        // it couldn't accept the binding. Re-read to verify.
        // SAFETY: same.
        let actual = unsafe { self.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR) };
        if actual != 0 {
            return Err(VirtioPciError::BarMapFailed);
        }
        self.irq_vector = Some(v);
        self.msix = Some(table);
        // Completions are reaped in the handler from now on (and still by
        // any waiter that looks first).
        self.mq.install_isr(v);
        Ok(v)
    }

    /// Issue a single 512-byte write at `sector`.
    pub fn write_sector(&self, sector: u64, data: &[u8; 512]) -> Result<(), VirtioPciError> {
        self.write_sectors(sector, data)
    }

    /// The queued request table (see [`crate::blk_mq`]).
    pub fn mq(&self) -> &alloc::sync::Arc<crate::blk_mq::BlkQueue> {
        &self.mq
    }

    /// Write a contiguous sector range with one descriptor chain. In
    /// particular, a filesystem metadata node must not be split into
    /// separate 512-byte commands. The request's own DMA payload stays
    /// pinned until the device completes it; the wait holds no lock and
    /// shares the queue with every other request in flight.
    pub fn write_sectors(&self, sector: u64, data: &[u8]) -> Result<(), VirtioPciError> {
        if data.is_empty() || data.len() % 512 != 0 || data.len() > MAX_IO_SECTORS as usize * 512 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let payload = alloc_coherent(data.len(), DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        // SAFETY: the fresh DMA allocation covers data.len() bytes, cannot
        // overlap the caller's live slice, and stays pinned by the request
        // until completion.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), payload.cpu_mut_ptr::<u8>(), data.len());
        }
        compiler_fence(Ordering::Release);
        let status = crate::blk_mq::submit_sync(
            &self.mq,
            crate::blk_mq::BlkOp::Write,
            sector,
            Some(alloc::sync::Arc::new(payload)),
            data.len(),
        )?;
        crate::blk_mq::ok(status)
    }

    /// Whether VIRTIO_BLK_F_FLUSH was negotiated at probe time.
    /// The sync wrapper reports it as `volatile_cache` so the
    /// advertisement always matches what `flush_cache` can do (#841).
    pub fn flush_supported(&self) -> bool {
        self.flush_supported
    }

    /// Drain the device's volatile write cache with a
    /// VIRTIO_BLK_T_FLUSH request (VirtIO 1.2 §5.2.6): a header-only
    /// chain, no payload. Returns Ok(()) without touching the
    /// device when flush was not negotiated — the device then has
    /// no guest-drainable cache and the write-through treatment is
    /// honest. A device status other than S_OK maps to an error:
    /// a flush that did not happen must surface, never report
    /// success (#841).
    pub fn flush_cache(&self) -> Result<(), VirtioPciError> {
        if !self.flush_supported {
            return Ok(());
        }
        let status = crate::blk_mq::submit_sync(&self.mq, crate::blk_mq::BlkOp::Flush, 0, None, 0)?;
        crate::blk_mq::ok(status)
    }

    /// Issue a single 512-byte read at `sector` and copy the result
    /// into `out`.
    pub fn read_sector(&self, sector: u64, out: &mut [u8; 512]) -> Result<(), VirtioPciError> {
        self.read_sectors(sector, 1, out)
    }

    /// Read `count` sectors (at most [`MAX_IO_SECTORS`]) at `sector` into
    /// `out` with one descriptor chain.
    pub fn read_sectors(
        &self,
        sector: u64,
        count: u16,
        out: &mut [u8],
    ) -> Result<(), VirtioPciError> {
        let count = count.clamp(1, MAX_IO_SECTORS);
        let bytes = count as usize * 512;
        if out.len() < bytes {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let payload =
            alloc_coherent(bytes, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload = alloc::sync::Arc::new(payload);
        let status = crate::blk_mq::submit_sync(
            &self.mq,
            crate::blk_mq::BlkOp::Read,
            sector,
            Some(alloc::sync::Arc::clone(&payload)),
            bytes,
        )?;
        crate::blk_mq::ok(status)?;
        // The completion made the device's writes visible; fence so the
        // bulk copy cannot be hoisted above it.
        compiler_fence(Ordering::Acquire);
        // SAFETY: a live coherent buffer of `bytes` bytes, separately
        // allocated so it cannot overlap `out`.
        unsafe {
            core::ptr::copy_nonoverlapping(payload.cpu_ptr::<u8>(), out.as_mut_ptr(), bytes);
        }
        Ok(())
    }

    /// Negotiated queue size.
    pub fn queue_size(&self) -> u16 {
        self.qsize
    }

    /// IRQ-driven variant of `read_sector`: the same queued request, whose
    /// wait parks on the queue's MSI-X vector when one is bound (and polls
    /// the used ring otherwise).
    pub fn read_sector_irq(&self, sector: u64, out: &mut [u8; 512]) -> Result<(), VirtioPciError> {
        self.read_sectors(sector, 1, out)
    }
}

/// Async, IRQ-driven 512-byte read from `sector`: one queued request on
/// the singleton controller, awaited beside every other request in flight.
pub async fn read_sector_irq_async(sector: u64) -> Result<[u8; 512], VirtioPciError> {
    let mq = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        alloc::sync::Arc::clone(c.mq())
    };
    let payload = alloc::sync::Arc::new(
        alloc_coherent(512, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?,
    );
    let status = crate::blk_mq::submit_async(
        mq,
        crate::blk_mq::BlkOp::Read,
        sector,
        Some(alloc::sync::Arc::clone(&payload)),
        512,
    )
    .await?;
    crate::blk_mq::ok(status)?;
    compiler_fence(Ordering::Acquire);
    let mut out = [0u8; 512];
    // SAFETY: a live 512-byte coherent buffer the device finished writing.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.cpu_ptr::<u8>(), out.as_mut_ptr(), 512);
    }
    Ok(out)
}

/// Async, IRQ-driven 512-byte write to `sector`. Mirrors
/// [`read_sector_irq_async`].
pub async fn write_sector_irq_async(sector: u64, data: [u8; 512]) -> Result<(), VirtioPciError> {
    let mq = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        alloc::sync::Arc::clone(c.mq())
    };
    let payload =
        alloc_coherent(512, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
    // SAFETY: fresh 512-byte coherent buffer, pinned by the request.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), payload.cpu_mut_ptr::<u8>(), 512);
    }
    compiler_fence(Ordering::Release);
    let status = crate::blk_mq::submit_async(
        mq,
        crate::blk_mq::BlkOp::Write,
        sector,
        Some(alloc::sync::Arc::new(payload)),
        512,
    )
    .await?;
    crate::blk_mq::ok(status)
}

// ── Driver-match registration ────────────────────────────────────────

/// Sync wrapper that lets the kernel's block registry address
/// virtio-blk uniformly with NVMe + AHCI. Wraps the singleton
/// CONTROLLER. Reads / writes go through the polled
/// `read_sector` / `write_sector` paths.
#[derive(Debug)]
pub struct VirtioBlkBlockSync;

impl narf_block::BlockDeviceSync for VirtioBlkBlockSync {
    fn lba_size(&self) -> u32 {
        512
    }
    fn capacity(&self) -> u64 {
        probed_device()
            .map(|(_gate, device)| device.capacity_sectors())
            .unwrap_or(0)
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let need = n_blocks as usize * 512;
        if out.len() < need {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        // The gate is held only to reach the device; the transfer itself
        // waits on its own queued request, beside everyone else's.
        let dev = probed_device_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let mut done: u16 = 0;
        while done < n_blocks {
            let want = core::cmp::min(MAX_IO_SECTORS, n_blocks - done);
            let off = done as usize * 512;
            dev.read_sectors(
                lba + done as u64,
                want,
                &mut out[off..off + want as usize * 512],
            )
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
            done += want;
        }
        Ok(())
    }
    /// The queued request path (see [`crate::blk_mq`]): what `SyncBlock`
    /// submits through, many requests in flight at once.
    fn queue(&self) -> Option<alloc::sync::Arc<dyn narf_block::BlockQueue>> {
        probed_device_ref().map(|dev| {
            alloc::sync::Arc::new(crate::blk_mq::VirtioBlkQueue::new(
                alloc::sync::Arc::clone(dev.mq()),
                dev.flush_supported(),
            )) as alloc::sync::Arc<dyn narf_block::BlockQueue>
        })
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let need = n_blocks as usize * 512;
        if data.len() < need {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if lba.checked_add(u64::from(n_blocks)).is_none() {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let dev = probed_device_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let mut done = 0usize;
        while done < need {
            let n = (need - done).min(MAX_IO_SECTORS as usize * 512);
            dev.write_sectors(lba + (done / 512) as u64, &data[done..done + n])
                .map_err(|_| narf_block::BlockIoError::DriverError)?;
            done += n;
        }
        Ok(())
    }
    /// Drain the device write cache via T_FLUSH when negotiated
    /// (#841). A failed flush surfaces as `DriverError`, never as
    /// silent success — the SyncBlock Flush advertisement is only
    /// honest if this is real.
    fn flush(&self) -> Result<(), narf_block::BlockIoError> {
        let dev = probed_device_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        dev.flush_cache()
            .map_err(|_| narf_block::BlockIoError::DriverError)
    }
    /// `volatile_cache` tracks negotiation exactly: a device that
    /// offered F_FLUSH may cache writes, and `flush` drains it; a
    /// device that did not offer it has no guest-drainable cache,
    /// so the write-through treatment is honest. `fua` is never
    /// native — the trait default (write + flush) is the emulation,
    /// sound exactly because `flush` is now real when negotiated.
    /// Unprobed, there is no device to describe: the default
    /// (write-through, emulated FUA) is reported.
    fn capabilities(&self) -> narf_block::BlockCaps {
        let flush_supported = probed_device()
            .map(|(_gate, dev)| dev.flush_supported())
            .unwrap_or(false);
        narf_block::BlockCaps {
            volatile_cache: flush_supported,
            fua: false,
        }
    }
}

/// The installed controller and the gate serialising access to it.
///
/// Leaked at install so the address is stable BY CONSTRUCTION rather than
/// by invariant. The earlier version stored the device inline in the
/// `Option` and handed out `&'static` references derived from a raw
/// pointer, resting on "installed once, never moved, never dropped" —
/// true today, but a later hot-unplug or re-probe change would turn it
/// into a use-after-free reachable only under load, and a test pinning
/// the invariant only catches that if someone runs it. Leaking removes
/// the question: the allocation outlives every reference unconditionally.
///
/// The `UnsafeCell` is what keeps the one `&mut` path sound. `req_gate`
/// admits a single holder at a time, so at most one `&mut VirtioBlkPci`
/// can exist, and no shared reference can overlap it.
struct InstalledDevice {
    /// Serialises device round-trips and every reference into `dev`.
    /// Spun on with interrupts ENABLED — see [`ReqGate`].
    req_gate: core::sync::atomic::AtomicBool,
    dev: core::cell::UnsafeCell<VirtioBlkPci>,
}

// SAFETY: every reference into `dev` is constructed while holding
// `req_gate`, which admits one holder at a time, so accesses are
// exclusive; `VirtioBlkPci` is `Send` (asserted below), so handing that
// exclusive access to whichever CPU wins the gate is fine.
unsafe impl Sync for InstalledDevice {}

const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<VirtioBlkPci>()
};

static CONTROLLER: IrqSafeSpinLock<Option<&'static InstalledDevice>> = IrqSafeSpinLock::new(None);

/// RAII holder for a device's request gate.
///
/// The synchronous block paths hold this instead of `CONTROLLER`.
/// `CONTROLLER` is an `IrqSafeSpinLock`, so holding it across a device
/// round-trip masks interrupts on the waiting CPU for the whole transfer
/// and forces every other CPU to spin with interrupts masked too. With a
/// filesystem workload — a desktop session loading thousands of small
/// files — that starves timers and RCU and livelocks the machine: the
/// stall watchdog caught three CPUs `SPIN-NOT-POLLING` on this exact lock
/// with work queued on every ready queue. Adding vCPUs made it worse,
/// because it is a thundering herd rather than a race.
///
/// The device's own `queue` lock still provides virtqueue mutual
/// exclusion, and `read_sectors` already releases it between completion
/// polls, so this gate only has to cover the shared scratch pool.
struct ReqGate<'a>(&'a core::sync::atomic::AtomicBool);

impl<'a> ReqGate<'a> {
    /// Acquire the gate. Interrupts keep their caller-supplied state so timer
    /// ticks, RCU quiescent states and the sleep pumps continue to run while we
    /// wait.
    ///
    /// On contention we do NOT pure-`spin_loop`: the gate holder may be a
    /// stackful task that was preempted mid-round-trip and is homed on THIS
    /// CPU, so spinning would monopolize the very CPU it needs to run on and
    /// livelock (the `no_park_backstop` thundering-herd convoy — the stall
    /// watchdog catches N CPUs `SPIN-NOT-POLLING` here with the gate held but no
    /// CPU in the critical section). After a short spin burst (cheap when the
    /// gate is held only briefly by a holder running on another CPU) we
    /// COOPERATIVELY YIELD so the executor can run the homed holder; it then
    /// completes and releases the gate, and we retry on re-poll. Yielding uses
    /// the well-tested own-stack yield path, not `no_preempt`.
    fn acquire(flag: &'a core::sync::atomic::AtomicBool) -> ReqGate<'a> {
        loop {
            // Fast path: brief spin for a gate held only momentarily by a
            // holder running on another CPU.
            for _ in 0..128 {
                if flag
                    .compare_exchange_weak(
                        false,
                        true,
                        core::sync::atomic::Ordering::Acquire,
                        core::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return ReqGate(flag);
                }
                core::hint::spin_loop();
            }
            // Still contended: the holder may be descheduled and homed on THIS
            // CPU. Yield to the executor so it can run it. Falls back to a spin
            // when there is no stackful task to yield (e.g. early boot, or a
            // non-x86_64 build without the own-stack model).
            if !narf_scheduler::cooperative_yield() {
                // Can't yield: drain pending TLB shootdowns while spinning
                // (see `narf_lib::sync::service_masked_spin`).
                narf_lib::sync::service_masked_spin();
                core::hint::spin_loop();
            }
        }
    }
}

impl Drop for ReqGate<'_> {
    fn drop(&mut self) {
        self.0.store(false, core::sync::atomic::Ordering::Release);
    }
}

/// The installed slot, WITHOUT holding `CONTROLLER` for the caller's use
/// of it.
///
/// `CONTROLLER` is taken only long enough to copy the slot reference out,
/// then released, so a transfer runs with interrupts enabled. The slot is
/// leaked at install, so this reference is valid for the rest of the boot
/// with no invariant to defend — see [`InstalledDevice`].
fn probed_slot() -> Option<&'static InstalledDevice> {
    *CONTROLLER.lock()
}

/// The installed controller for a read-only use, serialised by its gate.
///
/// Returns the gate guard alongside the reference so the caller cannot
/// accidentally drop the guard while still holding the device.
fn probed_device() -> Option<(ReqGate<'static>, &'static VirtioBlkPci)> {
    let slot = probed_slot()?;
    let gate = ReqGate::acquire(&slot.req_gate);
    // SAFETY: `gate` is held for as long as the returned reference, and
    // the gate admits one holder at a time, so no other reference into
    // the cell — shared or exclusive — can overlap this one.
    Some((gate, unsafe { &*slot.dev.get() }))
}

/// The installed controller for the data path, without the gate. Sound
/// because the only `&mut` into the cell (`with_controller_mut`,
/// `enable_msix_for_probed`) exists under the gate and is used only before
/// the controller serves I/O (MSI-X enable at probe / in a smoke before its
/// transfers); the data path reads `mq` (an `Arc`) and the negotiated
/// flags, which those paths never change.
fn probed_device_ref() -> Option<&'static VirtioBlkPci> {
    let slot = probed_slot()?;
    // SAFETY: see above.
    Some(unsafe { &*slot.dev.get() })
}

/// The installed controller's address, or `None` before probe. Test hook
/// for the install-once invariant `with_device_unlocked` relies on.
#[doc(hidden)]
pub fn dbg_device_addr() -> Option<usize> {
    probed_slot().map(|s| s.dev.get() as usize)
}

/// Probe entry — installed via `bus::register_pci_driver`.
/// Idempotent: returns `Ok(())` when the controller is already
/// brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // Enable MEM_SPACE + BUS_MASTER on the device. Without BME the
    // virtio-pci controller can't DMA the descriptor / used rings.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority, exclusive ownership of the device's
    // cfg + BAR windows for the duration of bring_up.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mut dev = match unsafe { VirtioBlkPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // MSI-X-driven completions (Linux `virtblk_probe` → `init_vq` with
    // per-queue vectors); the polled path remains the fallback.
    // SAFETY: caller-authority over the device, exclusive before install.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    // Leak the slot: an in-flight transfer may hold a reference into it,
    // and freeing that under a live guard would be a use-after-free
    // reachable only under load. `probe` early-returns when a controller
    // exists, so this happens once per boot.
    let slot: &'static InstalledDevice =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(InstalledDevice {
            req_gate: core::sync::atomic::AtomicBool::new(false),
            dev: core::cell::UnsafeCell::new(dev),
        }));
    *CONTROLLER.lock() = Some(slot);
    // Register against the unified block-device registry.
    let parent = alloc::sync::Arc::new(VirtioBlkBlockSync)
        as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>;
    narf_block::register_block_device("vblk0", parent.clone());
    // Make GPT/MBR child devices visible to the root-mount walk. Without
    // this, a partitioned virtio disk only exposes its whole-disk parent, so
    // filesystem detection never reaches an ext4 root stored in a partition.
    // A scan failure is non-fatal: unpartitioned virtio disks remain usable
    // through the parent device just as before.
    let _ = narf_block::partition::scan_and_register_partitions(parent, "vblk0");
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vblk0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(VIRTIO_BLK_PCI_VENDOR),
        pci_did: Some(VIRTIO_BLK_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    Ok(())
}

/// Register the driver with the bus-level match table.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-blk-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_BLK_PCI_VENDOR,
            device: VIRTIO_BLK_PCI_DEVICE,
        },
        probe,
    });
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&VirtioBlkPci) -> R) -> Option<R> {
    let (_gate, dev) = probed_device()?;
    Some(f(dev))
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Enable MSI-X-driven completion on the probed controller. The
/// caller supplies the `Cap<BusDeviceCap, Write>` they got from
/// `claim_device_cap` (the same one the bus's match-table dispatch
/// hands the probe). Returns the IDT vector wired into the device.
pub fn enable_msix_for_probed(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<u8, VirtioPciError> {
    // The only `&mut` access to the installed controller. The gate admits
    // one holder at a time, so this cannot alias a shared reference handed
    // to a live transfer.
    let slot = probed_slot().ok_or(VirtioPciError::NoQueues)?;
    let _gate = ReqGate::acquire(&slot.req_gate);
    // SAFETY: `_gate` is held for the whole borrow and admits a single
    // holder, so this `&mut` is exclusive.
    let dev = unsafe { &mut *slot.dev.get() };
    if let Some(v) = dev.irq_vector {
        return Ok(v);
    }
    // SAFETY: caller-authority over the device.
    unsafe { dev.enable_msix(cap, device) }
}

/// Mutable accessor for the probed controller — used by tests that
/// want to switch on MSI-X mid-suite. Wave-3a pragmatic surface;
/// proper Wave-3b API has the registry hand back a typed handle.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut VirtioBlkPci) -> R) -> Option<R> {
    let slot = probed_slot()?;
    let _gate = ReqGate::acquire(&slot.req_gate);
    // SAFETY: `_gate` is held for the whole borrow and admits a single
    // holder, so this `&mut` cannot alias any other reference into the cell.
    Some(f(unsafe { &mut *slot.dev.get() }))
}

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
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_NUM_QUEUES, CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE,
    CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
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

/// Max sectors per virtio-blk read round-trip. 128 × 512 B = 64 KiB, the
/// size of one contiguous coherent payload (order-4 buddy block). Bounds
/// how much `read_sectors` transfers per submit; a fallback drops to 8
/// sectors if the 64 KiB contiguous DMA buffer can't be allocated.
/// Maximum sectors in one synchronous request. Keep the payload within one
/// 4 KiB DMA page until multi-page virtio-blk transfers have a completion
/// integration test; the 64 KiB experiment could leave QEMU without a used
/// entry during Fedora's large DSO reads.
pub const MAX_READ_SECTORS: u16 = 8;

/// virtio-blk completion status.
pub const VIRTIO_BLK_S_OK: u8 = 0;

// Written only after a request has already failed to complete for one second,
// then read by the feature-gated fatal stall watchdog. Keeping diagnostics off
// the normal submit/poll path avoids perturbing timing-sensitive failures.
static STALLED_QUEUE_STATE: AtomicU64 = AtomicU64::new(0);
static STALLED_REQUEST: AtomicU64 = AtomicU64::new(0);

/// Last virtio-blk timeout snapshot for the fatal stall watchdog.
///
/// Returns `(sector, head, avail_idx, last_used_idx, device_used_idx,
/// num_free, status)`, or `None` if no request has crossed the one-second
/// threshold.
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

/// virtio-blk request header (VirtIO 1.2 §5.2.6).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct BlkHeader {
    type_tag: u32,
    _resv: u32,
    sector: u64,
}

/// Probed live virtio-blk-pci controller. Holds the live
/// register-region maps + DMA buffers for the queue + per-request
/// header/status pool.
pub struct VirtioBlkPci {
    common: VirtioRegion,
    notify: VirtioRegion,
    /// `notify_off_multiplier` from the Notify cap header.
    notify_off_multiplier: u32,
    queue: IrqSafeSpinLock<Option<Virtqueue>>,
    /// DMA buffer holding the descriptor table + avail + used rings.
    _q_buf: DmaBuffer,
    /// Per-request scratch (16-byte header + 1-byte status + pad to
    /// 64 bytes) — single-request driver until the multi-inflight
    /// path lands.
    pool: DmaBuffer,
    /// Negotiated queue size.
    qsize: u16,
    /// `queue_notify_off` for queue 0, captured at probe time.
    queue_notify_off: u16,
    /// IDT vector allocated for queue-0 MSI-X delivery, or `None`
    /// when the driver is running in polled mode.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table, kept alive so completion-time notifications
    /// keep flowing.
    msix: Option<narf_bus::MsixTable>,
    /// True once the wire-up is done. `false` when the device
    /// rejected our feature set or the queue couldn't be sized.
    pub ready: bool,
}

impl core::fmt::Debug for VirtioBlkPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlkPci")
            .field("ready", &self.ready)
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
        // Driver agrees only to VERSION_1 — minimal, predictable
        // behaviour. Stage-4 follow-ups can opt into RING_PACKED,
        // VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_FLUSH, etc.
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, 0);
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
        let q_phys = q_buf.phys_addr().raw();
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

        // 8. Per-request pool — single 4 KiB page; layout is 16 bytes
        //    of header + 1 byte of status + padding (64 bytes per
        //    slot, 64 slots / page).
        let pool =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        // SAFETY: Virtqueue::new wipes the layout regions; the
        // backing pages may be recycled (alloc_frame doesn't zero).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let queue = unsafe { Virtqueue::new(layout) };

        Ok(Self {
            common,
            notify,
            notify_off_multiplier,
            queue: IrqSafeSpinLock::new(Some(queue)),
            _q_buf: q_buf,
            pool,
            qsize,
            queue_notify_off,
            irq_vector: None,
            msix: None,
            ready: true,
        })
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
        Ok(v)
    }

    /// Issue a single 512-byte write at `sector`. Polled.
    pub fn write_sector(&self, sector: u64, data: &[u8; 512]) -> Result<(), VirtioPciError> {
        // Build header into the per-request pool slot 0.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_OUT,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }
        // Stage the payload into a fresh DMA page.
        let payload =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA buffer; fill the first 512 bytes
        // with the caller's data.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for (i, &byte) in data.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(payload_phys + i as u64).kernel_mut_ptr::<u8>(),
                    byte,
                );
            }
        }
        // For Write, payload is read-only from the device's POV.
        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: 512,
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
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(notify_off, 0);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // during the IDENTIFY-style probe completion wait.
        let mut q_err = false;
        // A submitted DMA request owns `payload` and its descriptor chain
        // until the device publishes a terminal used-ring entry. Returning on
        // an arbitrary timeout used to drop `payload` while the device could
        // still write to it and leaked the three descriptors permanently.
        // Reusing an abandoned chain can exhaust or corrupt the queue. Keep
        // pumping in bounded wall-clock slices, but do not abandon an
        // in-flight request.
        let done = loop {
            let completed = narf_scheduler::responsive_spin_until(
                || {
                    let elem = {
                        let mut g = self.queue.lock();
                        match g.as_mut() {
                            Some(q) => q.poll_used(),
                            None => {
                                q_err = true;
                                return true;
                            }
                        }
                    };
                    matches!(elem, Some((id, _)) if id == head as u32)
                },
                narf_time::Deadline::after_ms(1_000),
            );
            if completed || q_err {
                break completed;
            }
            let (avail, last_used, device_used, free) = {
                let g = self.queue.lock();
                g.as_ref()
                    .map(Virtqueue::diagnostic_snapshot)
                    .unwrap_or((0, 0, 0, 0))
            };
            // SAFETY: `status_phys` is the live DMA status byte allocated for
            // this request; the descriptor chain remains owned until the
            // device completes it, so the byte is valid for this diagnostic
            // volatile read.
            let status = unsafe {
                core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
            };
            STALLED_REQUEST.store(
                (sector << 16) | ((status as u64) << 8) | head as u64,
                Ordering::Relaxed,
            );
            STALLED_QUEUE_STATE.store(
                ((avail as u64) << 48)
                    | ((last_used as u64) << 32)
                    | ((device_used as u64) << 16)
                    | free as u64,
                Ordering::Release,
            );
        };
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        debug_assert!(done);
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        let _ = payload;
        Ok(())
    }

    /// Issue a single 512-byte read at `sector` and copy the result
    /// into `out`. Polled — the IRQ-driven path lands once we wire
    /// MSI-X for virtio-pci (a follow-up).
    pub fn read_sector(&self, sector: u64, out: &mut [u8; 512]) -> Result<(), VirtioPciError> {
        // Build header + status into the per-request pool slot 0.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_IN,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }

        // Allocate a 4 KiB DMA scratch buffer for the read payload.
        // (DMA buffers are page-sized; we only consume 512 bytes.)
        let payload =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA buffer; zero the first 512 bytes so
        // a stale read shows up clearly if the device misses our
        // request.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(payload_phys + i as u64).kernel_mut_ptr::<u8>(),
                    0,
                );
            }
        }

        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: 512,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];

        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };

        // Notify queue 0. The notify register address is
        //   notify_base + queue_notify_off * notify_off_multiplier
        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: notify cap region is identity-mapped MMIO; offset
        // bounded by the device's queue_notify_off.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.notify.write16(notify_off, 0);
        }

        // Poll the used ring for our completion. responsive_spin_until
        // ticks sleep_pumps so cursor/FB stay alive on slow I/O.
        let mut q_err = false;
        // The DMA payload and descriptor chain remain device-owned until a
        // used-ring entry arrives. A timeout is not a terminal completion:
        // dropping the payload and leaking the chain here eventually exhausted
        // the queue while Plasma streamed its DSOs.
        let done = loop {
            let completed = narf_scheduler::responsive_spin_until(
                || {
                    let elem = {
                        let mut g = self.queue.lock();
                        match g.as_mut() {
                            Some(q) => q.poll_used(),
                            None => {
                                q_err = true;
                                return true;
                            }
                        }
                    };
                    matches!(elem, Some((id, _)) if id == head as u32)
                },
                narf_time::Deadline::after_ms(1_000),
            );
            if completed || q_err {
                break completed;
            }
        };
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        debug_assert!(done);

        // Read the status byte; non-zero means I/O error.
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        if status != VIRTIO_BLK_S_OK {
            // Free chain to avoid leak.
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Copy the payload out. The completion check above is what makes the
        // device's writes visible; fence so the compiler cannot hoist this
        // bulk copy above it.
        compiler_fence(Ordering::Acquire);
        // SAFETY: identity-mapped DMA page of at least `out.len()` bytes,
        // freshly allocated so it cannot overlap `out`. Bulk copy rather than
        // a per-byte volatile loop — see `read_sectors`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(payload_phys).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                out.len(),
            );
        }

        // Free the descriptor chain.
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        // payload drops here — controller doesn't reference it after
        // the used-ring entry arrived.
        let _ = payload;
        Ok(())
    }

    /// Read `count` contiguous 512-byte sectors from `sector` in ONE virtio
    /// request — a single submit→poll round-trip instead of one per sector.
    /// `count` is clamped to 1..=8 (one 4 KiB DMA page holds 8 sectors);
    /// `out` must be at least `count*512` bytes. This is the batched
    /// counterpart to `read_sector`: a sequential file read (ext2 streaming a
    /// DSO) pays ~1/8 the `responsive_spin_until` round-trips.
    pub fn read_sectors(
        &self,
        sector: u64,
        count: u16,
        out: &mut [u8],
    ) -> Result<(), VirtioPciError> {
        // Keep each transfer within one DMA page. Multi-page coherent buffers
        // are supported by the allocator, but virtio-blk completion for larger
        // descriptors needs its own QEMU integration gate before this path can
        // safely raise the ceiling.
        let count = count.clamp(1, MAX_READ_SECTORS);
        let bytes = count as usize * 512;
        if out.len() < bytes {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_IN,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }

        let payload =
            alloc_coherent(bytes, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: coherent DMA buffer of >= `bytes`; zero the bytes we'll read
        // so a missed device write shows up clearly.
        //
        // `write_bytes`, not a volatile byte loop: this ran one
        // `write_volatile` per byte, which the compiler cannot vectorise or
        // turn into a `memset`, so every 4 KiB read paid 4096 separate
        // single-byte stores. On a filesystem workload that is the dominant
        // cost of a transfer — the stall watchdog caught a CPU sitting in
        // exactly this loop. Volatility buys nothing here: the buffer is not
        // MMIO, and the ordering that matters is the fence below, which is
        // what publishes these zeroes before the device is notified.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(payload_phys).kernel_mut_ptr::<u8>(),
                0,
                bytes,
            );
        }

        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: bytes as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];

        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };

        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: notify cap region is identity-mapped MMIO.
        unsafe {
            self.notify.write16(notify_off, 0);
        }

        let mut q_err = false;
        // The DMA payload and descriptor chain remain device-owned until a
        // used-ring entry arrives. A timeout is not a terminal completion.
        let done = loop {
            let completed = narf_scheduler::responsive_spin_until(
                || {
                    let elem = {
                        let mut g = self.queue.lock();
                        match g.as_mut() {
                            Some(q) => q.poll_used(),
                            None => {
                                q_err = true;
                                return true;
                            }
                        }
                    };
                    matches!(elem, Some((id, _)) if id == head as u32)
                },
                narf_time::Deadline::after_ms(1_000),
            );
            if completed || q_err {
                break completed;
            }
        };
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        debug_assert!(done);

        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // The used-ring entry above is what makes the device's writes
        // visible; keep the compiler from hoisting this copy above that
        // check now that it is a single bulk move rather than a sequence of
        // volatile reads.
        compiler_fence(Ordering::Acquire);
        // SAFETY: identity-mapped DMA page holding at least `bytes`, and
        // `out` is `bytes` long (checked above); the regions cannot overlap
        // because `payload` is a freshly allocated coherent buffer.
        //
        // A bulk copy for the same reason as the zeroing above: this was one
        // `read_volatile` per byte, so a 4 KiB read cost 4096 single-byte
        // loads that could not be vectorised.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(payload_phys).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                bytes,
            );
        }

        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        let _ = payload;
        Ok(())
    }

    /// Negotiated queue size.
    pub fn queue_size(&self) -> u16 {
        self.qsize
    }

    /// Submit a single 512-byte read without waiting for the device.
    /// Returns the descriptor chain head + the payload DmaBuffer +
    /// the (status, payload) phys addresses. Caller must keep the
    /// returned `payload` alive until drain completes.
    pub fn submit_read(&self, sector: u64) -> Result<(u16, DmaBuffer, u64, u64), VirtioPciError> {
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_IN,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }
        let payload =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: 512,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(notify_off, 0);
        }
        Ok((head, payload, status_phys, payload_phys))
    }

    /// Drain a previously submitted read. Returns Ok if the device
    /// reported success and the payload was copied into `out`.
    pub fn drain_read(
        &self,
        head: u16,
        status_phys: u64,
        payload_phys: u64,
        out: &mut [u8; 512],
    ) -> Result<(), VirtioPciError> {
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for our completion. Foreign-id used entries
        // are consumed inline and don't count against the bound.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.queue.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        // The completion check above makes the device's writes visible;
        // fence so the bulk copy cannot be hoisted above it.
        compiler_fence(Ordering::Acquire);
        // SAFETY: identity-mapped DMA page of at least `out.len()` bytes,
        // separately allocated so it cannot overlap `out`. Bulk copy rather
        // than a per-byte volatile loop — see `read_sectors`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(payload_phys).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(())
    }

    /// Submit a single 512-byte write without waiting for the device.
    /// Returns the descriptor chain head + the payload DmaBuffer +
    /// the status phys address. Caller must keep the returned
    /// `payload` alive until drain completes.
    pub fn submit_write(
        &self,
        sector: u64,
        data: &[u8; 512],
    ) -> Result<(u16, DmaBuffer, u64), VirtioPciError> {
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_OUT,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }
        let payload =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA buffer; copy in caller's data.
        unsafe {
            for (i, &byte) in data.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(payload_phys + i as u64).kernel_mut_ptr::<u8>(),
                    byte,
                );
            }
        }
        // Write payload is read-only from the device's POV (no
        // VIRTQ_DESC_F_WRITE on the payload desc).
        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: 512,
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
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(notify_off, 0);
        }
        Ok((head, payload, status_phys))
    }

    /// Drain a previously submitted write. Returns Ok if the device
    /// reported success.
    pub fn drain_write(&self, head: u16, status_phys: u64) -> Result<(), VirtioPciError> {
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for our write completion.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.queue.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        if status != VIRTIO_BLK_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// IRQ-driven variant of `read_sector`. Submits the request,
    /// then polls on `narf_interrupts::fire_count(irq_vector)` —
    /// the same atomic `wait_for_irq.await` consumes. Falls through
    /// to the polled `read_sector` if MSI-X isn't enabled yet.
    pub fn read_sector_irq(&self, sector: u64, out: &mut [u8; 512]) -> Result<(), VirtioPciError> {
        let v = match self.irq_vector {
            Some(v) => v,
            None => return self.read_sector(sector, out),
        };
        // Build header.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(header_phys).kernel_mut_ptr::<BlkHeader>(),
                BlkHeader {
                    type_tag: VIRTIO_BLK_T_IN,
                    _resv: 0,
                    sector,
                },
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u8>(),
                0xFFu8,
            );
        }
        let payload =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized.
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(payload_phys + i as u64).kernel_mut_ptr::<u8>(),
                    0,
                );
            }
        }
        let descs = [
            VirtqDesc {
                addr: header_phys,
                len: 16,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: 512,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];

        let _ = v; // fire_count is observed by the caller, not here.
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };

        let notify_off = (self.queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(notify_off, 0);
        }

        // Wait for the used ring to surface our head. We don't break
        // on `fire_count > baseline` — a stale or coalesced MSI-X
        // delivery (from a prior submission, an enable-interrupts
        // bookkeeping race, etc.) can advance fire_count *before* the
        // device actually completes this request. The IRQ will still
        // fire during this poll (MSI-X is wired), so the caller's
        // post-submit fire_count check still observes the wakeup.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.queue.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u8>())
        };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        // The completion check above makes the device's writes visible;
        // fence so the bulk copy cannot be hoisted above it.
        compiler_fence(Ordering::Acquire);
        // SAFETY: identity-mapped DMA page of at least `out.len()` bytes,
        // separately allocated so it cannot overlap `out`. Bulk copy rather
        // than a per-byte volatile loop — see `read_sectors`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(payload_phys).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        let _ = payload;
        Ok(())
    }
}

/// Async, IRQ-driven 512-byte read from `sector`. Submits the
/// request against the singleton CONTROLLER, awaits MSI-X delivery
/// via [`narf_interrupts::wait_for_irq_until`], drains the used
/// ring, and returns the device-written data.
///
/// The IRQ wait is bounded by a 5-second deadline. Typical virtio-
/// blk completions land in microseconds; this is the "device
/// wedged / lost MSI / EC quirk" fallback. On expiry we surface
/// `CompletionTimeout` so the upper layer can retry or abandon.
pub async fn read_sector_irq_async(sector: u64) -> Result<[u8; 512], VirtioPciError> {
    let vector = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.irq_vector
    };
    // Construct waiter BEFORE submit so a synchronously-delivered
    // MSI-X (QEMU completes virtio-blk reads inline) can't slip past
    // us — the future's baseline is the pre-submit fire_count.
    let waiter = vector
        .map(|v| narf_interrupts::wait_for_irq_until(v, narf_time::Deadline::after_ms(5_000)));
    let (head, payload, status_phys, payload_phys) = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.submit_read(sector)?
    };
    if let Some(w) = waiter {
        // Outer Result is the timeout (Err = Elapsed); inner is the
        // IRQ future's own output. We only care that the IRQ fired
        // OR that the deadline expired.
        if w.await.is_err() {
            return Err(VirtioPciError::CompletionTimeout);
        }
    }
    let mut out = [0u8; 512];
    let r = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.drain_read(head, status_phys, payload_phys, &mut out)
    };
    drop(payload);
    r.map(|()| out)
}

/// Async, IRQ-driven 512-byte write to `sector`. Mirrors
/// [`read_sector_irq_async`] — see that doc for the protocol and
/// the 5-second wait deadline.
pub async fn write_sector_irq_async(sector: u64, data: [u8; 512]) -> Result<(), VirtioPciError> {
    let vector = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.irq_vector
    };
    let waiter = vector
        .map(|v| narf_interrupts::wait_for_irq_until(v, narf_time::Deadline::after_ms(5_000)));
    let (head, payload, status_phys) = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.submit_write(sector, &data)?
    };
    if let Some(w) = waiter {
        if w.await.is_err() {
            return Err(VirtioPciError::CompletionTimeout);
        }
    }
    let r = {
        let (_gate, c) = probed_device().ok_or(VirtioPciError::NoQueues)?;
        c.drain_write(head, status_phys)
    };
    drop(payload);
    r
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
        0
    } // Stage-4 stub — capacity from device cfg lands later.
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
        // Interrupts stay enabled for the whole transfer: hold the device's
        // request gate, not the IRQ-masking CONTROLLER lock. See `ReqGate`.
        let (_gate, dev) = probed_device().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        {
            // Batch one 4 KiB page per virtio round-trip.
            let mut done: u16 = 0;
            while done < n_blocks {
                let want = core::cmp::min(MAX_READ_SECTORS, n_blocks - done);
                let off = done as usize * 512;
                let chunk = match dev.read_sectors(
                    lba + done as u64,
                    want,
                    &mut out[off..off + want as usize * 512],
                ) {
                    Ok(()) => want,
                    Err(_) if want > 8 => {
                        let small = 8u16.min(n_blocks - done);
                        dev.read_sectors(
                            lba + done as u64,
                            small,
                            &mut out[off..off + small as usize * 512],
                        )
                        .map_err(|_| narf_block::BlockIoError::DriverError)?;
                        small
                    }
                    Err(_) => return Err(narf_block::BlockIoError::DriverError),
                };
                done += chunk;
            }
            Ok(())
        }
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if n_blocks != 1 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if data.len() < 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let mut buf = [0u8; 512];
        buf.copy_from_slice(&data[..512]);
        // Same reasoning as `read` above.
        let (_gate, dev) = probed_device().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        dev.write_sector(lba, &buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)
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
    let dev = match unsafe { VirtioBlkPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
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

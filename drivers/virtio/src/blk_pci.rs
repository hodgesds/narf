//! virtio-blk over modern virtio-PCI transport.
//!
//! The driver shape mirrors `blk.rs` (virtio-mmio); the only
//! difference is where register reads / writes land. Probe registers
//! itself with `bus::register_pci_driver` for vendor 0x1AF4, device
//! 0x1041 (modern virtio-blk).

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS,
    CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT, CC_NUM_QUEUES,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE,
    CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{Virtqueue, VirtqueueLayout, VirtqDesc, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
    VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
};

/// QEMU `virtio-blk-pci` modern device id. The modern transport
/// formula is `0x1040 + virtio_device_id`; virtio-blk's type is 2
/// (per VirtIO 1.2 §5.2), so the PCI device id is 0x1042.
pub const VIRTIO_BLK_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_BLK_PCI_DEVICE: u16 = 0x1042;

/// virtio-blk request types.
pub const VIRTIO_BLK_T_IN:    u32 = 0;
pub const VIRTIO_BLK_T_OUT:   u32 = 1;

/// virtio-blk completion status.
pub const VIRTIO_BLK_S_OK:    u8 = 0;

/// virtio-blk request header (VirtIO 1.2 §5.2.6).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct BlkHeader {
    type_tag: u32,
    _resv:    u32,
    sector:   u64,
}

/// Probed live virtio-blk-pci controller. Holds the live
/// register-region maps + DMA buffers for the queue + per-request
/// header/status pool.
pub struct VirtioBlkPci {
    common:   VirtioRegion,
    notify:   VirtioRegion,
    /// `notify_off_multiplier` from the Notify cap header.
    notify_off_multiplier: u32,
    queue:    IrqSafeSpinLock<Option<Virtqueue>>,
    /// DMA buffer holding the descriptor table + avail + used rings.
    _q_buf:   DmaBuffer,
    /// Per-request scratch (16-byte header + 1-byte status + pad to
    /// 64 bytes) — single-request driver until the multi-inflight
    /// path lands.
    pool:     DmaBuffer,
    /// Negotiated queue size.
    qsize:    u16,
    /// `queue_notify_off` for queue 0, captured at probe time.
    queue_notify_off: u16,
    /// IDT vector allocated for queue-0 MSI-X delivery, or `None`
    /// when the driver is running in polled mode.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table, kept alive so completion-time notifications
    /// keep flowing.
    msix:     Option<narf_bus::MsixTable>,
    /// True once the wire-up is done. `false` when the device
    /// rejected our feature set or the queue couldn't be sized.
    pub ready: bool,
}

impl core::fmt::Debug for VirtioBlkPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlkPci")
            .field("ready",  &self.ready)
            .field("qsize",  &self.qsize)
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
        _cap:   &Cap<BusDeviceCap, Write>,
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
        unsafe { common.write8(CC_DEVICE_STATUS, 0); }
        // 4. ACK + DRIVER status bits.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8);
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
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK) as u8);
        }
        // SAFETY: same.
        let post_feat = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post_feat & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // 6. Queue 0 setup.
        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q == 0 { return Err(VirtioPciError::NoQueues); }
        // SAFETY: queue_select=0; queue_size returns max for q0.
        let qsize_max = unsafe {
            common.write16(CC_QUEUE_SELECT, 0);
            common.read16(CC_QUEUE_SIZE)
        };
        if qsize_max == 0 { return Err(VirtioPciError::QueueTooSmall); }
        let qsize = qsize_max.min(64).next_power_of_two() / 2;
        let qsize = if qsize == 0 { 4 } else { qsize.min(qsize_max) };

        // Allocate the queue backing page.
        let q_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let q_phys = q_buf.phys_addr().raw();
        let layout = VirtqueueLayout::new(qsize, q_phys)
            .ok_or(VirtioPciError::QueueTooSmall)?;

        // Program queue addresses. Use the 64-bit split-write helper.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write16(CC_QUEUE_SIZE, qsize);
            common.write64_split(CC_QUEUE_DESC,   layout.desc_table);
            common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
            common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
        }
        // SAFETY: same.
        let queue_notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
        // SAFETY: same.
        unsafe { common.write16(CC_QUEUE_ENABLE, 1); }

        // 7. DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // 8. Per-request pool — single 4 KiB page; layout is 16 bytes
        //    of header + 1 byte of status + padding (64 bytes per
        //    slot, 64 slots / page).
        let pool = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;

        // SAFETY: q_buf is freshly-allocated zeroed coherent DMA.
        let queue = unsafe { Virtqueue::new(layout) };

        Ok(Self {
            common, notify, notify_off_multiplier,
            queue: IrqSafeSpinLock::new(Some(queue)),
            _q_buf: q_buf, pool,
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
        let mut table = narf_bus::msix::enable_msix(cap, device)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        // 2. Alloc IDT vector + reserve table slot 0.
        let v = narf_interrupts::vector::alloc()
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let _ = table.alloc_vector().ok_or(VirtioPciError::BarMapFailed)?;
        // 3. Program slot 0.
        // SAFETY: caller-authority, exclusive ownership.
        let _ = unsafe { table.program_vector(0, 0, v) }
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        // SAFETY: same.
        let _ = unsafe { table.enable() }
            .map_err(|_| VirtioPciError::BarMapFailed)?;
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
        self.msix       = Some(table);
        Ok(v)
    }

    /// Issue a single 512-byte write at `sector`. Polled.
    pub fn write_sector(&self, sector: u64, data: &[u8; 512])
        -> Result<(), VirtioPciError>
    {
        // Build header into the per-request pool slot 0.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            core::ptr::write_volatile(header_phys as *mut BlkHeader, BlkHeader {
                type_tag: VIRTIO_BLK_T_OUT, _resv: 0, sector,
            });
            core::ptr::write_volatile(status_phys as *mut u8, 0xFFu8);
        }
        // Stage the payload into a fresh DMA page.
        let payload = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA buffer; fill the first 512 bytes
        // with the caller's data.
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile((payload_phys + i as u64) as *mut u8, data[i]);
            }
        }
        // For Write, payload is read-only from the device's POV.
        let descs = [
            VirtqDesc { addr: header_phys,  len: 16,  flags: 0,                  next: 0 },
            VirtqDesc { addr: payload_phys, len: 512, flags: 0,                  next: 0 },
            VirtqDesc { addr: status_phys,  len: 1,   flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let notify_off = (self.queue_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(notify_off, 0); }
        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile(status_phys as *const u8) };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() { q.free_chain(head); }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        let _ = payload;
        Ok(())
    }

    /// Issue a single 512-byte read at `sector` and copy the result
    /// into `out`. Polled — the IRQ-driven path lands once we wire
    /// MSI-X for virtio-pci (a follow-up).
    pub fn read_sector(&self, sector: u64, out: &mut [u8; 512])
        -> Result<(), VirtioPciError>
    {
        // Build header + status into the per-request pool slot 0.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            core::ptr::write_volatile(header_phys as *mut BlkHeader, BlkHeader {
                type_tag: VIRTIO_BLK_T_IN, _resv: 0, sector,
            });
            core::ptr::write_volatile(status_phys as *mut u8, 0xFFu8);
        }

        // Allocate a 4 KiB DMA scratch buffer for the read payload.
        // (DMA buffers are page-sized; we only consume 512 bytes.)
        let payload = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA buffer; zero the first 512 bytes so
        // a stale read shows up clearly if the device misses our
        // request.
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile((payload_phys + i as u64) as *mut u8, 0);
            }
        }

        let descs = [
            VirtqDesc { addr: header_phys,  len: 16,  flags: 0,                    next: 0 },
            VirtqDesc { addr: payload_phys, len: 512, flags: VIRTQ_DESC_F_WRITE,   next: 0 },
            VirtqDesc { addr: status_phys,  len: 1,   flags: VIRTQ_DESC_F_WRITE,   next: 0 },
        ];

        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };

        // Notify queue 0. The notify register address is
        //   notify_base + queue_notify_off * notify_off_multiplier
        let notify_off = (self.queue_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: notify cap region is identity-mapped MMIO; offset
        // bounded by the device's queue_notify_off.
        unsafe { self.notify.write16(notify_off, 0); }

        // Poll the used ring for our completion.
        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _len)) = elem {
                if id == head as u32 { break; }
            }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }

        // Read the status byte; non-zero means I/O error.
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile(status_phys as *const u8) };
        if status != VIRTIO_BLK_S_OK {
            // Free chain to avoid leak.
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() { q.free_chain(head); }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Copy the payload out.
        // SAFETY: identity-mapped 4 KiB page.
        for i in 0..512usize {
            out[i] = unsafe {
                core::ptr::read_volatile((payload_phys + i as u64) as *const u8)
            };
        }

        // Free the descriptor chain.
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        // payload drops here — controller doesn't reference it after
        // the used-ring entry arrived.
        let _ = payload;
        Ok(())
    }

    /// Negotiated queue size.
    pub fn queue_size(&self) -> u16 { self.qsize }

    /// IRQ-driven variant of `write_sector`. Same shape as
    /// `read_sector_irq` — submit, await fire_count or used-ring,
    /// drain, return.
    pub fn write_sector_irq(&self, sector: u64, data: &[u8; 512])
        -> Result<(), VirtioPciError>
    {
        let v = match self.irq_vector {
            Some(v) => v,
            None    => return self.write_sector(sector, data),
        };
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(header_phys as *mut BlkHeader, BlkHeader {
                type_tag: VIRTIO_BLK_T_OUT, _resv: 0, sector,
            });
            core::ptr::write_volatile(status_phys as *mut u8, 0xFFu8);
        }
        let payload = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized DMA.
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile(
                    (payload_phys + i as u64) as *mut u8, data[i]);
            }
        }
        let descs = [
            VirtqDesc { addr: header_phys,  len: 16,  flags: 0,                  next: 0 },
            VirtqDesc { addr: payload_phys, len: 512, flags: 0,                  next: 0 },
            VirtqDesc { addr: status_phys,  len: 1,   flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];
        let baseline = narf_interrupts::fire_count(v);
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let notify_off = (self.queue_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(notify_off, 0); }
        let mut spins = 0u32;
        loop {
            if narf_interrupts::fire_count(v) > baseline { break; }
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        loop {
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            match elem {
                Some((id, _)) if id == head as u32 => break,
                Some(_) => continue,
                None    => core::hint::spin_loop(),
            }
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile(status_phys as *const u8) };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() { q.free_chain(head); }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        let _ = payload;
        Ok(())
    }

    /// IRQ-driven variant of `read_sector`. Submits the request,
    /// then polls on `narf_interrupts::fire_count(irq_vector)` —
    /// the same atomic `wait_for_irq.await` consumes. Falls through
    /// to the polled `read_sector` if MSI-X isn't enabled yet.
    pub fn read_sector_irq(&self, sector: u64, out: &mut [u8; 512])
        -> Result<(), VirtioPciError>
    {
        let v = match self.irq_vector {
            Some(v) => v,
            None    => return self.read_sector(sector, out),
        };
        // Build header.
        let pool_phys = self.pool.phys_addr().raw();
        let header_phys = pool_phys;
        let status_phys = pool_phys + 16;
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(header_phys as *mut BlkHeader, BlkHeader {
                type_tag: VIRTIO_BLK_T_IN, _resv: 0, sector,
            });
            core::ptr::write_volatile(status_phys as *mut u8, 0xFFu8);
        }
        let payload = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let payload_phys = payload.phys_addr().raw();
        // SAFETY: page-sized.
        unsafe {
            for i in 0..512usize {
                core::ptr::write_volatile((payload_phys + i as u64) as *mut u8, 0);
            }
        }
        let descs = [
            VirtqDesc { addr: header_phys,  len: 16,  flags: 0,                  next: 0 },
            VirtqDesc { addr: payload_phys, len: 512, flags: VIRTQ_DESC_F_WRITE, next: 0 },
            VirtqDesc { addr: status_phys,  len: 1,   flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];

        let baseline = narf_interrupts::fire_count(v);
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };

        let notify_off = (self.queue_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(notify_off, 0); }

        // Wait for either the IRQ to fire or the used ring to
        // advance. Defensive — stale or coalesced IRQ deliveries
        // won't strand the request.
        let mut spins = 0u32;
        loop {
            if narf_interrupts::fire_count(v) > baseline { break; }
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        // Drain the used ring.
        loop {
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            match elem {
                Some((id, _)) if id == head as u32 => break,
                Some(_) => continue,
                None    => {
                    // IRQ fired but used ring wasn't fully populated
                    // yet; tight wait-and-retry.
                    core::hint::spin_loop();
                }
            }
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile(status_phys as *const u8) };
        if status != VIRTIO_BLK_S_OK {
            let mut g = self.queue.lock();
            if let Some(q) = g.as_mut() { q.free_chain(head); }
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        // SAFETY: same.
        for i in 0..512usize {
            out[i] = unsafe {
                core::ptr::read_volatile((payload_phys + i as u64) as *const u8)
            };
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        let _ = payload;
        Ok(())
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Sync wrapper that lets the kernel's block registry address
/// virtio-blk uniformly with NVMe + AHCI. Wraps the singleton
/// CONTROLLER. Reads / writes go through the polled
/// `read_sector` / `write_sector` paths.
#[derive(Debug)]
pub struct VirtioBlkBlockSync;

impl narf_block::BlockDeviceSync for VirtioBlkBlockSync {
    fn lba_size(&self) -> u32 { 512 }
    fn capacity(&self) -> u64 { 0 } // Stage-4 stub — capacity from device cfg lands later.
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8])
        -> Result<(), narf_block::BlockIoError>
    {
        if n_blocks != 1 { return Err(narf_block::BlockIoError::BufferTooSmall); }
        if out.len() < 512 { return Err(narf_block::BlockIoError::BufferTooSmall); }
        let g = CONTROLLER.lock();
        let dev = g.as_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let mut tmp = [0u8; 512];
        dev.read_sector(lba, &mut tmp)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        out[..512].copy_from_slice(&tmp);
        Ok(())
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8])
        -> Result<(), narf_block::BlockIoError>
    {
        if n_blocks != 1 { return Err(narf_block::BlockIoError::BufferTooSmall); }
        if data.len() < 512 { return Err(narf_block::BlockIoError::BufferTooSmall); }
        let g = CONTROLLER.lock();
        let dev = g.as_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let mut buf = [0u8; 512];
        buf.copy_from_slice(&data[..512]);
        dev.write_sector(lba, &buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        Ok(())
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioBlkPci>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
/// Idempotent: returns `Ok(())` when the controller is already
/// brought up.
pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    // Enable MEM_SPACE + BUS_MASTER on the device. Without BME the
    // virtio-pci controller can't DMA the descriptor / used rings.
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority, exclusive ownership of the device's
    // cfg + BAR windows for the duration of bring_up.
    let dev = match unsafe { VirtioBlkPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    // Register against the unified block-device registry.
    narf_block::register_block_device("vblk0",
        alloc::sync::Arc::new(VirtioBlkBlockSync)
            as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("vblk0"),
        kind:    narf_drivers::BoundKind::Block,
        pci_vid: Some(VIRTIO_BLK_PCI_VENDOR),
        pci_did: Some(VIRTIO_BLK_PCI_DEVICE),
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
    CONTROLLER.lock().as_ref().map(f)
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

/// Enable MSI-X-driven completion on the probed controller. The
/// caller supplies the `Cap<BusDeviceCap, Write>` they got from
/// `claim_device_cap` (the same one the bus's match-table dispatch
/// hands the probe). Returns the IDT vector wired into the device.
pub fn enable_msix_for_probed(
    cap:    &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<u8, VirtioPciError> {
    let mut g = CONTROLLER.lock();
    let dev = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
    if let Some(v) = dev.irq_vector { return Ok(v); }
    // SAFETY: caller-authority over the device.
    unsafe { dev.enable_msix(cap, device) }
}

/// Mutable accessor for the probed controller — used by tests that
/// want to switch on MSI-X mid-suite. Wave-3a pragmatic surface;
/// proper Wave-3b API has the registry hand back a typed handle.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut VirtioBlkPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}

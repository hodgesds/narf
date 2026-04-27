//! virtio-rng over modern virtio-PCI transport (VirtIO 1.2 §5.4).
//!
//! Modern virtio-rng's PCI device id is `0x1040 + 4 = 0x1044`.
//! Single virtqueue. Driver puts a device-writable descriptor on
//! the queue with the buffer where the device should write entropy;
//! device fills it + posts to the used ring.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS,
    CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE,
    CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{Virtqueue, VirtqueueLayout, VirtqDesc, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
    VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_RNG_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_RNG_PCI_DEVICE: u16 = 0x1044;

pub struct VirtioRngPci {
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    queue:  IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf: DmaBuffer,
    queue_notify_off: u16,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioRngPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioRngPci")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioRngPci {
    /// # Safety
    /// Caller owns the device exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset + ACK + DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8);
        }

        // Feature negotiation: only VERSION_1.
        // SAFETY: same.
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
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Queue 0 setup.
        // SAFETY: same.
        let qmax = unsafe {
            common.write16(CC_QUEUE_SELECT, 0);
            common.read16(CC_QUEUE_SIZE)
        };
        if qmax == 0 { return Err(VirtioPciError::QueueTooSmall); }
        // Use a small power-of-two depth ≤ qmax. virtio-rng often
        // exposes qmax = 1; we still want a sensible request buffer.
        let mut qsize = 4u16.min(qmax);
        if !qsize.is_power_of_two() {
            // Round down to the largest power of 2 ≤ qsize.
            qsize = 1 << (15 - qsize.leading_zeros() as u16);
        }
        if qsize == 0 { qsize = 1; }

        let q_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let layout = VirtqueueLayout::new(qsize, q_buf.phys_addr().raw())
            .ok_or(VirtioPciError::QueueTooSmall)?;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write16(CC_QUEUE_SIZE, qsize);
            common.write64_split(CC_QUEUE_DESC,   layout.desc_table);
            common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
            common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
            // VIRTIO_MSI_NO_VECTOR — explicitly tell the device we
            // don't want MSI-X delivery on this queue, so it falls
            // back to legacy / polled completion.
            common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
        }
        // SAFETY: same.
        let queue_notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
        // SAFETY: same.
        unsafe { common.write16(CC_QUEUE_ENABLE, 1); }

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // SAFETY: q_buf is zero-initialised coherent DMA.
        let queue = unsafe { Virtqueue::new(layout) };
        Ok(Self {
            notify, notify_off_multiplier,
            queue: IrqSafeSpinLock::new(Some(queue)),
            _q_buf: q_buf,
            queue_notify_off,
            ready: true,
        })
    }

    /// Diagnostic snapshot of the queue's used_idx — useful when a
    /// completion-timeout is suspected, to see whether the device
    /// has bumped used at all.
    pub fn diag_used_idx(&self) -> u16 {
        let g = self.queue.lock();
        let q = match g.as_ref() { Some(q) => q, None => return 0xFFFF };
        q.used_idx_snapshot()
    }

    /// Read up to `out.len()` bytes of entropy. Polled. The device
    /// may write fewer bytes than requested; returns the actual
    /// count.
    pub fn read_bytes(&self, out: &mut [u8]) -> Result<usize, VirtioPciError> {
        if out.is_empty() { return Ok(0); }
        let len = out.len().min(4096);
        let buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let phys = buf.phys_addr().raw();
        // SAFETY: page-sized.
        unsafe {
            for i in 0..len {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, 0);
            }
        }
        let descs = [
            VirtqDesc { addr: phys, len: len as u32, flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];
        let head = {
            let mut g = self.queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::AddBufferFailed)?
        };
        let off = (self.queue_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(off, 0); }
        let mut spins = 0u32;
        let used_len = loop {
            let elem = {
                let mut g = self.queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, l)) = elem { if id == head as u32 { break l as usize; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::CompletionTimeout); }
            core::hint::spin_loop();
        };
        let n = used_len.min(len);
        // SAFETY: identity-mapped DMA.
        for i in 0..n {
            out[i] = unsafe { core::ptr::read_volatile((phys + i as u64) as *const u8) };
        }
        let mut g = self.queue.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        let _ = buf;
        Ok(n)
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioRngPci>> =
    IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { VirtioRngPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("vrng0"),
        kind:    narf_drivers::BoundKind::Rng,
        pci_vid: Some(VIRTIO_RNG_PCI_VENDOR),
        pci_did: Some(VIRTIO_RNG_PCI_DEVICE),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-rng-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_RNG_PCI_VENDOR,
            device: VIRTIO_RNG_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioRngPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

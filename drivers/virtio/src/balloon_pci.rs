//! virtio-balloon over modern virtio-PCI transport (VirtIO 1.2 §5.5).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-balloon's PCI device id is `0x1040 + 5 = 0x1045`.
//! Two virtqueues:
//!   - 0 = inflate (driver hands pages to the host).
//!   - 1 = deflate (host returns pages to the driver).
//!
//! Wire format for both queues (VirtIO 1.2 §5.5.6.1): the driver
//! posts a single descriptor whose payload is a packed
//! `le32` array of PFNs (page-frame numbers, page = 4 KiB). Host
//! ack'd via the used ring; no per-element status.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF,
    CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_BALLOON_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_BALLOON_PCI_DEVICE: u16 = 0x1045;

/// Maximum PFN array length per submission. Inflate / deflate scratch
/// is a single 4 KiB page; with 4 B per PFN that's 1024 PFNs per call.
pub const MAX_PFNS_PER_REQ: usize = 1024;

pub struct VirtioBalloonPci {
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    inflate_q: IrqSafeSpinLock<Option<Virtqueue>>,
    deflate_q: IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf_inflate: DmaBuffer,
    _q_buf_deflate: DmaBuffer,
    /// Scratch DMA pages holding the PFN array for one outstanding
    /// inflate / deflate at a time.
    inflate_buf: DmaBuffer,
    deflate_buf: DmaBuffer,
    inflate_notify_off: u16,
    deflate_notify_off: u16,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioBalloonPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBalloonPci")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioBalloonPci {
    /// # Safety
    /// Caller owns the device exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: caller-owned.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset + ACK + DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
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
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: same.
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Queues 0 (inflate) and 1 (deflate).
        let setup_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer, u16), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            let qsize = 4u16.min(qmax);
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout = VirtqueueLayout::new(qsize, buf.dma_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
                common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // SAFETY: same.
            let nof = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            Ok((layout, buf, nof))
        };
        let (inf_layout, inf_buf, inflate_notify_off) = setup_q(0)?;
        let (def_layout, def_buf, deflate_notify_off) = setup_q(1)?;

        // Scratch DMA buffers for the per-call PFN arrays. One page
        // each → 1024 PFNs per submission. Allocated once at probe so
        // inflate / deflate don't allocate on the hot path.
        let inflate_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let deflate_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        // DRIVER_OK.
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

        // SAFETY: Virtqueue::new wipes the layout regions; the
        // backing pages may be recycled (alloc_frame doesn't zero).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let inflate_q = unsafe { Virtqueue::new(inf_layout) };
        // SAFETY: same.
        let deflate_q = unsafe { Virtqueue::new(def_layout) };
        Ok(Self {
            notify,
            notify_off_multiplier,
            inflate_q: IrqSafeSpinLock::new(Some(inflate_q)),
            deflate_q: IrqSafeSpinLock::new(Some(deflate_q)),
            _q_buf_inflate: inf_buf,
            _q_buf_deflate: def_buf,
            inflate_buf,
            deflate_buf,
            inflate_notify_off,
            deflate_notify_off,
            ready: true,
        })
    }

    /// Submit `pfns` to the inflate queue. Each PFN is a guest
    /// 4 KiB page index (phys >> 12). Polled completion. Bounded
    /// to `MAX_PFNS_PER_REQ` (1024) per call by the scratch buffer.
    pub fn inflate(&self, pfns: &[u32]) -> Result<(), VirtioPciError> {
        self.submit_pfns(/*queue=*/ 0, pfns)
    }

    /// Submit `pfns` to the deflate queue (return pages to driver).
    /// Same constraints as `inflate`.
    pub fn deflate(&self, pfns: &[u32]) -> Result<(), VirtioPciError> {
        self.submit_pfns(/*queue=*/ 1, pfns)
    }

    fn submit_pfns(&self, queue: u8, pfns: &[u32]) -> Result<(), VirtioPciError> {
        if pfns.is_empty() {
            return Ok(());
        }
        if pfns.len() > MAX_PFNS_PER_REQ {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let (lock, buf, q_notify_off, q_idx) = match queue {
            0 => (
                &self.inflate_q,
                &self.inflate_buf,
                self.inflate_notify_off,
                0u16,
            ),
            1 => (
                &self.deflate_q,
                &self.deflate_buf,
                self.deflate_notify_off,
                1u16,
            ),
            _ => return Err(VirtioPciError::NoQueues),
        };
        let phys = buf.dma_addr().raw();
        // SAFETY: identity-mapped scratch DMA, single-flight per queue.
        unsafe {
            for (i, p) in pfns.iter().enumerate() {
                core::ptr::write_volatile(buf.cpu_mut_ptr_at::<u32>((i * 4) as u64), p.to_le());
            }
        }
        let descs = [VirtqDesc {
            addr: phys,
            len: (pfns.len() * 4) as u32,
            flags: 0,
            next: 0,
        }];
        let head = {
            let mut g = lock.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs)
                .ok_or(VirtioPciError::AddBufferFailed)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * q_notify_off as u64,
                q_idx,
            );
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for the device to publish a used-ring entry.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = lock.lock();
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
            let mut g = lock.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(head);
            }
            return Err(VirtioPciError::CompletionTimeout);
        }
        let mut g = lock.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(())
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioBalloonPci>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { VirtioBalloonPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vballoon0"),
        kind: narf_drivers::BoundKind::Balloon,
        pci_vid: Some(VIRTIO_BALLOON_PCI_VENDOR),
        pci_did: Some(VIRTIO_BALLOON_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Balloon.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-balloon-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_BALLOON_PCI_VENDOR,
            device: VIRTIO_BALLOON_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioBalloonPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

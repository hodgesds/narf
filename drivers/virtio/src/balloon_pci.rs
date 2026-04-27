//! virtio-balloon over modern virtio-PCI transport (VirtIO 1.2 §5.5).
//!
//! Modern virtio-balloon's PCI device id is `0x1040 + 5 = 0x1045`.
//! Two virtqueues:
//!   - 0 = inflate (driver hands pages to the host).
//!   - 1 = deflate (host returns pages to the driver).
//!
//! Stage-4 cut: structural bring-up. The actual page-handoff logic
//! ties into `narf_memory`'s frame allocator and lands once the
//! kernel needs guest-side memory pressure response. Probe-only.

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
use crate::queue::{Virtqueue, VirtqueueLayout};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
    VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_BALLOON_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_BALLOON_PCI_DEVICE: u16 = 0x1045;

pub struct VirtioBalloonPci {
    inflate_q: IrqSafeSpinLock<Option<Virtqueue>>,
    deflate_q: IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf_inflate: DmaBuffer,
    _q_buf_deflate: DmaBuffer,
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
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;

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

        // Queues 0 (inflate) and 1 (deflate).
        let setup_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 { return Err(VirtioPciError::QueueTooSmall); }
            let qsize = 4u16.min(qmax);
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout = VirtqueueLayout::new(qsize, buf.phys_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC,   layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
                common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // queue_notify_off captured but not used by this stub.
            // SAFETY: same.
            let _ = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            Ok((layout, buf))
        };
        let (inf_layout, inf_buf) = setup_q(0)?;
        let (def_layout, def_buf) = setup_q(1)?;

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // SAFETY: queue buffers freshly zeroed.
        let inflate_q = unsafe { Virtqueue::new(inf_layout) };
        // SAFETY: same.
        let deflate_q = unsafe { Virtqueue::new(def_layout) };
        Ok(Self {
            inflate_q: IrqSafeSpinLock::new(Some(inflate_q)),
            deflate_q: IrqSafeSpinLock::new(Some(deflate_q)),
            _q_buf_inflate: inf_buf,
            _q_buf_deflate: def_buf,
            ready: true,
        })
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioBalloonPci>> =
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
    let dev = match unsafe { VirtioBalloonPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
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

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

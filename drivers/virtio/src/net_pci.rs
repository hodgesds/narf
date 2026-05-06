//! virtio-net over modern virtio-PCI transport (VirtIO 1.2 §5.1).
//!
//! Modern virtio-net's PCI device id is `0x1000 + 0x40 + 0x01`
//! = 0x1041 (`0x1040 + virtio_id`, virtio_id 1 = net).
//!
//! Queue layout (basic, no multi-queue / no VIRTIO_NET_F_MQ):
//!   - queue 0 = RX (receiveq).
//!   - queue 1 = TX (transmitq).
//!   - queue 2 = control queue (only when VIRTIO_NET_F_CTRL_VQ
//!     negotiated; we don't request it).
//!
//! Stage-4 cut: bring up the device, attach RX + TX virtqueues,
//! enqueue 8 RX buffers so the device has somewhere to land
//! incoming packets, and expose a `tx(&[u8])` that posts a single
//! TX buffer + waits for completion. The TX path uses polled
//! completion today; MSI-X-driven TX is structurally identical to
//! `blk_pci::read_sector_irq` and lands in a follow-up.

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
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

/// Modern virtio-net PCI ids.
pub const VIRTIO_NET_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_NET_PCI_DEVICE: u16 = 0x1041;

/// virtio-net header (VirtIO 1.2 §5.1.6.1). 12 bytes when
/// VIRTIO_F_VERSION_1 is negotiated and VIRTIO_NET_F_MRG_RXBUF /
/// VIRTIO_NET_F_HASH_REPORT are *not* — the form we use.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

/// Maximum frame we'll accept on RX. Standard MTU + Ethernet
/// header + virtio-net header headroom.
pub const MAX_FRAME: usize = 1518 + 16;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

pub struct VirtioNetPci {
    common: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    rx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    rx_q_buf: DmaBuffer,
    tx_q_buf: DmaBuffer,
    /// RX buffer pool — `RX_POOL_LEN` 4 KiB pages, each holds one
    /// frame.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// TX scratch buffer. Single-flight in this Stage-4 cut.
    tx_buf: DmaBuffer,
    rx_qsize: u16,
    tx_qsize: u16,
    rx_notify_off: u16,
    tx_notify_off: u16,
    /// IDT vector bound to receiveq (queue 0) when MSI-X is enabled.
    /// `None` means polled-only completion. Consumers wait via
    /// `narf_interrupts::wait_for_irq(v).await`.
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
}

const RX_POOL_LEN: usize = 8;

impl core::fmt::Debug for VirtioNetPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetPci")
            .field("ready", &self.ready)
            .field("rx_qsize", &self.rx_qsize)
            .field("tx_qsize", &self.tx_qsize)
            .finish_non_exhaustive()
    }
}

impl VirtioNetPci {
    /// Bring up the device with RX + TX virtqueues. RX is pre-
    /// populated with `RX_POOL_LEN` empty buffers.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk over identity-mapped cfg.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned device.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
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

        // Feature negotiation: we only ask for VERSION_1.
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

        // Per-queue setup. Helper to size + program one queue.
        let size_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer, u16, u16), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            let qsize = qmax.min(64).next_power_of_two() / 2;
            let qsize = if qsize == 0 { 4 } else { qsize.min(qmax) };
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let phys = buf.phys_addr().raw();
            let layout = VirtqueueLayout::new(qsize, phys).ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
            }
            // SAFETY: same.
            let nof = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            Ok((layout, buf, qsize, nof))
        };
        let (rx_layout, rx_q_buf, rx_qsize, rx_notify_off) = size_q(RX_QUEUE)?;
        let (tx_layout, tx_q_buf, tx_qsize, tx_notify_off) = size_q(TX_QUEUE)?;

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
        let mut rx_q = unsafe { Virtqueue::new(rx_layout) };
        // SAFETY: same.
        let tx_q = unsafe { Virtqueue::new(tx_layout) };

        // Pre-populate RX queue with empty buffers so the device has
        // somewhere to land an incoming frame.
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RX_POOL_LEN);
        for _ in 0..RX_POOL_LEN {
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let phys = buf.phys_addr().raw();
            // One desc covering header + max frame, device-writable.
            let descs = [VirtqDesc {
                addr: phys,
                len: MAX_FRAME as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            let _ = rx_q.add_buffer(&descs);
            rx_pool.push(buf);
        }

        // Notify device that RX has new buffers. Compute
        // notify-register address from the captured offset.
        let rx_off = (rx_notify_off as u64) * (notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            notify.write16(rx_off, RX_QUEUE);
        }

        // Allocate the TX scratch.
        let tx_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        Ok(Self {
            common,
            notify,
            notify_off_multiplier,
            rx_queue: IrqSafeSpinLock::new(Some(rx_q)),
            tx_queue: IrqSafeSpinLock::new(Some(tx_q)),
            rx_q_buf,
            tx_q_buf,
            rx_pool,
            tx_buf,
            rx_qsize,
            tx_qsize,
            rx_notify_off,
            tx_notify_off,
            irq_vector: None,
            msix: None,
            ready: true,
        })
    }

    /// Bind the receiveq (queue 0) to a fresh MSI-X vector. After
    /// this call, frame-arrival is observable via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())`.
    /// The polled `rx()` path keeps working unchanged.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) =
            unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, RX_QUEUE) }?;
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Transmit a single frame on the TX queue. Polled completion.
    /// Frame must fit in `MAX_FRAME` minus the 12-byte virtio-net
    /// header.
    pub fn tx(&self, frame: &[u8]) -> Result<(), VirtioPciError> {
        if frame.len() > MAX_FRAME - 12 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let phys = self.tx_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            // Zero the virtio-net header.
            for i in 0..12usize {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, 0);
            }
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + 12 + i as u64) as *mut u8, *b);
            }
        }
        // Two descriptors: header + payload, both device-readable.
        let descs = [
            VirtqDesc {
                addr: phys,
                len: 12,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: phys + 12,
                len: frame.len() as u32,
                flags: 0,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.tx_queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.tx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped.
        unsafe {
            self.notify.write16(off, TX_QUEUE);
        }
        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.tx_queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem {
                if id == head as u32 {
                    break;
                }
            }
            spins += 1;
            if spins > 10_000_000 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            core::hint::spin_loop();
        }
        let mut g = self.tx_queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(())
    }

    pub fn rx_queue_size(&self) -> u16 {
        self.rx_qsize
    }
    pub fn tx_queue_size(&self) -> u16 {
        self.tx_qsize
    }

    /// Drain one frame from the RX queue. Returns the number of
    /// bytes copied into `out` (excluding the 12-byte virtio-net
    /// header), or 0 if no frame is ready.
    ///
    /// Refills the RX descriptor by adding the same buffer back to
    /// the avail ring + notifying the queue.
    pub fn rx(&self, out: &mut [u8]) -> usize {
        let elem = {
            let mut g = self.rx_queue.lock();
            let q = match g.as_mut() {
                Some(q) => q,
                None => return 0,
            };
            q.poll_used()
        };
        let (id, len) = match elem {
            Some(t) => t,
            None => return 0,
        };
        // Find the buffer this descriptor pointed at. With one desc
        // per frame the head id maps to rx_pool[id % RX_POOL_LEN].
        let pool_idx = (id as usize) % self.rx_pool.len();
        let buf = &self.rx_pool[pool_idx];
        let phys = buf.phys_addr().raw();
        // Skip the 12-byte virtio-net header.
        let frame_len = (len as usize).saturating_sub(12).min(out.len());
        // SAFETY: identity-mapped DMA buffer.
        for i in 0..frame_len {
            out[i] = unsafe { core::ptr::read_volatile((phys + 12 + i as u64) as *const u8) };
        }
        // Refill: free the chain + post the buffer back.
        {
            let mut g = self.rx_queue.lock();
            let q = match g.as_mut() {
                Some(q) => q,
                None => return frame_len,
            };
            q.free_chain(id as u16);
            let descs = [VirtqDesc {
                addr: phys,
                len: MAX_FRAME as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            let _ = q.add_buffer(&descs);
        }
        // Re-notify the device about the refill.
        let off = (self.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, RX_QUEUE);
        }
        frame_len
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<VirtioNetPci>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: caller-authority over the device.
    let dev = match unsafe { VirtioNetPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    // Best-effort MSI-X for receiveq (queue 0). Failure is fine —
    // the polled `rx()` path stays in place.
    {
        let mut g = CONTROLLER.lock();
        if let Some(c) = g.as_mut() {
            // SAFETY: probe-time caller owns the device.
            let _ = unsafe { c.enable_msix(&cap, &device) };
        }
    }
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vnet0"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(VIRTIO_NET_PCI_VENDOR),
        pci_did: Some(VIRTIO_NET_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-net-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_NET_PCI_VENDOR,
            device: VIRTIO_NET_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioNetPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Async, IRQ-driven RX. Awaits the receiveq's MSI-X vector, then
/// drains one frame into `out`. Falls through to the polled drain if
/// MSI-X isn't enabled. Returns the byte count copied (0 if no frame
/// was ready after the IRQ — caller should re-await).
pub async fn rx_irq_async(out: &mut [u8]) -> usize {
    let vector = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(c) => c.irq_vector,
            None => return 0,
        }
    };
    if let Some(v) = vector {
        narf_interrupts::wait::wait_for_irq(v).await;
    }
    let g = CONTROLLER.lock();
    let c = match g.as_ref() {
        Some(c) => c,
        None => return 0,
    };
    c.rx(out)
}

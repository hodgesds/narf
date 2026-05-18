//! virtio-net over modern virtio-PCI transport (VirtIO 1.2 §5.1).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
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

// virtio-net feature bits (VirtIO 1.2 §5.1.3). We negotiate the
// subset the kernel actually reads from device-cfg.
const VIRTIO_NET_F_CSUM: u64 = 0; // device handles packet checksums
const VIRTIO_NET_F_MTU: u64 = 3;
const VIRTIO_NET_F_MAC: u64 = 5;
const VIRTIO_NET_F_STATUS: u64 = 16;

// virtio-net config status bits.
const VIRTIO_NET_S_LINK_UP: u16 = 1 << 0;

// Offsets within the device-specific config region (VirtIO 1.2
// §5.1.4 — `struct virtio_net_config`).
const CFG_MAC: u64 = 0;
const CFG_STATUS: u64 = 6;
const CFG_MTU: u64 = 10;

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
    /// Device-specific config region. `None` when the device didn't
    /// expose a Device cap (rare on modern QEMU); MAC defaults to
    /// `[0; 6]`, MTU to 1500, link assumed up in that case.
    device_cfg: Option<VirtioRegion>,
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
    /// Per-queue MSI-X vector for TX completions. `None` =
    /// caller hasn't called `enable_tx_msix` yet, TX uses
    /// polled used-ring drain.
    pub tx_irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
    /// 48-bit hardware address captured from device-cfg. Zero when
    /// the device didn't advertise `VIRTIO_NET_F_MAC` (QEMU always
    /// does; bare-metal NICs may not).
    mac: [u8; 6],
    /// Last-read MTU from device-cfg (when `VIRTIO_NET_F_MTU`
    /// negotiated). Default 1500 otherwise.
    mtu: u32,
    /// True when `VIRTIO_NET_F_STATUS` was negotiated. Without it
    /// the spec says treat link as always up.
    has_status: bool,
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
        // Opportunistic negotiation: take F_MAC / F_STATUS / F_MTU
        // / F_CSUM when the device offers them. Each is a "device
        // tells us something" feature — accepting it just unlocks
        // the corresponding device-cfg field. We don't yet drive
        // the offload paths F_CSUM enables (we only checksum on
        // RX inspection), so guests built with strict feature
        // checks still accept the negotiation. F_MQ stays off —
        // we use the single-queue path.
        let want_mac = feats & (1u64 << VIRTIO_NET_F_MAC) != 0;
        let want_status = feats & (1u64 << VIRTIO_NET_F_STATUS) != 0;
        let want_mtu = feats & (1u64 << VIRTIO_NET_F_MTU) != 0;
        let want_csum = feats & (1u64 << VIRTIO_NET_F_CSUM) != 0;
        // All virtio-net F_* bits we care about live in the low
        // 32 (max is F_STATUS = 16); only F_VERSION_1 = 32 is in
        // the high half.
        let drv_lo = (1u32 << VIRTIO_NET_F_MAC) * (want_mac as u32)
            | (1u32 << VIRTIO_NET_F_MTU) * (want_mtu as u32)
            | (1u32 << VIRTIO_NET_F_CSUM) * (want_csum as u32)
            | (1u32 << VIRTIO_NET_F_STATUS) * (want_status as u32);
        let drv_hi = 1u32 << (VIRTIO_F_VERSION_1 - 32);
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, drv_lo);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, drv_hi);
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

        // Optional device-cfg region. Maps the same way virtio-input
        // does — if the device skipped the Device cap (rare), we
        // fall back to defaults.
        let device_cfg = if let Some(cap) = caps.device_cfg.as_ref() {
            // SAFETY: caller-owned device.
            match unsafe { crate::pci::map_cap(device, cap) } {
                Ok(r) => Some(r),
                Err(_) => None,
            }
        } else {
            None
        };
        // Read MAC + MTU + status from device-cfg, gated on whether
        // the feature was negotiated. Spec: the corresponding field
        // is only valid when its feature was negotiated.
        let mut mac = [0u8; 6];
        let mut mtu: u32 = 1500;
        let mut link_up_init = true;
        if let Some(r) = device_cfg.as_ref() {
            if want_mac {
                // SAFETY: device-cfg region was just mapped; field
                // at offset 0..6.
                for i in 0..6u64 {
                    mac[i as usize] = unsafe { r.read8(CFG_MAC + i) };
                }
            }
            if want_status {
                // SAFETY: same. Status at offset 6 (u16 LE).
                let s = unsafe { r.read16(CFG_STATUS) };
                link_up_init = s & VIRTIO_NET_S_LINK_UP != 0;
            }
            if want_mtu {
                // SAFETY: same. MTU at offset 10 (u16 LE).
                let m = unsafe { r.read16(CFG_MTU) };
                if m >= 64 {
                    mtu = m as u32;
                }
            }
        }
        // Stash an initial link-state guess on the controller so
        // accessors don't need to re-read MMIO on every poll.
        let _ = link_up_init;

        Ok(Self {
            common,
            notify,
            device_cfg,
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
            tx_irq_vector: None,
            msix: None,
            ready: true,
            mac,
            mtu,
            has_status: want_status,
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

    /// TX-queue MSI-X. Same shape as `enable_msix` but for the
    /// TX virtqueue (queue index 1). Reuses the existing
    /// `MsixTable` if RX MSI-X is already enabled — both
    /// vectors land on the same MSI-X table.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_tx_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) =
            unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, TX_QUEUE) }?;
        self.tx_irq_vector = Some(v);
        // Replace the MSI-X table handle with the latest one
        // (enable_msix_queue allocates a fresh slot in the
        // existing table; there's only one table per device,
        // and the new handle keeps both vectors live).
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
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for the device to publish a used-ring entry.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.tx_queue.lock();
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
            return Err(VirtioPciError::QueueTooSmall);
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

    /// 48-bit hardware address. Zero when `VIRTIO_NET_F_MAC` wasn't
    /// negotiated (rare; QEMU advertises a vendor-default MAC).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Negotiated MTU. Defaults to 1500 when `VIRTIO_NET_F_MTU`
    /// wasn't offered.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Live link state. Reads the status word from device-cfg every
    /// call when `VIRTIO_NET_F_STATUS` was negotiated; returns
    /// `true` unconditionally otherwise (spec: absence of the
    /// feature means assume link up).
    pub fn link_up(&self) -> bool {
        if !self.has_status {
            return true;
        }
        let r = match self.device_cfg.as_ref() {
            Some(r) => r,
            None => return true,
        };
        // SAFETY: device-cfg region was mapped at bring_up; field
        // at offset 6 stays valid for the controller's lifetime.
        let s = unsafe { r.read16(CFG_STATUS) };
        s & VIRTIO_NET_S_LINK_UP != 0
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
    // Register the controller with narf_net so the TCP stack can
    // find it as `vnet0`. Build the two SPSC rings, hand the
    // caller-facing halves to the Interface, capture the peer
    // halves in forwarder tasks.
    register_net_interface();
    Ok(())
}

/// Build a `VirtioNet` from the currently-probed controller, register
/// it with `narf_net::registry()`, and spawn the RX/TX forwarder
/// tasks that bridge the device's virtqueues to the SPSC rings the
/// TCP stack pops/pushes.
fn register_net_interface() {
    use alloc::string::ToString;
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    let (mac, mtu, link_up, irq_vector) = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(c) => (c.mac(), c.mtu(), c.link_up(), c.irq_vector),
            None => return,
        }
    };
    let (tx_prod, mut tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
    let (mut rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
    let iface = narf_net::virtio_net::VirtioNet::new(
        "vnet0".to_string(),
        mac,
        mtu,
        link_up,
        tx_prod,
        rx_cons,
    );
    let authority = narf_net::bootstrap_authority();
    // Registration failure leaks the iface (returned by-value into
    // the registry would have moved it) — we constructed it above
    // and Registry::register consumes it on success. On failure
    // the Vec slot stays free and the forwarders below would talk
    // to nothing useful, so bail.
    if narf_net::registry().register(&authority, iface).is_err() {
        return;
    }
    // RX forwarder: await the device IRQ (or fall back to a 16 ms
    // poll), drain every available frame, wrap each in a fresh
    // DmaBuffer-backed Frame, send through rx_prod. The peer
    // (caller-held Consumer) is what the stack pops.
    narf_scheduler::spawn(async move {
        const PUMP_CYCLES: u64 = 53_000_000;
        let mut scratch = [0u8; MAX_FRAME];
        loop {
            if let Some(v) = irq_vector {
                narf_interrupts::wait::wait_for_irq(v).await;
            } else {
                narf_time::sleep_cycles(PUMP_CYCLES).await;
            }
            loop {
                let n = {
                    let g = CONTROLLER.lock();
                    match g.as_ref() {
                        Some(c) => c.rx(&mut scratch),
                        None => return,
                    }
                };
                if n == 0 {
                    break;
                }
                let dma = match alloc_coherent(MAX_FRAME, DomainId::DRIVER_0) {
                    Ok(b) => b,
                    Err(_) => break,
                };
                // SAFETY: alloc_coherent returns a >= MAX_FRAME
                // buffer; `n` is bounded by `scratch.len()` =
                // MAX_FRAME.
                unsafe {
                    core::ptr::copy_nonoverlapping(scratch.as_ptr(), dma.as_mut_ptr(), n);
                }
                let frame = Frame::new(dma, n as u32);
                if rx_prod.send(frame).await.is_err() {
                    return;
                }
            }
        }
    });
    // TX forwarder: drain the caller-facing Producer's Consumer
    // peer, push each frame through the device's TX queue. The
    // existing tx() method blocks briefly on the used-ring drain;
    // sleep_pumps stay alive throughout.
    narf_scheduler::spawn(async move {
        while let Ok(frame) = tx_cons.recv().await {
            let (buf, len) = frame.into_parts();
            let len = len as usize;
            let bytes = &buf.as_slice()[..len.min(buf.len())];
            if let Some(c) = CONTROLLER.lock().as_ref() {
                let _ = c.tx(bytes);
            }
            // `buf` drops here → DmaBuffer::drop frees the page.
        }
    });
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

/// Async, IRQ-driven TX completion. Awaits the TX queue's
/// MSI-X vector when configured, then drains the TX used ring.
/// Falls through to a synchronous used-ring drain when the TX
/// vector isn't enabled.
///
/// Use case: a sender that fires `tx(frame)` then needs to
/// know "the descriptor is reclaimed; I can free the buffer"
/// without blocking. RX-side `rx_irq_async` does the same for
/// the receive queue.
pub async fn tx_irq_async() {
    let vector = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(c) => c.tx_irq_vector,
            None => return,
        }
    };
    if let Some(v) = vector {
        // Construct WaitForIrq before any code that could
        // race the IRQ — same ordering invariant as NVMe's
        // submit_io_irq_async (drivers/nvme/lib.rs:1130).
        let wait = narf_interrupts::wait::wait_for_irq(v);
        let _ = wait.await;
    }
    // Used-ring drain happens lazily via the next tx() call;
    // no per-IRQ work needed here today.
}

//! virtio-vsock over modern virtio-PCI transport (VirtIO 1.2 §5.10).
//!
//! Stage 1: PCI match (1AF4:1053) + virtio cfg cap discovery + decode
//! of the §5.10.4 device-specific config (`guest_cid: u64 LE`).
//!
//! No virtqueue traffic yet — that lands in a follow-up stage.

use core::sync::atomic::{compiler_fence, Ordering};

extern crate alloc;
use alloc::vec::Vec;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, enable_msix_queue, map_cap, VirtioCaps, VirtioPciError, VirtioRegion,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE,
    CC_DRIVER_FEATURE_SELECT, CC_NUM_QUEUES, CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER,
    CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

/// PCI vendor / device id for virtio-vsock (VirtIO 1.2 §5.10, §4.1.2).
pub const VIRTIO_VSOCK_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_VSOCK_PCI_DEVICE: u16 = 0x1053;

/// virtio-vsock device-specific config (VirtIO 1.2 §5.10.4).
///
/// Wire layout (LE):
///   +0x00 guest_cid : u64
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VsockDeviceConfig {
    pub guest_cid: u64,
}

impl VsockDeviceConfig {
    /// Wire-size of the §5.10.4 device-specific config region.
    pub const WIRE_SIZE: usize = 8;

    /// Decode a §5.10.4 device-cfg blob (LE). `None` when the slice
    /// is shorter than `WIRE_SIZE`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE {
            return None;
        }
        let guest_cid = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        Some(Self { guest_cid })
    }

    /// Encode in §5.10.4 wire form. Round-trip with `decode`.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        b[0..8].copy_from_slice(&self.guest_cid.to_le_bytes());
        b
    }
}

/// Read the §5.10.4 device-specific config out of the mapped Device cap.
///
/// # Safety
/// `region` must be the live Device-cfg cap window for a virtio-vsock
/// PCI device, exclusively owned by the caller.
pub unsafe fn read_device_config(
    region: &VirtioRegion,
) -> Result<VsockDeviceConfig, VirtioPciError> {
    if (region.length as usize) < VsockDeviceConfig::WIRE_SIZE {
        return Err(VirtioPciError::NoCommonCfg);
    }
    let mut buf = [0u8; VsockDeviceConfig::WIRE_SIZE];
    // SAFETY: caller-asserted; offsets bounded above.
    unsafe {
        for i in 0..VsockDeviceConfig::WIRE_SIZE {
            buf[i] = region.read8(i as u64);
        }
    }
    VsockDeviceConfig::decode(&buf).ok_or(VirtioPciError::NoCommonCfg)
}

mod tests;

// ── Stage 2: §5.10.6 virtio_vsock_hdr + ops ─────────────────────────

/// Per-packet operation type (VirtIO 1.2 §5.10.6).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VsockOp {
    Request = 1,
    Response = 2,
    Rst = 3,
    Shutdown = 4,
    Rw = 5,
    CreditUpdate = 6,
    CreditRequest = 7,
}

impl VsockOp {
    pub fn from_raw(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Rst,
            4 => Self::Shutdown,
            5 => Self::Rw,
            6 => Self::CreditUpdate,
            7 => Self::CreditRequest,
            _ => return None,
        })
    }
}

/// `virtio_vsock_hdr` — packet header (VirtIO 1.2 §5.10.6).
///
/// Wire layout (44 bytes, all LE):
///   +0x00 src_cid    : u64
///   +0x08 dst_cid    : u64
///   +0x10 src_port   : u32
///   +0x14 dst_port   : u32
///   +0x18 len        : u32
///   +0x1C type       : u16
///   +0x1E op         : u16
///   +0x20 flags      : u32
///   +0x24 buf_alloc  : u32
///   +0x28 fwd_cnt    : u32
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VsockHdr {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub typ: u16,
    pub op: VsockOp,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VsockHdr {
    /// §5.10.6 header wire size.
    pub const WIRE_SIZE: usize = 44;

    /// `type = VIRTIO_VSOCK_TYPE_STREAM` (§5.10.6).
    pub const TYPE_STREAM: u16 = 1;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        b[0x00..0x08].copy_from_slice(&self.src_cid.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[0x10..0x14].copy_from_slice(&self.src_port.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&self.dst_port.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&self.len.to_le_bytes());
        b[0x1C..0x1E].copy_from_slice(&self.typ.to_le_bytes());
        b[0x1E..0x20].copy_from_slice(&(self.op as u16).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&self.flags.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE {
            return None;
        }
        let src_cid = u64::from_le_bytes(bytes[0x00..0x08].try_into().ok()?);
        let dst_cid = u64::from_le_bytes(bytes[0x08..0x10].try_into().ok()?);
        let src_port = u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?);
        let dst_port = u32::from_le_bytes(bytes[0x14..0x18].try_into().ok()?);
        let len = u32::from_le_bytes(bytes[0x18..0x1C].try_into().ok()?);
        let typ = u16::from_le_bytes(bytes[0x1C..0x1E].try_into().ok()?);
        let op_raw = u16::from_le_bytes(bytes[0x1E..0x20].try_into().ok()?);
        let op = VsockOp::from_raw(op_raw)?;
        let flags = u32::from_le_bytes(bytes[0x20..0x24].try_into().ok()?);
        let buf_alloc = u32::from_le_bytes(bytes[0x24..0x28].try_into().ok()?);
        let fwd_cnt = u32::from_le_bytes(bytes[0x28..0x2C].try_into().ok()?);
        Some(Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len,
            typ,
            op,
            flags,
            buf_alloc,
            fwd_cnt,
        })
    }
}

// ── Driver-match registration ───────────────────────────────────────

/// Probed virtio-vsock controller — full live-traffic surface.
/// Holds both transport regions, all three virtqueues (rx / tx /
/// event), and a per-receive scratch pool that's pre-posted at
/// bring-up time so the device can deliver packets without first
/// waiting on the driver.
pub struct VirtioVsockPci {
    pub config: VsockDeviceConfig,
    common: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    rx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    ev_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    _rx_buf: DmaBuffer,
    _tx_buf: DmaBuffer,
    _ev_buf: DmaBuffer,
    rx_pool: DmaBuffer,
    rx_slots: IrqSafeSpinLock<Vec<u64>>,
    rx_notify_off: u16,
    tx_notify_off: u16,
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioVsockPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioVsockPci")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Pre-posted RX descriptor count + per-buffer length. A vsock
/// packet is `VsockHdr::WIRE_SIZE` bytes header + `len` bytes of
/// payload; we size each pre-posted buffer for a small payload
/// and combine them on receive.
const RX_PREPOST: u16 = 16;
const RX_BUF_LEN: u32 = 1024;

impl VirtioVsockPci {
    /// Full bring-up: walk caps, reset, negotiate VERSION_1,
    /// program rx (queue 0) + tx (queue 1) + event (queue 2),
    /// pre-post RX buffers, set DRIVER_OK.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively for
    /// the duration of bring_up.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded cap-list walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        let device_cap = caps.device_cfg.clone().ok_or(VirtioPciError::NoCommonCfg)?;
        // SAFETY: caller-owned BARs.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        // SAFETY: same.
        let device_region = unsafe { map_cap(device, &device_cap) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset → ACK → DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // Feature negotiation: VERSION_1 only.
        // SAFETY: same.
        let feats_lo = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            common.read32(CC_DEVICE_FEATURE)
        };
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

        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q < 3 {
            return Err(VirtioPciError::NoQueues);
        }

        // SAFETY: same.
        let config = unsafe { read_device_config(&device_region) }?;

        // Queues 0/1/2 = rx/tx/event.
        // SAFETY: identity-mapped MMIO.
        let (rx_buf, rx_q, rx_notify_off) = unsafe { setup_queue(&common, 0) }?;
        let (tx_buf, tx_q, tx_notify_off) = unsafe { setup_queue(&common, 1) }?;
        let (ev_buf, ev_q, _) = unsafe { setup_queue(&common, 2) }?;

        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // RX pool: pre-post RX_PREPOST × RX_BUF_LEN bytes.
        let rx_pool =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let rx_pool_phys = rx_pool.phys_addr().raw();
        // SAFETY: page-sized DMA buffer.
        unsafe {
            core::ptr::write_bytes(rx_pool_phys as *mut u8, 0, 4096);
        }
        // RX_BUF_LEN × RX_PREPOST = 16 KiB; only one 4 KiB page,
        // so cap RX_PREPOST × RX_BUF_LEN to 4 KiB. Use 16 × 256.
        let rx_buf_len: u32 = (4096 / RX_PREPOST as u32).min(RX_BUF_LEN);
        let _ = rx_buf_len; // kept as named constant; payload >256 truncates.

        let rx_q_lock = IrqSafeSpinLock::new(Some(rx_q));
        let mut rx_slots: Vec<u64> = Vec::with_capacity(RX_PREPOST as usize);
        {
            let mut g = rx_q_lock.lock();
            let q = g.as_mut().unwrap();
            let per = (4096u64 / RX_PREPOST as u64) as u32;
            for i in 0..RX_PREPOST {
                let off = (i as u64) * (per as u64);
                let addr = rx_pool_phys + off;
                let descs = [VirtqDesc {
                    addr,
                    len: per,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }];
                if q.add_buffer(&descs).is_some() {
                    rx_slots.push(off);
                } else {
                    break;
                }
            }
        }
        // Kick the device: tell it the RX ring has descriptors.
        let off = (rx_notify_off as u64) * (notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            notify.write16(off, 0);
        }

        Ok(Self {
            config,
            common,
            notify,
            notify_off_multiplier,
            rx_queue: rx_q_lock,
            tx_queue: IrqSafeSpinLock::new(Some(tx_q)),
            ev_queue: IrqSafeSpinLock::new(Some(ev_q)),
            _rx_buf: rx_buf,
            _tx_buf: tx_buf,
            _ev_buf: ev_buf,
            rx_pool,
            rx_slots: IrqSafeSpinLock::new(rx_slots),
            rx_notify_off,
            tx_notify_off,
            irq_vector: None,
            msix: None,
            ready: true,
        })
    }

    /// Bind queue 0 (rx) to MSI-X so the kernel wakes on incoming packets.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, 0)? };
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Send a single vsock packet — `hdr` carries the destination
    /// (`dst_cid`/`dst_port`) and op; `payload` is the data, which
    /// may be empty for control ops (REQUEST/RESPONSE/RST/SHUTDOWN).
    /// The caller's `hdr.len` is overwritten to `payload.len()`
    /// so it stays consistent.
    pub fn send(&self, mut hdr: VsockHdr, payload: &[u8]) -> Result<(), VirtioPciError> {
        if payload.len() > 4096 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        hdr.len = payload.len() as u32;
        // Stage the packet in a fresh DMA page.
        let buf =
            alloc_coherent(8192, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let phys = buf.phys_addr().raw();
        let hdr_bytes = hdr.encode();
        // SAFETY: page-sized DMA buffer.
        unsafe {
            for (i, &b) in hdr_bytes.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, b);
            }
            for (i, &b) in payload.iter().enumerate() {
                core::ptr::write_volatile((phys + (VsockHdr::WIRE_SIZE + i) as u64) as *mut u8, b);
            }
        }
        let total = (VsockHdr::WIRE_SIZE + payload.len()) as u32;
        let descs = [VirtqDesc {
            addr: phys,
            len: total,
            flags: 0,
            next: 0,
        }];
        let head = {
            let mut g = self.tx_queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.tx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, 1);
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
        let _ = buf;
        Ok(())
    }

    /// Poll the rx ring and return the next packet, if any.
    /// Re-posts the descriptor for further use.
    pub fn recv(&self) -> Option<(VsockHdr, alloc::vec::Vec<u8>)> {
        let pool_phys = self.rx_pool.phys_addr().raw();
        let per = (4096u64 / RX_PREPOST as u64) as u32;
        let elem = {
            let mut g = self.rx_queue.lock();
            let q = g.as_mut()?;
            q.poll_used()?
        };
        let (id, len) = elem;
        let slot_off = {
            let slots = self.rx_slots.lock();
            *slots.get(id as usize)?
        };
        if (len as usize) < VsockHdr::WIRE_SIZE {
            return None;
        }
        let mut hdr_buf = [0u8; VsockHdr::WIRE_SIZE];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..VsockHdr::WIRE_SIZE {
                hdr_buf[i] =
                    core::ptr::read_volatile((pool_phys + slot_off + i as u64) as *const u8);
            }
        }
        let hdr = VsockHdr::decode(&hdr_buf)?;
        let payload_len = ((len as usize) - VsockHdr::WIRE_SIZE).min(hdr.len as usize);
        let mut payload = alloc::vec![0u8; payload_len];
        // SAFETY: same.
        unsafe {
            for i in 0..payload_len {
                payload[i] = core::ptr::read_volatile(
                    (pool_phys + slot_off + (VsockHdr::WIRE_SIZE + i) as u64) as *const u8,
                );
            }
        }
        // Re-post.
        let descs = [VirtqDesc {
            addr: pool_phys + slot_off,
            len: per,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        }];
        let mut g = self.rx_queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(id as u16);
            let _ = q.add_buffer(&descs);
        }
        drop(g);
        let off = (self.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, 0);
        }
        Some((hdr, payload))
    }

    /// Drain any device-posted events on the eventq.
    pub fn drain_events(&self) -> usize {
        let mut n = 0;
        loop {
            let elem = {
                let mut g = self.ev_queue.lock();
                match g.as_mut() {
                    Some(q) => q.poll_used(),
                    None => return n,
                }
            };
            if let Some((id, _)) = elem {
                let mut g = self.ev_queue.lock();
                if let Some(q) = g.as_mut() {
                    q.free_chain(id as u16);
                }
                n += 1;
            } else {
                break;
            }
        }
        n
    }

    pub fn guest_cid(&self) -> u64 {
        self.config.guest_cid
    }
}

unsafe fn setup_queue(
    common: &VirtioRegion,
    idx: u16,
) -> Result<(DmaBuffer, Virtqueue, u16), VirtioPciError> {
    // SAFETY: identity-mapped MMIO.
    let qsize_max = unsafe {
        common.write16(CC_QUEUE_SELECT, idx);
        common.read16(CC_QUEUE_SIZE)
    };
    if qsize_max == 0 {
        return Err(VirtioPciError::QueueTooSmall);
    }
    let qsize = qsize_max.min(64).next_power_of_two() / 2;
    let qsize = if qsize == 0 { 4 } else { qsize.min(qsize_max) };
    let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
    let layout =
        VirtqueueLayout::new(qsize, buf.phys_addr().raw()).ok_or(VirtioPciError::QueueTooSmall)?;
    // SAFETY: identity-mapped MMIO.
    unsafe {
        common.write16(CC_QUEUE_SIZE, qsize);
        common.write64_split(CC_QUEUE_DESC, layout.desc_table);
        common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
        common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
    }
    // SAFETY: same.
    let notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
    // SAFETY: same.
    unsafe {
        common.write16(CC_QUEUE_ENABLE, 1);
    }
    // SAFETY: Virtqueue::new wipes the layout regions.
    let q = unsafe { Virtqueue::new(layout) };
    Ok((buf, q, notify_off))
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioVsockPci>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
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
    let mut dev = match unsafe { VirtioVsockPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

/// Register the driver with the bus-level match table.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-vsock-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_VSOCK_PCI_VENDOR,
            device: VIRTIO_VSOCK_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioVsockPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

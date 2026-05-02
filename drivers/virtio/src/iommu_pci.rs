//! virtio-iommu over modern virtio-PCI transport (VirtIO 1.2 §5.16).
//!
//! Stage 1: PCI match (1AF4:1057) + virtio cfg cap discovery + decode
//! of the device-specific config (§5.16.4).
//! Stage 2: pure-data builders for the request types in §5.16.6.
//!
//! No virtqueue traffic yet — that lands in a follow-up stage.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, enable_msix_queue, map_cap, VirtioCaps, VirtioPciError,
    VirtioRegion,
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

/// PCI vendor / device id for virtio-iommu (VirtIO 1.2 §5.16, §4.1.2).
pub const VIRTIO_IOMMU_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_IOMMU_PCI_DEVICE: u16 = 0x1057;

/// virtio-iommu device-specific config (VirtIO 1.2 §5.16.4).
///
/// Wire layout (all LE):
///   +0x00 page_size_mask   : u64
///   +0x08 input_range.start: u64
///   +0x10 input_range.end  : u64
///   +0x18 domain_range.start: u32
///   +0x1C domain_range.end : u32
///   +0x20 probe_size       : u32
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IommuDeviceConfig {
    pub page_size_mask:   u64,
    pub input_range_start: u64,
    pub input_range_end:   u64,
    pub domain_range_start: u32,
    pub domain_range_end:   u32,
    pub probe_size:        u32,
}

impl IommuDeviceConfig {
    /// Wire-size of the device-specific config region.
    pub const WIRE_SIZE: usize = 0x24;

    /// Decode a §5.16.4 device-cfg blob (LE). Returns `None` if the
    /// caller's slice is shorter than `WIRE_SIZE`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let r64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        Some(Self {
            page_size_mask:     r64(0x00),
            input_range_start:  r64(0x08),
            input_range_end:    r64(0x10),
            domain_range_start: r32(0x18),
            domain_range_end:   r32(0x1C),
            probe_size:         r32(0x20),
        })
    }

    /// Encode in §5.16.4 wire form. Round-trip with `decode`.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        b[0x00..0x08].copy_from_slice(&self.page_size_mask.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&self.input_range_start.to_le_bytes());
        b[0x10..0x18].copy_from_slice(&self.input_range_end.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&self.domain_range_start.to_le_bytes());
        b[0x1C..0x20].copy_from_slice(&self.domain_range_end.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&self.probe_size.to_le_bytes());
        b
    }
}

/// Read the §5.16.4 device-specific config out of the mapped Device cap.
///
/// # Safety
/// `region` must be the live Device-cfg cap window for a virtio-iommu
/// PCI device, exclusively owned by the caller.
pub unsafe fn read_device_config(region: &VirtioRegion)
    -> Result<IommuDeviceConfig, VirtioPciError>
{
    if (region.length as usize) < IommuDeviceConfig::WIRE_SIZE {
        return Err(VirtioPciError::NoCommonCfg);
    }
    let mut buf = [0u8; IommuDeviceConfig::WIRE_SIZE];
    // SAFETY: caller-asserted; offsets bounded above.
    unsafe {
        for i in 0..IommuDeviceConfig::WIRE_SIZE {
            buf[i] = region.read8(i as u64);
        }
    }
    IommuDeviceConfig::decode(&buf).ok_or(VirtioPciError::NoCommonCfg)
}

// ── Stage 2: §5.16.6 request builders ──────────────────────────────

/// Request opcodes (VirtIO 1.2 §5.16.6).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IommuOp {
    Attach = 1,
    Detach = 2,
    Map    = 3,
    Unmap  = 4,
    Probe  = 5,
}

impl IommuOp {
    pub fn from_raw(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Attach,
            2 => Self::Detach,
            3 => Self::Map,
            4 => Self::Unmap,
            5 => Self::Probe,
            _ => return None,
        })
    }
}

/// Common 16-byte request header (§5.16.6).
///
/// Wire layout:
///   +0x00 type       : u8   (one of `IommuOp`)
///   +0x01 reserved   : u8 × 3
///   +0x04 flags      : u32 LE
///   +0x08 _padding   : u8 × 8 (kept zero so payloads align at +0x10)
///
/// The spec defines per-request structs that prefix a `tail` (status +
/// reserved). Headers here are the request envelope; the per-op
/// `Req*` structs below are the payloads that follow.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqHeader {
    pub op:    IommuOp,
    pub flags: u32,
}

impl ReqHeader {
    pub const WIRE_SIZE: usize = 16;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        b[0] = self.op as u8;
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let op = IommuOp::from_raw(bytes[0])?;
        let flags = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        Some(Self { op, flags })
    }
}

/// `virtio_iommu_req_attach` payload (§5.16.6.1).
///
/// Wire layout (after the 16-byte header):
///   domain   : u32 LE
///   endpoint : u32 LE
///   reserved : u8 × 8
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqAttach {
    pub domain:   u32,
    pub endpoint: u32,
}

impl ReqAttach {
    pub const PAYLOAD_SIZE: usize = 16;
    pub const WIRE_SIZE:    usize = ReqHeader::WIRE_SIZE + Self::PAYLOAD_SIZE;

    pub fn encode(&self, flags: u32) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        let h = ReqHeader { op: IommuOp::Attach, flags }.encode();
        b[..ReqHeader::WIRE_SIZE].copy_from_slice(&h);
        let p = ReqHeader::WIRE_SIZE;
        b[p..p + 4].copy_from_slice(&self.domain.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&self.endpoint.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<(ReqHeader, Self)> {
        let h = ReqHeader::decode(bytes)?;
        if h.op != IommuOp::Attach { return None; }
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let p = ReqHeader::WIRE_SIZE;
        let domain   = u32::from_le_bytes(bytes[p..p + 4].try_into().ok()?);
        let endpoint = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().ok()?);
        Some((h, Self { domain, endpoint }))
    }
}

/// `virtio_iommu_req_detach` payload (§5.16.6.2).
///
/// Wire layout (after the 16-byte header):
///   domain   : u32 LE
///   endpoint : u32 LE
///   reserved : u8 × 8
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqDetach {
    pub domain:   u32,
    pub endpoint: u32,
}

impl ReqDetach {
    pub const PAYLOAD_SIZE: usize = 16;
    pub const WIRE_SIZE:    usize = ReqHeader::WIRE_SIZE + Self::PAYLOAD_SIZE;

    pub fn encode(&self, flags: u32) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        let h = ReqHeader { op: IommuOp::Detach, flags }.encode();
        b[..ReqHeader::WIRE_SIZE].copy_from_slice(&h);
        let p = ReqHeader::WIRE_SIZE;
        b[p..p + 4].copy_from_slice(&self.domain.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&self.endpoint.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<(ReqHeader, Self)> {
        let h = ReqHeader::decode(bytes)?;
        if h.op != IommuOp::Detach { return None; }
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let p = ReqHeader::WIRE_SIZE;
        let domain   = u32::from_le_bytes(bytes[p..p + 4].try_into().ok()?);
        let endpoint = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().ok()?);
        Some((h, Self { domain, endpoint }))
    }
}

/// `virtio_iommu_req_map` payload (§5.16.6.3).
///
/// Wire layout (after the 16-byte header):
///   domain      : u32 LE
///   _reserved   : u32 LE (zero on the wire)
///   virt_start  : u64 LE
///   virt_end    : u64 LE
///   phys_start  : u64 LE
///   flags_inner : u32 LE   (per-mapping flags, distinct from header.flags)
///   _reserved2  : u32 LE
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqMap {
    pub domain:     u32,
    pub virt_start: u64,
    pub virt_end:   u64,
    pub phys_start: u64,
    pub map_flags:  u32,
}

impl ReqMap {
    pub const PAYLOAD_SIZE: usize = 40;
    pub const WIRE_SIZE:    usize = ReqHeader::WIRE_SIZE + Self::PAYLOAD_SIZE;

    pub fn encode(&self, flags: u32) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        let h = ReqHeader { op: IommuOp::Map, flags }.encode();
        b[..ReqHeader::WIRE_SIZE].copy_from_slice(&h);
        let p = ReqHeader::WIRE_SIZE;
        b[p..p + 4].copy_from_slice(&self.domain.to_le_bytes());
        // +4..+8 reserved
        b[p + 8..p + 16].copy_from_slice(&self.virt_start.to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&self.virt_end.to_le_bytes());
        b[p + 24..p + 32].copy_from_slice(&self.phys_start.to_le_bytes());
        b[p + 32..p + 36].copy_from_slice(&self.map_flags.to_le_bytes());
        // +36..+40 reserved
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<(ReqHeader, Self)> {
        let h = ReqHeader::decode(bytes)?;
        if h.op != IommuOp::Map { return None; }
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let p = ReqHeader::WIRE_SIZE;
        let domain     = u32::from_le_bytes(bytes[p..p + 4].try_into().ok()?);
        let virt_start = u64::from_le_bytes(bytes[p + 8..p + 16].try_into().ok()?);
        let virt_end   = u64::from_le_bytes(bytes[p + 16..p + 24].try_into().ok()?);
        let phys_start = u64::from_le_bytes(bytes[p + 24..p + 32].try_into().ok()?);
        let map_flags  = u32::from_le_bytes(bytes[p + 32..p + 36].try_into().ok()?);
        Some((h, Self { domain, virt_start, virt_end, phys_start, map_flags }))
    }
}

/// `virtio_iommu_req_unmap` payload (§5.16.6.4).
///
/// Wire layout (after the 16-byte header):
///   domain     : u32 LE
///   _reserved  : u32 LE
///   virt_start : u64 LE
///   virt_end   : u64 LE
///   _reserved2 : u8 × 4
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReqUnmap {
    pub domain:     u32,
    pub virt_start: u64,
    pub virt_end:   u64,
}

impl ReqUnmap {
    pub const PAYLOAD_SIZE: usize = 24;
    pub const WIRE_SIZE:    usize = ReqHeader::WIRE_SIZE + Self::PAYLOAD_SIZE;

    pub fn encode(&self, flags: u32) -> [u8; Self::WIRE_SIZE] {
        let mut b = [0u8; Self::WIRE_SIZE];
        let h = ReqHeader { op: IommuOp::Unmap, flags }.encode();
        b[..ReqHeader::WIRE_SIZE].copy_from_slice(&h);
        let p = ReqHeader::WIRE_SIZE;
        b[p..p + 4].copy_from_slice(&self.domain.to_le_bytes());
        // +4..+8 reserved
        b[p + 8..p + 16].copy_from_slice(&self.virt_start.to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&self.virt_end.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Option<(ReqHeader, Self)> {
        let h = ReqHeader::decode(bytes)?;
        if h.op != IommuOp::Unmap { return None; }
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let p = ReqHeader::WIRE_SIZE;
        let domain     = u32::from_le_bytes(bytes[p..p + 4].try_into().ok()?);
        let virt_start = u64::from_le_bytes(bytes[p + 8..p + 16].try_into().ok()?);
        let virt_end   = u64::from_le_bytes(bytes[p + 16..p + 24].try_into().ok()?);
        Some((h, Self { domain, virt_start, virt_end }))
    }
}

// ── Driver-match registration ───────────────────────────────────────

/// `virtio_iommu_req_tail` (§5.16.6): 4-byte device-written tail
/// appended after every request. Status 0 = OK, 1 = IO error,
/// 2 = unsupported, 3 = invalid, 4 = range, 5 = entry-conflict.
pub const REQ_TAIL_LEN: usize = 4;
pub const STATUS_OK: u8 = 0;

/// Probed virtio-iommu controller. Holds the live transport
/// regions, the request queue, plus a 4 KiB request scratch
/// pool — the driver issues one request at a time.
pub struct VirtioIommuPci {
    pub config: IommuDeviceConfig,
    common:                VirtioRegion,
    notify:                VirtioRegion,
    notify_off_multiplier: u32,
    requestq:              IrqSafeSpinLock<Option<Virtqueue>>,
    eventq:                IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf:                DmaBuffer,
    _eq_buf:               DmaBuffer,
    /// 4 KiB pool for the next request: the encoded request lives
    /// at offset 0; the device writes the 4-byte tail at offset
    /// 0x800. Single-inflight driver — the lock around `requestq`
    /// already serialises callers.
    pool:                  DmaBuffer,
    request_notify_off:    u16,
    pub irq_vector:        Option<u8>,
    msix:                  Option<narf_bus::MsixTable>,
    pub ready:             bool,
}

impl core::fmt::Debug for VirtioIommuPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioIommuPci")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl VirtioIommuPci {
    /// Full bring-up: walk caps, reset, negotiate VERSION_1,
    /// program both virtqueues, set DRIVER_OK.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively for
    /// the duration of bring_up.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded cap-list walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        let device_cap = caps.device_cfg.clone().ok_or(VirtioPciError::NoCommonCfg)?;
        // SAFETY: caller-owned BAR.
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
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8);
        }

        // Feature negotiation: VERSION_1 only.
        // SAFETY: identity-mapped MMIO.
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
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK) as u8);
        }
        // SAFETY: same.
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q < 2 { return Err(VirtioPciError::NoQueues); }

        // SAFETY: same.
        let config = unsafe { read_device_config(&device_region) }?;

        // Queue 0 = requestq, queue 1 = eventq.
        let (q_buf, requestq, request_notify_off) =
            // SAFETY: identity-mapped MMIO.
            unsafe { setup_queue(&common, 0) }?;
        let (eq_buf, eventq, _) =
            // SAFETY: same.
            unsafe { setup_queue(&common, 1) }?;

        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // Pool: 4 KiB scratch — request at +0, tail-write slot
        // at +0x800.
        let pool = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let pool_phys = pool.phys_addr().raw();
        // SAFETY: page-sized DMA.
        unsafe { core::ptr::write_bytes(pool_phys as *mut u8, 0, 4096); }

        Ok(Self {
            config,
            common, notify, notify_off_multiplier,
            requestq: IrqSafeSpinLock::new(Some(requestq)),
            eventq:   IrqSafeSpinLock::new(Some(eventq)),
            _q_buf: q_buf, _eq_buf: eq_buf,
            pool,
            request_notify_off,
            irq_vector: None,
            msix:       None,
            ready: true,
        })
    }

    /// Bind the request queue (queue 0) to an MSI-X vector so the
    /// kernel gets woken on completion.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap:    &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, 0)? };
        self.irq_vector = Some(v);
        self.msix       = Some(table);
        Ok(v)
    }

    /// Issue a single request (encoded bytes), wait for completion,
    /// return the tail status. The request is staged at pool[0..N];
    /// the device writes its 4-byte tail at pool[0x800..0x804].
    fn submit_request(&self, req: &[u8]) -> Result<u8, VirtioPciError> {
        if req.is_empty() || req.len() > 0x800 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let pool_phys = self.pool.phys_addr().raw();
        let req_phys  = pool_phys;
        let tail_phys = pool_phys + 0x800;
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            for (i, &b) in req.iter().enumerate() {
                core::ptr::write_volatile((req_phys + i as u64) as *mut u8, b);
            }
            // Mark the tail slot so a stale 0 can't masquerade as OK.
            core::ptr::write_volatile(tail_phys as *mut u8, 0xFF);
            for i in 1..REQ_TAIL_LEN {
                core::ptr::write_volatile((tail_phys + i as u64) as *mut u8, 0);
            }
        }
        let descs = [
            VirtqDesc { addr: req_phys,  len: req.len() as u32, flags: 0,                  next: 0 },
            VirtqDesc { addr: tail_phys, len: REQ_TAIL_LEN as u32,
                        flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];
        let head = {
            let mut g = self.requestq.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.request_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(off, 0); }

        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.requestq.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile(tail_phys as *const u8) };
        let mut g = self.requestq.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        Ok(status)
    }

    pub fn attach(&self, domain: u32, endpoint: u32) -> Result<u8, VirtioPciError> {
        let r = ReqAttach { domain, endpoint }.encode(0);
        self.submit_request(&r)
    }
    pub fn detach(&self, domain: u32, endpoint: u32) -> Result<u8, VirtioPciError> {
        let r = ReqDetach { domain, endpoint }.encode(0);
        self.submit_request(&r)
    }
    pub fn map(&self, domain: u32, virt_start: u64, virt_end: u64,
               phys_start: u64, map_flags: u32)
        -> Result<u8, VirtioPciError>
    {
        let r = ReqMap { domain, virt_start, virt_end, phys_start, map_flags }.encode(0);
        self.submit_request(&r)
    }
    pub fn unmap(&self, domain: u32, virt_start: u64, virt_end: u64)
        -> Result<u8, VirtioPciError>
    {
        let r = ReqUnmap { domain, virt_start, virt_end }.encode(0);
        self.submit_request(&r)
    }

    /// Draw down any async events the device has posted on the
    /// eventq. Returns the count drained. Stage-N: Fault events
    /// (§5.16.7.1). For now we just free the descriptors so the
    /// queue doesn't stall.
    pub fn drain_events(&self) -> usize {
        let mut n = 0;
        loop {
            let elem = {
                let mut g = self.eventq.lock();
                match g.as_mut() {
                    Some(q) => q.poll_used(),
                    None    => return n,
                }
            };
            if let Some((id, _)) = elem {
                let mut g = self.eventq.lock();
                if let Some(q) = g.as_mut() { q.free_chain(id as u16); }
                n += 1;
            } else {
                break;
            }
        }
        n
    }
}

/// Helper: select queue `idx`, allocate 4 KiB backing page,
/// program addresses, enable. Same shape as console_pci's helper.
unsafe fn setup_queue(
    common: &VirtioRegion,
    idx:    u16,
) -> Result<(DmaBuffer, Virtqueue, u16), VirtioPciError> {
    // SAFETY: identity-mapped MMIO.
    let qsize_max = unsafe {
        common.write16(CC_QUEUE_SELECT, idx);
        common.read16(CC_QUEUE_SIZE)
    };
    if qsize_max == 0 { return Err(VirtioPciError::QueueTooSmall); }
    let qsize = qsize_max.min(64).next_power_of_two() / 2;
    let qsize = if qsize == 0 { 4 } else { qsize.min(qsize_max) };
    let buf = alloc_coherent(4096, DomainId::DRIVER_0)
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    let layout = VirtqueueLayout::new(qsize, buf.phys_addr().raw())
        .ok_or(VirtioPciError::QueueTooSmall)?;
    // SAFETY: identity-mapped MMIO.
    unsafe {
        common.write16(CC_QUEUE_SIZE, qsize);
        common.write64_split(CC_QUEUE_DESC,   layout.desc_table);
        common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
        common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
    }
    // SAFETY: same.
    let notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
    // SAFETY: same.
    unsafe { common.write16(CC_QUEUE_ENABLE, 1); }
    // SAFETY: Virtqueue::new wipes the layout regions.
    let q = unsafe { Virtqueue::new(layout) };
    Ok((buf, q, notify_off))
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioIommuPci>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
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
    // SAFETY: caller-authority over the device.
    let mut dev = match unsafe { VirtioIommuPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
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
        name: "virtio-iommu-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_IOMMU_PCI_VENDOR,
            device: VIRTIO_IOMMU_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioIommuPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

mod tests;

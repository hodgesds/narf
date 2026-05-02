//! virtio-iommu over modern virtio-PCI transport (VirtIO 1.2 §5.16).
//!
//! Stage 1: PCI match (1AF4:1057) + virtio cfg cap discovery + decode
//! of the device-specific config (§5.16.4).
//! Stage 2: pure-data builders for the request types in §5.16.6.
//!
//! No virtqueue traffic yet — that lands in a follow-up stage.

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion};

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

/// Probed virtio-iommu controller. Holds the discovered cap snapshot
/// + decoded device config. Stage-3 bring-up will fold in queue
/// setup; for now this is structural.
pub struct VirtioIommuPci {
    pub caps:   VirtioCaps,
    pub _device_region: VirtioRegion,
    pub config: IommuDeviceConfig,
}

impl core::fmt::Debug for VirtioIommuPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioIommuPci")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl VirtioIommuPci {
    /// Probe + decode the device-specific config. Stops short of
    /// virtqueue setup.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively for the
    /// duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded cap-list walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        let device_cap = caps.device_cfg.ok_or(VirtioPciError::NoCommonCfg)?;
        // SAFETY: caller-owned BAR window.
        let region = unsafe { map_cap(device, &device_cap) }?;
        // SAFETY: same.
        let config = unsafe { read_device_config(&region) }?;
        Ok(Self { caps, _device_region: region, config })
    }
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
    let dev = match unsafe { VirtioIommuPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
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

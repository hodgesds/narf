//! virtio-vsock over modern virtio-PCI transport (VirtIO 1.2 §5.10).
//!
//! Stage 1: PCI match (1AF4:1053) + virtio cfg cap discovery + decode
//! of the §5.10.4 device-specific config (`guest_cid: u64 LE`).
//!
//! No virtqueue traffic yet — that lands in a follow-up stage.

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion};

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
        if bytes.len() < Self::WIRE_SIZE { return None; }
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
pub unsafe fn read_device_config(region: &VirtioRegion)
    -> Result<VsockDeviceConfig, VirtioPciError>
{
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
    Request       = 1,
    Response      = 2,
    Rst           = 3,
    Shutdown      = 4,
    Rw            = 5,
    CreditUpdate  = 6,
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
    pub src_cid:   u64,
    pub dst_cid:   u64,
    pub src_port:  u32,
    pub dst_port:  u32,
    pub len:       u32,
    pub typ:       u16,
    pub op:        VsockOp,
    pub flags:     u32,
    pub buf_alloc: u32,
    pub fwd_cnt:   u32,
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
        if bytes.len() < Self::WIRE_SIZE { return None; }
        let src_cid   = u64::from_le_bytes(bytes[0x00..0x08].try_into().ok()?);
        let dst_cid   = u64::from_le_bytes(bytes[0x08..0x10].try_into().ok()?);
        let src_port  = u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?);
        let dst_port  = u32::from_le_bytes(bytes[0x14..0x18].try_into().ok()?);
        let len       = u32::from_le_bytes(bytes[0x18..0x1C].try_into().ok()?);
        let typ       = u16::from_le_bytes(bytes[0x1C..0x1E].try_into().ok()?);
        let op_raw    = u16::from_le_bytes(bytes[0x1E..0x20].try_into().ok()?);
        let op        = VsockOp::from_raw(op_raw)?;
        let flags     = u32::from_le_bytes(bytes[0x20..0x24].try_into().ok()?);
        let buf_alloc = u32::from_le_bytes(bytes[0x24..0x28].try_into().ok()?);
        let fwd_cnt   = u32::from_le_bytes(bytes[0x28..0x2C].try_into().ok()?);
        Some(Self {
            src_cid, dst_cid, src_port, dst_port, len, typ, op,
            flags, buf_alloc, fwd_cnt,
        })
    }
}

// ── Driver-match registration ───────────────────────────────────────

/// Probed virtio-vsock controller. Stage-1 surface: discovered cap
/// snapshot + decoded device config. Virtqueue setup is a follow-up
/// stage.
pub struct VirtioVsockPci {
    pub caps:           VirtioCaps,
    pub _device_region: VirtioRegion,
    pub config:         VsockDeviceConfig,
}

impl core::fmt::Debug for VirtioVsockPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioVsockPci")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl VirtioVsockPci {
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

static CONTROLLER: IrqSafeSpinLock<Option<VirtioVsockPci>> =
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
    let dev = match unsafe { VirtioVsockPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
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

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioVsockPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

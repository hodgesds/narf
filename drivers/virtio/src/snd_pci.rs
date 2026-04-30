//! virtio-sound over modern virtio-PCI transport (VirtIO 1.2 §5.14).
//!
//! Modern virtio-sound's PCI device id is `0x1040 + 25 = 0x1059`.
//! Four virtqueues:
//!   - 0 = controlq (PCM info / set-params / start / stop verbs).
//!   - 1 = eventq   (jack / device-side state-change notifications).
//!   - 2 = txq      (driver → device PCM data; playback).
//!   - 3 = rxq      (device → driver PCM data; capture).
//!
//! Stage-4 cut: structural bring-up. The bring-up (a) negotiates
//! VERSION_1, (b) reads the cfg-space `virtio_snd_config` to learn
//! how many jacks / streams / chmaps the device exposes, and (c)
//! installs the four virtqueues.
//!
//! No PCM submission yet — the tx data plane lands behind the
//! `narf-audio::AudioWriter::submit` plumbing once the unified
//! DmaBuffer surface is decided. Until then this driver gives the
//! audio crate the "is_probed + topology snapshot" surface it needs
//! to advertise a stream.

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError,
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

pub const VIRTIO_SND_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_SND_PCI_DEVICE: u16 = 0x1059;

/// Virtio-sound device-cfg layout (VirtIO 1.2 §5.14.4). All fields
/// little-endian; `repr(C)` mirrors the wire format so we can read
/// the cfg BAR directly.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VirtioSndConfig {
    pub jacks:   u32,
    pub streams: u32,
    pub chmaps:  u32,
}

#[derive(Debug)]
pub struct VirtioSoundPci {
    control_q: IrqSafeSpinLock<Option<Virtqueue>>,
    event_q:   IrqSafeSpinLock<Option<Virtqueue>>,
    tx_q:      IrqSafeSpinLock<Option<Virtqueue>>,
    rx_q:      IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf_control: DmaBuffer,
    _q_buf_event:   DmaBuffer,
    _q_buf_tx:      DmaBuffer,
    _q_buf_rx:      DmaBuffer,
    pub cfg:   VirtioSndConfig,
    pub ready: bool,
}

impl VirtioSoundPci {
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

        // Feature negotiation: only VERSION_1 today.
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

        // Read device-cfg topology. The device cap's BAR is the
        // start of the device-cfg window; layout is
        // `virtio_snd_config { u32 jacks, streams, chmaps }`.
        // device_cfg is optional in the spec, but every QEMU
        // virtio-sound advertises it.
        let dev_cap = caps.device_cfg.as_ref()
            .ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        // SAFETY: caller-owned device, identity-mapped MMIO.
        let dev_cfg = unsafe { map_cap(device, dev_cap) }?;
        // SAFETY: same.
        let cfg = unsafe {
            VirtioSndConfig {
                jacks:   dev_cfg.read32(0),
                streams: dev_cfg.read32(4),
                chmaps:  dev_cfg.read32(8),
            }
        };

        // Set up four virtqueues: 0=control, 1=event, 2=tx, 3=rx.
        // Each gets a 4 KiB coherent buffer for descriptor + ring
        // storage. Stage-4: queue depth 4 per queue — virtio-sound
        // spec's minimum + matches balloon's stub footprint. Real
        // playback wants tx depth 32+, but that's a tx-data-plane
        // concern that lands with submit_pcm.
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
            // queue_notify_off captured but unused at probe time.
            // SAFETY: same.
            let _ = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            Ok((layout, buf))
        };
        let (ctrl_layout, ctrl_buf)  = setup_q(0)?;
        let (event_layout, event_buf) = setup_q(1)?;
        let (tx_layout, tx_buf)       = setup_q(2)?;
        let (rx_layout, rx_buf)       = setup_q(3)?;

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // SAFETY: queue buffers freshly zeroed by the allocator.
        let control_q = unsafe { Virtqueue::new(ctrl_layout) };
        // SAFETY: same.
        let event_q   = unsafe { Virtqueue::new(event_layout) };
        // SAFETY: same.
        let tx_q      = unsafe { Virtqueue::new(tx_layout) };
        // SAFETY: same.
        let rx_q      = unsafe { Virtqueue::new(rx_layout) };
        Ok(Self {
            control_q: IrqSafeSpinLock::new(Some(control_q)),
            event_q:   IrqSafeSpinLock::new(Some(event_q)),
            tx_q:      IrqSafeSpinLock::new(Some(tx_q)),
            rx_q:      IrqSafeSpinLock::new(Some(rx_q)),
            _q_buf_control: ctrl_buf,
            _q_buf_event:   event_buf,
            _q_buf_tx:      tx_buf,
            _q_buf_rx:      rx_buf,
            cfg,
            ready: true,
        })
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioSoundPci>> =
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
    let dev = match unsafe { VirtioSoundPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("vsnd0"),
        kind:    narf_drivers::BoundKind::Audio,
        pci_vid: Some(VIRTIO_SND_PCI_VENDOR),
        pci_did: Some(VIRTIO_SND_PCI_DEVICE),
        domain:  narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-snd-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_SND_PCI_VENDOR,
            device: VIRTIO_SND_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

/// Topology snapshot — `(jacks, streams, chmaps)`. Returns `None`
/// if the device hasn't probed.
pub fn topology() -> Option<(u32, u32, u32)> {
    CONTROLLER.lock().as_ref()
        .map(|c| (c.cfg.jacks, c.cfg.streams, c.cfg.chmaps))
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}

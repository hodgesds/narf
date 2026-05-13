//! virtio-9p (transitional / legacy) PCI driver — clean room.
//!
//! VirtIO 1.2 §5.9 ("9P transport") describes the device-specific
//! configuration; the wire protocol is Plan 9 9P2000.L
//! (https://ericvh.github.io/9p-rfc/rfc9p2000.l.html).
//!
//! Stage 1: PCI match + pure-data mount-tag decode.
//! Stage 2: 9P2000.L message builders (pure-data encode/decode).

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{compiler_fence, Ordering};

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

// ── PCI ids ────────────────────────────────────────────────────────

/// virtio-9p PCI vendor id (Red Hat).
pub const VIRTIO_9P_PCI_VENDOR: u16 = 0x1AF4;
/// virtio-9p legacy / transitional PCI device id (VirtIO 1.2 §4.1.2.1).
pub const VIRTIO_9P_PCI_DEVICE: u16 = 0x1009;

// ── §5.9.4 device-specific configuration ───────────────────────────

/// Decoded virtio-9p device-config layout (VirtIO 1.2 §5.9.4):
///   `mount_tag_len: u16 LE`
///   `mount_tag:     [u8; mount_tag_len]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTag {
    pub tag: Vec<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MountTagDecodeError {
    TooShortForLen,
    TooShortForTag,
}

impl MountTag {
    /// Decode the device-specific config region. Reads
    /// `mount_tag_len` (u16 LE) then the following `mount_tag_len`
    /// bytes of UTF-8-ish tag.
    pub fn decode(buf: &[u8]) -> Result<Self, MountTagDecodeError> {
        if buf.len() < 2 {
            return Err(MountTagDecodeError::TooShortForLen);
        }
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + len {
            return Err(MountTagDecodeError::TooShortForTag);
        }
        let mut tag = Vec::with_capacity(len);
        tag.extend_from_slice(&buf[2..2 + len]);
        Ok(Self { tag })
    }

    /// Encode back to wire form (used by smokes for round-trip).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.tag.len());
        let len = self.tag.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.tag);
        out
    }
}

// ── PCI driver registration ────────────────────────────────────────

pub struct VirtioP9Pci {
    common: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    requestq: IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf: DmaBuffer,
    /// 8 KiB scratch — request at +0, response at +0x1000.
    pool: DmaBuffer,
    request_notify_off: u16,
    pub mount_tag: MountTag,
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioP9Pci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioP9Pci")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioP9Pci {
    /// Bring up the device on its single request queue.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded cap-list walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        let device_cap = caps.device_cfg.clone().ok_or(VirtioPciError::NoCommonCfg)?;
        // SAFETY: caller-owned BARs.
        let common = unsafe { map_cap(device, &caps.common) }?;
        let notify = unsafe { map_cap(device, &caps.notify) }?;
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

        // Read mount-tag.
        // SAFETY: same.
        let tag_len = unsafe { device_region.read16(0) } as usize;
        let mut tag_bytes = alloc::vec![0u8; tag_len.min(255)];
        // SAFETY: same.
        unsafe {
            for i in 0..tag_bytes.len() {
                tag_bytes[i] = device_region.read8(2 + i as u64);
            }
        }
        let mount_tag = MountTag { tag: tag_bytes };

        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q == 0 {
            return Err(VirtioPciError::NoQueues);
        }

        // SAFETY: identity-mapped MMIO.
        let (q_buf, requestq, request_notify_off) = unsafe { setup_queue(&common, 0) }?;

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

        let pool =
            alloc_coherent(8192, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        // SAFETY: page-sized DMA.
        unsafe {
            core::ptr::write_bytes(pool.phys_addr().raw() as *mut u8, 0, 8192);
        }

        Ok(Self {
            common,
            notify,
            notify_off_multiplier,
            requestq: IrqSafeSpinLock::new(Some(requestq)),
            _q_buf: q_buf,
            pool,
            request_notify_off,
            mount_tag,
            irq_vector: None,
            msix: None,
            ready: true,
        })
    }

    /// Bind the request queue (queue 0) to MSI-X.
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

    /// Submit a 9P request and read back up to `resp_max` bytes of
    /// response. Single-inflight: the lock around the request queue
    /// already serialises callers.
    pub fn submit(&self, req: &[u8], resp_max: usize) -> Result<Vec<u8>, VirtioPciError> {
        if req.is_empty() || req.len() > 0x1000 || resp_max > 0x1000 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let pool_phys = self.pool.phys_addr().raw();
        let req_phys = pool_phys;
        let resp_phys = pool_phys + 0x1000;
        // SAFETY: identity-mapped DMA.
        unsafe {
            for (i, &b) in req.iter().enumerate() {
                core::ptr::write_volatile((req_phys + i as u64) as *mut u8, b);
            }
            core::ptr::write_bytes(resp_phys as *mut u8, 0, resp_max);
        }
        let descs = [
            VirtqDesc {
                addr: req_phys,
                len: req.len() as u32,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: resp_phys,
                len: resp_max as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.requestq.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.request_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, 0);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for the device to publish a used-ring entry.
        let mut used_len: u32 = 0;
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.requestq.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                if let Some((id, len)) = elem {
                    if id == head as u32 {
                        used_len = len;
                        return true;
                    }
                }
                false
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let n = (used_len as usize).min(resp_max);
        let mut out = alloc::vec![0u8; n];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..n {
                out[i] = core::ptr::read_volatile((resp_phys + i as u64) as *const u8);
            }
        }
        let mut g = self.requestq.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(out)
    }

    /// 9P2000.L Tversion handshake convenience.
    pub fn tversion(&self, msize: u32, version: &str) -> Result<p9::Rversion, VirtioPciError> {
        let req = p9::Tversion {
            tag: 0xFFFF,
            msize,
            version: version.as_bytes().to_vec(),
        }
        .encode();
        let resp = self.submit(&req, 0x100)?;
        p9::Rversion::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
    }

    /// Tattach: bind `fid` to the file-system root advertised by the
    /// device (`uname` is the user, `aname` is the requested
    /// subtree — empty for the mount root). 9P2000.L uses
    /// `n_uname` as the numeric uid.
    pub fn tattach(
        &self,
        tag: u16,
        fid: u32,
        uname: &[u8],
        aname: &[u8],
        n_uname: u32,
    ) -> Result<p9::Rattach, VirtioPciError> {
        let req = p9::Tattach {
            tag,
            fid,
            afid: p9::NOFID,
            uname: uname.to_vec(),
            aname: aname.to_vec(),
            n_uname,
        }
        .encode();
        let resp = self.submit(&req, 0x100)?;
        p9::Rattach::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
    }

    /// Twalk from `fid` to `newfid` traversing `wnames` (each is
    /// a path component, no `/`). Bounded to 16 by the protocol.
    pub fn twalk(
        &self,
        tag: u16,
        fid: u32,
        newfid: u32,
        wnames: &[&[u8]],
    ) -> Result<p9::Rwalk, VirtioPciError> {
        let req = p9::Twalk {
            tag,
            fid,
            newfid,
            wnames: wnames.iter().map(|s| s.to_vec()).collect(),
        }
        .encode()
        .map_err(|_| VirtioPciError::QueueTooSmall)?;
        let resp = self.submit(&req, 0x400)?;
        p9::Rwalk::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
    }

    /// Tlopen: open `fid` with POSIX `flags` (O_RDONLY/etc).
    pub fn tlopen(&self, tag: u16, fid: u32, flags: u32) -> Result<p9::Rlopen, VirtioPciError> {
        let req = p9::Tlopen { tag, fid, flags }.encode();
        let resp = self.submit(&req, 0x100)?;
        p9::Rlopen::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
    }

    /// Tread `count` bytes from `fid` at byte `offset`. Caller must
    /// have first opened `fid` with `tlopen`. The response payload
    /// max is bounded by the 4 KiB scratch (4080 bytes minus header
    /// and count word).
    pub fn tread(
        &self,
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    ) -> Result<p9::Rread, VirtioPciError> {
        // Payload cap: response buffer = 0x1000, minus the
        // R_READ frame overhead of 7 (header) + 4 (count).
        let cap = (0x1000u32 - 11).min(count);
        let req = p9::Tread {
            tag,
            fid,
            offset,
            count: cap,
        }
        .encode();
        let resp = self.submit(&req, 0x1000)?;
        p9::Rread::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
    }

    /// Tclunk: forget `fid`.
    pub fn tclunk(&self, tag: u16, fid: u32) -> Result<p9::Rclunk, VirtioPciError> {
        let req = p9::Tclunk { tag, fid }.encode();
        let resp = self.submit(&req, 0x100)?;
        p9::Rclunk::decode(&resp).map_err(|_| VirtioPciError::DeviceRejectedFeatures)
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

static CONTROLLER: IrqSafeSpinLock<Option<VirtioP9Pci>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: probe contract.
    let mut dev = match unsafe { VirtioP9Pci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioP9Pci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-9p-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_9P_PCI_VENDOR,
            device: VIRTIO_9P_PCI_DEVICE,
        },
        probe,
    });
}

// ── 9P2000.L wire protocol (stage 2) ───────────────────────────────

pub mod p9;

mod tests;

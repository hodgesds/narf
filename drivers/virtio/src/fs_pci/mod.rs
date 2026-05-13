//! virtio-fs over modern virtio-PCI transport (VirtIO 1.2 §5.11).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-fs PCI device id: `0x1040 + 26 = 0x105A` (§4.1.2,
//! virtio device type 26).
//!
//! Live surface: §5.11.4 device-cfg decode + bring-up of hiprioq
//! (queue 0) + first request queue (queue 1) + FUSE-on-virtio
//! request submission. The FUSE wire format itself is in `fuse.rs`.
//!   <https://www.kernel.org/doc/html/latest/filesystems/fuse.html>

pub mod config;
pub mod fuse;

mod tests;

pub use config::{
    decode_device_config, FsConfig, FS_TAG_LEN, VIRTIO_FS_PCI_DEVICE, VIRTIO_FS_PCI_VENDOR,
};
pub use fuse::{
    FuseEntryOut, FuseInHeader, FuseInitIn, FuseInitOut, FuseOpcode, FuseOutHeader, FuseReadIn,
    FUSE_GETATTR, FUSE_INIT, FUSE_IN_HEADER_LEN, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
    FUSE_LOOKUP, FUSE_OUT_HEADER_LEN, FUSE_READ, FUSE_RELEASE, FUSE_ROOT_ID,
};

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

const HIPRIO_IDX: u16 = 0;
const REQUEST_IDX_0: u16 = 1;

pub struct VirtioFsPci {
    common: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    hiprio: IrqSafeSpinLock<Option<Virtqueue>>,
    requestq: IrqSafeSpinLock<Option<Virtqueue>>,
    _hiprio_buf: DmaBuffer,
    _request_buf: DmaBuffer,
    /// 8 KiB scratch — request at +0, response at +0x1000.
    pool: DmaBuffer,
    request_notify_off: u16,
    pub config: FsConfig,
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioFsPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioFsPci")
            .field("ready", &self.ready)
            .field("num_request_queues", &self.config.num_request_queues)
            .finish_non_exhaustive()
    }
}

impl VirtioFsPci {
    /// Full bring-up: walk caps, reset, negotiate VERSION_1, decode
    /// the §5.11.4 device-cfg, program hiprio (queue 0) + first
    /// request queue (queue 1), DRIVER_OK.
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

        // Read device cfg.
        let mut cfg_buf = [0u8; config::FS_CONFIG_LEN];
        // SAFETY: same.
        unsafe {
            for i in 0..config::FS_CONFIG_LEN {
                cfg_buf[i] = device_region.read8(i as u64);
            }
        }
        let cfg = decode_device_config(&cfg_buf).ok_or(VirtioPciError::NoCommonCfg)?;

        // SAFETY: same.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q < 2 {
            return Err(VirtioPciError::NoQueues);
        }

        // SAFETY: identity-mapped MMIO.
        let (hi_buf, hiprio, _) = unsafe { setup_queue(&common, HIPRIO_IDX) }?;
        let (req_buf, requestq, request_notify_off) =
            unsafe { setup_queue(&common, REQUEST_IDX_0) }?;

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
            hiprio: IrqSafeSpinLock::new(Some(hiprio)),
            requestq: IrqSafeSpinLock::new(Some(requestq)),
            _hiprio_buf: hi_buf,
            _request_buf: req_buf,
            pool,
            request_notify_off,
            config: cfg,
            irq_vector: None,
            msix: None,
            ready: true,
        })
    }

    /// Bind the first request queue (queue 1) to MSI-X.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, REQUEST_IDX_0)? };
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Submit a single FUSE request on the first request queue.
    /// `req` is the full request (header + payload); the device
    /// writes its `fuse_out_header` (16 bytes) + payload into the
    /// response slot, capped at `resp_max`.
    pub fn submit_request(&self, req: &[u8], resp_max: usize) -> Result<Vec<u8>, VirtioPciError> {
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
            self.notify.write16(off, REQUEST_IDX_0);
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

    /// FUSE_INIT handshake. Sends a `fuse_init_in` carrying the
    /// driver's protocol version and reads back the device's
    /// `fuse_init_out`. Required first round-trip per FUSE wire docs.
    pub fn fuse_init(&self, unique: u64) -> Result<FuseInitOut, VirtioPciError> {
        let payload = FuseInitIn {
            major: fuse::FUSE_KERNEL_VERSION,
            minor: fuse::FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 0,
            flags: 0,
        }
        .encode();
        let hdr = FuseInHeader::new(
            FuseOpcode::Init,
            unique,
            /*nodeid=*/ 0,
            /*uid=*/ 0,
            /*gid=*/ 0,
            /*pid=*/ 0,
            payload.len() as u32,
        )
        .encode();
        let mut req = Vec::with_capacity(hdr.len() + payload.len());
        req.extend_from_slice(&hdr);
        req.extend_from_slice(&payload);
        let resp = self.submit_request(&req, 0x200)?;
        if resp.len() < FUSE_OUT_HEADER_LEN {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let oh = FuseOutHeader::decode(&resp).ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        if oh.error != 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        FuseInitOut::decode(&resp[FUSE_OUT_HEADER_LEN..])
            .ok_or(VirtioPciError::DeviceRejectedFeatures)
    }

    /// FUSE_LOOKUP: look up `name` under `parent_nodeid`. The name
    /// is passed as a NUL-terminated payload per FUSE wire docs.
    /// Returns the entry's nodeid (the value the host assigns) or
    /// `Err` if the name doesn't exist.
    pub fn fuse_lookup(
        &self,
        unique: u64,
        parent_nodeid: u64,
        name: &[u8],
    ) -> Result<FuseEntryOut, VirtioPciError> {
        if name.is_empty() || name.contains(&0) {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let mut payload = Vec::with_capacity(name.len() + 1);
        payload.extend_from_slice(name);
        payload.push(0);
        let hdr = FuseInHeader::new(
            FuseOpcode::Lookup,
            unique,
            parent_nodeid,
            /*uid=*/ 0,
            /*gid=*/ 0,
            /*pid=*/ 0,
            payload.len() as u32,
        )
        .encode();
        let mut req = Vec::with_capacity(hdr.len() + payload.len());
        req.extend_from_slice(&hdr);
        req.extend_from_slice(&payload);
        let resp = self.submit_request(&req, 0x200)?;
        if resp.len() < FUSE_OUT_HEADER_LEN {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let oh = FuseOutHeader::decode(&resp).ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        if oh.error != 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        FuseEntryOut::decode(&resp[FUSE_OUT_HEADER_LEN..])
            .ok_or(VirtioPciError::DeviceRejectedFeatures)
    }

    /// FUSE_READ: read up to `size` bytes from a previously-opened
    /// file handle `fh` at byte `offset`. Bounded by the response
    /// scratch (≤ 4 KiB minus the 16-byte fuse_out_header).
    pub fn fuse_read(
        &self,
        unique: u64,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, VirtioPciError> {
        let cap = size.min((0x1000 - FUSE_OUT_HEADER_LEN) as u32);
        let payload = FuseReadIn {
            fh,
            offset,
            size: cap,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        }
        .encode();
        let hdr = FuseInHeader::new(
            FuseOpcode::Read,
            unique,
            nodeid,
            /*uid=*/ 0,
            /*gid=*/ 0,
            /*pid=*/ 0,
            payload.len() as u32,
        )
        .encode();
        let mut req = Vec::with_capacity(hdr.len() + payload.len());
        req.extend_from_slice(&hdr);
        req.extend_from_slice(&payload);
        let resp = self.submit_request(&req, 0x1000)?;
        if resp.len() < FUSE_OUT_HEADER_LEN {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let oh = FuseOutHeader::decode(&resp).ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        if oh.error != 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(resp[FUSE_OUT_HEADER_LEN..].to_vec())
    }

    /// Drain hiprioq used ring (forget completions).
    pub fn drain_hiprio(&self) -> usize {
        let mut n = 0;
        loop {
            let elem = {
                let mut g = self.hiprio.lock();
                match g.as_mut() {
                    Some(q) => q.poll_used(),
                    None => return n,
                }
            };
            if let Some((id, _)) = elem {
                let mut g = self.hiprio.lock();
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

static CONTROLLER: IrqSafeSpinLock<Option<VirtioFsPci>> = IrqSafeSpinLock::new(None);

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioFsPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-fs-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_FS_PCI_VENDOR,
            device: VIRTIO_FS_PCI_DEVICE,
        },
        probe,
    });
}

fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
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
    let mut dev = match unsafe { VirtioFsPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

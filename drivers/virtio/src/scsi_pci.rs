//! virtio-scsi over modern virtio-PCI transport (VirtIO 1.2 §5.6).
//!
//! Modern transitional virtio-scsi PCI device id: `0x1040 + 8 = 0x1048`.
//!
//! Live surface: controlq (queue 0) + eventq (queue 1) + the first
//! command queue (queue 2). `submit_cmd` builds a request /
//! response descriptor chain on the cmd queue and polls used.
//! `submit_tmf` does the same on the controlq for task-management.

use core::sync::atomic::{compiler_fence, Ordering};

extern crate alloc;

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

pub const VIRTIO_SCSI_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_SCSI_PCI_DEVICE: u16 = 0x1048;

pub mod wire;

mod tests;

use wire::{
    VirtioScsiCmdReq, VirtioScsiCmdResp, VirtioScsiCtrlTmfReq,
    encode_cmd_req, decode_cmd_resp, encode_tmf_req, CmdRespDecoded,
    CDB_SIZE, SENSE_SIZE,
};

const CTRLQ_IDX: u16 = 0;
const EVENTQ_IDX: u16 = 1;
const CMDQ0_IDX:  u16 = 2;

pub struct VirtioScsiPci {
    common:                VirtioRegion,
    notify:                VirtioRegion,
    notify_off_multiplier: u32,
    ctrlq:                 IrqSafeSpinLock<Option<Virtqueue>>,
    eventq:                IrqSafeSpinLock<Option<Virtqueue>>,
    cmdq:                  IrqSafeSpinLock<Option<Virtqueue>>,
    _ctrl_buf:             DmaBuffer,
    _event_buf:            DmaBuffer,
    _cmd_buf:              DmaBuffer,
    /// Per-cmd scratch: 4 KiB enough for one inflight req + resp +
    /// data slot (request at +0, response at +0x800, data at +0x1000).
    pool:                  DmaBuffer,
    ctrl_notify_off:       u16,
    cmd_notify_off:        u16,
    pub irq_vector:        Option<u8>,
    msix:                  Option<narf_bus::MsixTable>,
    pub ready:             bool,
}

impl core::fmt::Debug for VirtioScsiPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioScsiPci")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioScsiPci {
    /// Full bring-up: walk caps, reset, negotiate VERSION_1,
    /// program controlq + eventq + first cmd queue, DRIVER_OK.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded cap-list walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned BARs.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset + ACK + DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8);
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
        if n_q < 3 { return Err(VirtioPciError::NoQueues); }

        // SAFETY: identity-mapped MMIO.
        let (ctrl_buf, ctrlq,  ctrl_notify_off) = unsafe { setup_queue(&common, CTRLQ_IDX) }?;
        let (event_buf, eventq, _)               = unsafe { setup_queue(&common, EVENTQ_IDX) }?;
        let (cmd_buf, cmdq,    cmd_notify_off)   = unsafe { setup_queue(&common, CMDQ0_IDX) }?;

        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        let pool = alloc_coherent(8192, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        // SAFETY: page-sized DMA.
        unsafe { core::ptr::write_bytes(pool.phys_addr().raw() as *mut u8, 0, 8192); }

        Ok(Self {
            common, notify, notify_off_multiplier,
            ctrlq:  IrqSafeSpinLock::new(Some(ctrlq)),
            eventq: IrqSafeSpinLock::new(Some(eventq)),
            cmdq:   IrqSafeSpinLock::new(Some(cmdq)),
            _ctrl_buf: ctrl_buf, _event_buf: event_buf, _cmd_buf: cmd_buf,
            pool,
            ctrl_notify_off, cmd_notify_off,
            irq_vector: None, msix: None,
            ready: true,
        })
    }

    /// Bind the first cmd queue (queue 2) to MSI-X so cmd
    /// completions wake the kernel.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap:    &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, CMDQ0_IDX)? };
        self.irq_vector = Some(v);
        self.msix       = Some(table);
        Ok(v)
    }

    /// Submit a single SCSI command via the first request queue.
    /// `data_in_len` > 0 → the device writes `data_in_len` bytes of
    /// data after the response. Returns the decoded response.
    pub fn submit_cmd(
        &self,
        target:      u8,
        lun:         u16,
        cdb:         &[u8; CDB_SIZE],
        data_in_len: u32,
        data_out:    &[u8],
    ) -> Result<(CmdRespDecoded, alloc::vec::Vec<u8>), VirtioPciError> {
        if data_in_len > 4096 || data_out.len() > 4096 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let pool_phys = self.pool.phys_addr().raw();
        let req_phys  = pool_phys;
        let resp_phys = pool_phys + 0x800;
        let data_phys = pool_phys + 0x1000;

        // Build req + resp via the wire helper, then DMA-write the
        // packed struct as raw bytes.
        let req = encode_cmd_req(target, lun, 0xCAFE_BABE,
            wire::VIRTIO_SCSI_S_SIMPLE, *cdb);
        let req_size = core::mem::size_of::<VirtioScsiCmdReq>();
        // SAFETY: identity-mapped DMA, packed struct is plain old data.
        unsafe {
            let src = &req as *const _ as *const u8;
            for i in 0..req_size {
                core::ptr::write_volatile(
                    (req_phys + i as u64) as *mut u8,
                    *src.add(i));
            }
            core::ptr::write_bytes(resp_phys as *mut u8, 0,
                core::mem::size_of::<VirtioScsiCmdResp>());
            for (i, &b) in data_out.iter().enumerate() {
                core::ptr::write_volatile((data_phys + i as u64) as *mut u8, b);
            }
        }

        // Build descriptor chain.
        let mut descs: alloc::vec::Vec<VirtqDesc> = alloc::vec::Vec::with_capacity(4);
        descs.push(VirtqDesc { addr: req_phys, len: req_size as u32, flags: 0, next: 0 });
        if !data_out.is_empty() {
            descs.push(VirtqDesc {
                addr: data_phys, len: data_out.len() as u32, flags: 0, next: 0,
            });
        }
        descs.push(VirtqDesc {
            addr: resp_phys,
            len:  core::mem::size_of::<VirtioScsiCmdResp>() as u32,
            flags: VIRTQ_DESC_F_WRITE, next: 0,
        });
        if data_in_len > 0 {
            descs.push(VirtqDesc {
                addr: data_phys, len: data_in_len, flags: VIRTQ_DESC_F_WRITE, next: 0,
            });
        }
        let head = {
            let mut g = self.cmdq.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.cmd_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(off, CMDQ0_IDX); }

        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.cmdq.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        // Read back response.
        let mut resp = VirtioScsiCmdResp {
            sense_len: 0, residual: 0,
            status_qualifier: 0, status: 0,
            response: 0, sense: [0u8; SENSE_SIZE],
        };
        // SAFETY: identity-mapped DMA.
        unsafe {
            let p = resp_phys as *const u8;
            resp.sense_len        = core::ptr::read_volatile(p.add(0) as *const u32);
            resp.residual         = core::ptr::read_volatile(p.add(4) as *const u32);
            resp.status_qualifier = core::ptr::read_volatile(p.add(8) as *const u16);
            resp.status           = core::ptr::read_volatile(p.add(10) as *const u8);
            resp.response         = core::ptr::read_volatile(p.add(11) as *const u8);
            for i in 0..SENSE_SIZE {
                resp.sense[i] = core::ptr::read_volatile(p.add(12 + i));
            }
        }
        let decoded = decode_cmd_resp(&resp);

        // Pull data-in if any.
        let mut data_in = alloc::vec![0u8; data_in_len as usize];
        // SAFETY: same.
        unsafe {
            for i in 0..data_in_len as usize {
                data_in[i] = core::ptr::read_volatile((data_phys + i as u64) as *const u8);
            }
        }
        let mut g = self.cmdq.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        Ok((decoded, data_in))
    }

    /// Issue a Task-Management Function on the controlq.
    pub fn submit_tmf(
        &self,
        subtype: u32,
        target:  u8,
        lun:     u16,
        tag:     u64,
    ) -> Result<u8, VirtioPciError> {
        let req = encode_tmf_req(subtype, target, lun, tag);
        let req_size = core::mem::size_of::<VirtioScsiCtrlTmfReq>();
        let pool_phys = self.pool.phys_addr().raw();
        let req_phys  = pool_phys;
        let resp_phys = pool_phys + 0x800;
        // SAFETY: identity-mapped DMA, packed struct.
        unsafe {
            let src = &req as *const _ as *const u8;
            for i in 0..req_size {
                core::ptr::write_volatile((req_phys + i as u64) as *mut u8, *src.add(i));
            }
            core::ptr::write_volatile(resp_phys as *mut u8, 0xFF);
        }
        let descs = [
            VirtqDesc { addr: req_phys,  len: req_size as u32,
                        flags: 0,                  next: 0 },
            VirtqDesc { addr: resp_phys, len: 1,
                        flags: VIRTQ_DESC_F_WRITE, next: 0 },
        ];
        let head = {
            let mut g = self.ctrlq.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.ctrl_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(off, CTRLQ_IDX); }
        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.ctrlq.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem { if id == head as u32 { break; } }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::QueueTooSmall); }
            core::hint::spin_loop();
        }
        // SAFETY: identity-mapped DMA.
        let response = unsafe { core::ptr::read_volatile(resp_phys as *const u8) };
        let mut g = self.ctrlq.lock();
        if let Some(q) = g.as_mut() { q.free_chain(head); }
        Ok(response)
    }

    /// Convenience wrapper for REPORT LUNS (SPC-4 §6.33). Allocates
    /// `alloc_len` bytes of inbound data and returns the raw LUN
    /// list along with the response status.
    pub fn report_luns(&self, target: u8, alloc_len: u32)
        -> Result<(CmdRespDecoded, alloc::vec::Vec<u8>), VirtioPciError>
    {
        let cdb = wire::build_report_luns_cdb(alloc_len);
        self.submit_cmd(target, 0, &cdb, alloc_len, &[])
    }
}

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

static CONTROLLER: IrqSafeSpinLock<Option<VirtioScsiPci>> =
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
    // SAFETY: probe contract.
    let mut dev = match unsafe { VirtioScsiPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-scsi-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_SCSI_PCI_VENDOR,
            device: VIRTIO_SCSI_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioScsiPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

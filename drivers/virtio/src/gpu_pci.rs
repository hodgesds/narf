//! virtio-gpu over modern virtio-PCI transport (VirtIO 1.2 §5.7).
//!
//! Modern virtio-gpu PCI device id: `0x1040 + 16 = 0x1050`. Two
//! virtqueues:
//!   * `queue 0` — controlQ: command submission (request +
//!     response chained descriptor pair).
//!   * `queue 1` — cursorQ: rare cursor updates. Reserved for a
//!     follow-up; this driver brings it up enough to pass DRIVER_OK
//!     but doesn't use it.
//!
//! M0 surface:
//!   * Bring-up + feature negotiation.
//!   * GET_DISPLAY_INFO → cache scanout 0's resolution.
//!   * RESOURCE_CREATE_2D + ATTACH_BACKING + SET_SCANOUT for one
//!     contiguous DMA-backed scanout buffer.
//!   * TRANSFER_TO_HOST_2D + RESOURCE_FLUSH after a draw.
//!   * Returns a `narf_graphics::Framebuffer` view over the DMA
//!     buffer so the same drawing primitives that ran on bochs
//!     work here without changes.
//!
//! Polled completion only — the scanout flushes are infrequent
//! enough that adding an MSI-X vector + waker isn't worth the
//! complexity yet.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_graphics::Framebuffer;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS,
    CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE,
    CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{Virtqueue, VirtqueueLayout, VirtqDesc, VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_NEXT};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
    VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_GPU_PCI_VENDOR:        u16 = 0x1AF4;
/// Modern transitional virtio-gpu — `0x1040 + virtio_device_id` (16).
pub const VIRTIO_GPU_PCI_DEVICE:        u16 = 0x1050;
/// Legacy (transitional) virtio-gpu (VirtIO 1.2 §4.1.2 transitional ids).
pub const VIRTIO_GPU_PCI_DEVICE_LEGACY: u16 = 0x1010;

// VirtIO 1.2 §5.7.2: virtio-gpu exposes two virtqueues —
// controlq (idx 0) for command/response, cursorq (idx 1) for
// cursor updates. Driver-side default depths.
pub const CTRL_Q_INDEX:   u16 = 0;
pub const CURSOR_Q_INDEX: u16 = 1;
pub const CTRL_Q_DEPTH:   u16 = 16;
pub const CURSOR_Q_DEPTH: u16 = 4;

mod tests;

// Command codes (VirtIO 1.2 §5.7.6).
const CMD_GET_DISPLAY_INFO:    u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D:  u32 = 0x0101;
const CMD_RESOURCE_UNREF:      u32 = 0x0102;
const CMD_SET_SCANOUT:         u32 = 0x0103;
const CMD_RESOURCE_FLUSH:      u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// Response codes.
const RESP_OK_NODATA:        u32 = 0x1100;
const RESP_OK_DISPLAY_INFO:  u32 = 0x1101;

// Pixel format. B8G8R8X8_UNORM matches our `Pixel32` (XRGB).
const FMT_B8G8R8X8_UNORM: u32 = 1;

const MAX_SCANOUTS: usize = 16;
const HDR_LEN: usize = 24;

/// Scanout dimensions for the M0 splash. Constrained to fit in a
/// single 4 KiB DMA frame (32 × 32 × 4 bytes = 4096) because
/// `narf_io::alloc_coherent` is currently page-capped — multi-page
/// DMA buffers need either a vmap surface or a contiguous-pool
/// allocator, both follow-ups. The host scanout still runs at the
/// device's native resolution (typically 1024×768); virtio-gpu
/// composes our 32×32 resource into the upper-left corner.
const SCANOUT_W: u32 = 32;
const SCANOUT_H: u32 = 32;

#[derive(Copy, Clone, Debug, Default)]
pub struct DisplayMode {
    pub width:  u32,
    pub height: u32,
    pub enabled: bool,
}

#[doc(hidden)]
pub struct VirtioGpuPci {
    notify:               VirtioRegion,
    notify_off_multiplier: u32,
    ctrl_q:               IrqSafeSpinLock<Option<Virtqueue>>,
    _cursor_q:            IrqSafeSpinLock<Option<Virtqueue>>,
    _ctrl_layout_buf:     DmaBuffer,
    _cursor_layout_buf:   DmaBuffer,
    /// Request DMA buffer (driver→device) — request body is written
    /// here, host reads it.
    req_buf:              DmaBuffer,
    /// Response DMA buffer (device→driver).
    resp_buf:             DmaBuffer,
    /// Scanout pixel buffer, one host-side resource id = 1.
    scanout_buf:          DmaBuffer,
    ctrl_q_notify_off:    u16,
    pub mode:             DisplayMode,
    pub ready:            bool,
    last_err:             Option<VirtioPciError>,
}

impl core::fmt::Debug for VirtioGpuPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioGpuPci")
            .field("ready", &self.ready)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl VirtioGpuPci {
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

        // Feature negotiation: only VERSION_1.
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

        // Set up controlQ (queue 0) and cursorQ (queue 1).
        let (ctrl_q, ctrl_buf, ctrl_q_notify_off) =
            // SAFETY: identity-mapped MMIO.
            unsafe { setup_queue(&common, 0, 16)? };
        let (cursor_q, cursor_buf, _) =
            // SAFETY: same.
            unsafe { setup_queue(&common, 1, 4)? };

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                 | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) as u8);
        }

        // Buffers for the request/response pair. virtio-gpu commands
        // are small; one 4 KiB page each is generous.
        let req_buf  = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        let resp_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;

        let me = Self {
            notify, notify_off_multiplier,
            ctrl_q:        IrqSafeSpinLock::new(Some(ctrl_q)),
            _cursor_q:     IrqSafeSpinLock::new(Some(cursor_q)),
            _ctrl_layout_buf:   ctrl_buf,
            _cursor_layout_buf: cursor_buf,
            req_buf,
            resp_buf,
            scanout_buf: alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?, // placeholder
            ctrl_q_notify_off,
            mode: DisplayMode::default(),
            ready: false,
            last_err: None,
        };

        Ok(me)
    }

    /// Most recent error encountered during `init_scanout`, for boot
    /// diagnostics. `None` until something fails.
    pub fn last_error(&self) -> Option<VirtioPciError> { self.last_err }

    /// Set up scanout 0 with a fresh DMA-backed resource. Separated
    /// from `bring_up` so probe failures (out-of-memory, device
    /// rejecting a command) leave the device in the bound list with
    /// `ready = false` instead of being dropped silently.
    ///
    /// # Safety
    /// `bring_up` must have completed; BSP-only.
    pub unsafe fn init_scanout(&mut self) -> Result<(), VirtioPciError> {
        if self.ready { return Ok(()); }
        // Wrap the body so we can capture the failing step.
        let r = unsafe { self.init_scanout_inner() };
        if let Err(e) = r { self.last_err = Some(e); }
        r
    }

    /// `init_scanout_inner` so the public wrapper can capture the
    /// failure step into `last_err`.
    unsafe fn init_scanout_inner(&mut self) -> Result<(), VirtioPciError> {

        // Query GET_DISPLAY_INFO. We don't actually use the host
        // resolution — our scanout buffer is fixed at SCANOUT_W ×
        // SCANOUT_H (32×32) so it fits in one DMA page — but the
        // probe round-trip proves the controlq is healthy.
        let mut display_info = [DisplayMode::default(); MAX_SCANOUTS];
        // SAFETY: req/resp buffers are 4 KiB.
        unsafe { self.fetch_display_info(&mut display_info)?; }
        self.mode = DisplayMode {
            width: SCANOUT_W, height: SCANOUT_H,
            enabled: display_info[0].enabled,
        };

        let scanout_bytes = (SCANOUT_W * SCANOUT_H * 4) as usize;
        let scanout_buf = alloc_coherent(scanout_bytes, DomainId::DRIVER_0)
            .map_err(|_| VirtioPciError::BarMapFailed)?;
        self.scanout_buf = scanout_buf;

        // SAFETY: queues + buffers prepared.
        unsafe {
            self.resource_create_2d(1, FMT_B8G8R8X8_UNORM, SCANOUT_W, SCANOUT_H)?;
            self.resource_attach_backing(1,
                self.scanout_buf.phys_addr().raw(),
                scanout_bytes as u32)?;
            self.set_scanout(0, 1, SCANOUT_W, SCANOUT_H)?;
        }

        self.ready = true;
        Ok(())
    }

    /// Borrow a `Framebuffer` view over the scanout buffer.
    /// Caller-side updates land in DMA memory; call `flush` to push
    /// them to the host scanout via TRANSFER + FLUSH.
    ///
    /// # Safety
    /// Caller must ensure no concurrent draw is in flight; FB writes
    /// go directly through the DMA mapping without a lock.
    pub unsafe fn framebuffer(&self) -> Framebuffer {
        // SAFETY: scanout_buf is identity-mapped + sized for w*h*4.
        unsafe {
            Framebuffer::new(
                self.scanout_buf.phys_addr().raw() as *mut u32,
                SCANOUT_W, SCANOUT_H, SCANOUT_W,
            )
        }
    }

    /// TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for the entire scanout.
    /// Call after every batch of FB writes the user wants visible.
    ///
    /// # Safety
    /// `bring_up` must have completed; ctrl queue serialised via
    /// internal lock.
    pub unsafe fn flush(&mut self) -> Result<(), VirtioPciError> {
        // SAFETY: req/resp buffers + queue prepared.
        unsafe {
            self.transfer_to_host_2d(1, 0, 0, SCANOUT_W, SCANOUT_H)?;
            self.resource_flush(1, 0, 0, SCANOUT_W, SCANOUT_H)?;
        }
        Ok(())
    }

    /// Internal: submit a request and wait for the response.
    ///
    /// `req_len` and `resp_len` are the byte counts of the
    /// request/response bodies (request copied into `req_buf`,
    /// response written into `resp_buf` by the device).
    ///
    /// # Safety
    /// `bring_up` complete; req body already written into req_buf.
    unsafe fn submit(&mut self, req_len: usize, resp_len: usize)
        -> Result<(), VirtioPciError>
    {
        let descs = [
            VirtqDesc {
                addr:  self.req_buf.phys_addr().raw(),
                len:   req_len as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next:  0, // patched by Virtqueue::add_buffer
            },
            VirtqDesc {
                addr:  self.resp_buf.phys_addr().raw(),
                len:   resp_len as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next:  0,
            },
        ];
        let head = {
            let mut g = self.ctrl_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::AddBufferFailed)?
        };
        let off = (self.ctrl_q_notify_off as u64)
            * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe { self.notify.write16(off, 0); }
        let mut spins = 0u32;
        loop {
            let elem = {
                let mut g = self.ctrl_q.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            if let Some((id, _)) = elem {
                if id == head as u32 {
                    let mut g = self.ctrl_q.lock();
                    if let Some(q) = g.as_mut() { q.free_chain(head); }
                    return Ok(());
                }
            }
            spins += 1;
            if spins > 10_000_000 { return Err(VirtioPciError::CompletionTimeout); }
            core::hint::spin_loop();
        }
    }

    /// Internal: write a 24-byte ctrl_hdr at offset 0 of req_buf,
    /// followed by `body_bytes` starting at offset 24.
    fn write_request(&self, cmd: u32, body: &[u8]) {
        let hdr_phys = self.req_buf.phys_addr().raw();
        // SAFETY: req_buf is 4 KiB; we write 24 + body.len() <= 4096.
        unsafe {
            // ctrl_hdr fields: type, flags, fence_id_lo, fence_id_hi,
            // ctx_id, padding (all little-endian).
            core::ptr::write_volatile(hdr_phys as *mut u32, cmd);
            core::ptr::write_volatile((hdr_phys + 4)  as *mut u32, 0); // flags
            core::ptr::write_volatile((hdr_phys + 8)  as *mut u64, 0); // fence_id
            core::ptr::write_volatile((hdr_phys + 16) as *mut u32, 0); // ctx_id
            core::ptr::write_volatile((hdr_phys + 20) as *mut u32, 0); // padding
            for (i, b) in body.iter().enumerate() {
                core::ptr::write_volatile((hdr_phys + 24 + i as u64) as *mut u8, *b);
            }
        }
    }

    /// Internal: read the response type word from the start of resp_buf.
    fn response_type(&self) -> u32 {
        let p = self.resp_buf.phys_addr().raw();
        // SAFETY: resp_buf is 4 KiB.
        unsafe { core::ptr::read_volatile(p as *const u32) }
    }

    /// Submit GET_DISPLAY_INFO and parse the response into `out`.
    unsafe fn fetch_display_info(&mut self, out: &mut [DisplayMode; MAX_SCANOUTS])
        -> Result<(), VirtioPciError>
    {
        self.write_request(CMD_GET_DISPLAY_INFO, &[]);
        // SAFETY: req/resp buffers prepared.
        unsafe { self.submit(HDR_LEN, HDR_LEN + MAX_SCANOUTS * 24)?; }
        if self.response_type() != RESP_OK_DISPLAY_INFO {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let p = self.resp_buf.phys_addr().raw();
        for i in 0..MAX_SCANOUTS {
            let entry = p + HDR_LEN as u64 + (i as u64) * 24;
            // SAFETY: resp_buf is 4 KiB and we never read past 408.
            let _x = unsafe { core::ptr::read_volatile(entry as *const u32) };
            let _y = unsafe { core::ptr::read_volatile((entry + 4)  as *const u32) };
            let w  = unsafe { core::ptr::read_volatile((entry + 8)  as *const u32) };
            let h  = unsafe { core::ptr::read_volatile((entry + 12) as *const u32) };
            let en = unsafe { core::ptr::read_volatile((entry + 16) as *const u32) };
            out[i] = DisplayMode { width: w, height: h, enabled: en != 0 };
        }
        Ok(())
    }

    unsafe fn resource_create_2d(&mut self, resource_id: u32,
                                  format: u32, w: u32, h: u32)
        -> Result<(), VirtioPciError>
    {
        let mut body = [0u8; 16];
        body[0..4].copy_from_slice(&resource_id.to_le_bytes());
        body[4..8].copy_from_slice(&format.to_le_bytes());
        body[8..12].copy_from_slice(&w.to_le_bytes());
        body[12..16].copy_from_slice(&h.to_le_bytes());
        self.write_request(CMD_RESOURCE_CREATE_2D, &body);
        // SAFETY: req/resp prepared.
        unsafe { self.submit(HDR_LEN + 16, HDR_LEN)?; }
        if self.response_type() != RESP_OK_NODATA {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    unsafe fn resource_attach_backing(&mut self, resource_id: u32,
                                       phys: u64, len: u32)
        -> Result<(), VirtioPciError>
    {
        // body: u32 resource_id, u32 nr_entries, then 1 mem entry
        // (u64 addr, u32 length, u32 padding).
        let mut body = [0u8; 8 + 16];
        body[0..4].copy_from_slice(&resource_id.to_le_bytes());
        body[4..8].copy_from_slice(&1u32.to_le_bytes()); // nr_entries
        body[8..16].copy_from_slice(&phys.to_le_bytes());
        body[16..20].copy_from_slice(&len.to_le_bytes());
        // padding is zeroed by default
        self.write_request(CMD_RESOURCE_ATTACH_BACKING, &body);
        // SAFETY: req/resp prepared.
        unsafe { self.submit(HDR_LEN + body.len(), HDR_LEN)?; }
        if self.response_type() != RESP_OK_NODATA {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    unsafe fn set_scanout(&mut self, scanout_id: u32, resource_id: u32,
                           w: u32, h: u32)
        -> Result<(), VirtioPciError>
    {
        // body: rect (16 bytes: x, y, w, h) + scanout_id (u32) + resource_id (u32).
        let mut body = [0u8; 16 + 8];
        body[0..4].copy_from_slice(&0u32.to_le_bytes()); // x
        body[4..8].copy_from_slice(&0u32.to_le_bytes()); // y
        body[8..12].copy_from_slice(&w.to_le_bytes());
        body[12..16].copy_from_slice(&h.to_le_bytes());
        body[16..20].copy_from_slice(&scanout_id.to_le_bytes());
        body[20..24].copy_from_slice(&resource_id.to_le_bytes());
        self.write_request(CMD_SET_SCANOUT, &body);
        // SAFETY: req/resp prepared.
        unsafe { self.submit(HDR_LEN + body.len(), HDR_LEN)?; }
        if self.response_type() != RESP_OK_NODATA {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    unsafe fn transfer_to_host_2d(&mut self, resource_id: u32,
                                   x: u32, y: u32, w: u32, h: u32)
        -> Result<(), VirtioPciError>
    {
        // body: rect (16 bytes) + offset (u64) + resource_id (u32) + padding (u32).
        let mut body = [0u8; 16 + 16];
        body[0..4].copy_from_slice(&x.to_le_bytes());
        body[4..8].copy_from_slice(&y.to_le_bytes());
        body[8..12].copy_from_slice(&w.to_le_bytes());
        body[12..16].copy_from_slice(&h.to_le_bytes());
        body[16..24].copy_from_slice(&0u64.to_le_bytes()); // offset
        body[24..28].copy_from_slice(&resource_id.to_le_bytes());
        // padding zeroed
        self.write_request(CMD_TRANSFER_TO_HOST_2D, &body);
        // SAFETY: req/resp prepared.
        unsafe { self.submit(HDR_LEN + body.len(), HDR_LEN)?; }
        if self.response_type() != RESP_OK_NODATA {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    unsafe fn resource_flush(&mut self, resource_id: u32,
                              x: u32, y: u32, w: u32, h: u32)
        -> Result<(), VirtioPciError>
    {
        let mut body = [0u8; 16 + 8];
        body[0..4].copy_from_slice(&x.to_le_bytes());
        body[4..8].copy_from_slice(&y.to_le_bytes());
        body[8..12].copy_from_slice(&w.to_le_bytes());
        body[12..16].copy_from_slice(&h.to_le_bytes());
        body[16..20].copy_from_slice(&resource_id.to_le_bytes());
        // padding zeroed
        self.write_request(CMD_RESOURCE_FLUSH, &body);
        // SAFETY: req/resp prepared.
        unsafe { self.submit(HDR_LEN + body.len(), HDR_LEN)?; }
        if self.response_type() != RESP_OK_NODATA {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }
}

/// Internal: bring up one virtqueue with the given default depth,
/// returning the queue, its layout backing buffer, and the
/// notify-off slot.
unsafe fn setup_queue(common: &VirtioRegion, idx: u16, default_depth: u16)
    -> Result<(Virtqueue, DmaBuffer, u16), VirtioPciError>
{
    // SAFETY: identity-mapped MMIO.
    let qmax = unsafe {
        common.write16(CC_QUEUE_SELECT, idx);
        common.read16(CC_QUEUE_SIZE)
    };
    if qmax == 0 { return Err(VirtioPciError::QueueTooSmall); }
    let mut qsize = default_depth.min(qmax);
    if !qsize.is_power_of_two() {
        qsize = 1u16 << (15 - qsize.leading_zeros() as u16);
    }
    if qsize == 0 { qsize = 1; }
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
        common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
    }
    // SAFETY: same.
    let notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
    // SAFETY: same.
    unsafe { common.write16(CC_QUEUE_ENABLE, 1); }
    // SAFETY: zero-initialised coherent DMA.
    let q = unsafe { Virtqueue::new(layout) };
    Ok((q, buf, notify_off))
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioGpuPci>> =
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
    let dev = match unsafe { VirtioGpuPci::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("vgpu0"),
        kind:    narf_drivers::BoundKind::Graphics,
        pci_vid: Some(VIRTIO_GPU_PCI_VENDOR),
        pci_did: Some(VIRTIO_GPU_PCI_DEVICE),
        domain:  narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-gpu-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_GPU_PCI_VENDOR,
            device: VIRTIO_GPU_PCI_DEVICE,
        },
        probe,
    });
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-gpu-pci-legacy",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_GPU_PCI_VENDOR,
            device: VIRTIO_GPU_PCI_DEVICE_LEGACY,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioGpuPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

pub fn with_controller_mut<R>(f: impl FnOnce(&mut VirtioGpuPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}

extern crate alloc;

// Unused-but-reserved: CMD_RESOURCE_UNREF is defined for future
// teardown work (not used in M0 since the scanout resource lives
// for the lifetime of the kernel).
const _UNUSED: u32 = CMD_RESOURCE_UNREF;

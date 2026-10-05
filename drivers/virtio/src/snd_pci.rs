//! virtio-sound over modern virtio-PCI transport (VirtIO 1.2 §5.14).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-sound's PCI device id is `0x1040 + 25 = 0x1059`.
//! Four virtqueues:
//!   - 0 = controlq (PCM info / set-params / start / stop verbs).
//!   - 1 = eventq   (jack / device-side state-change notifications).
//!   - 2 = txq      (driver → device PCM data; playback).
//!   - 3 = rxq      (device → driver PCM data; capture).
//!
//! Registers stream-0 playback in the shared sound registry after PCM_INFO
//! verifies its direction and supported formats. PCM submissions use owned
//! coherent DMA with exclusive leases and bounded device waits.

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use alloc::sync::Arc;
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
use crate::req_gate::ReqGate;

mod sound_card;
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

// ── Spec constants (VirtIO 1.2 §5.14.6) ─────────────────────────────

const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
#[allow(dead_code)]
const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

const VIRTIO_SND_S_OK: u32 = 0x8000;

// virtio_snd_pcm_fmt (VirtIO 1.2 §5.14.6.6.3.1.1).
// IMA_ADPCM=0, MU_LAW=1, A_LAW=2, S8=3, U8=4, S16=5, U16=6, ...
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;

// virtio_snd_pcm_rate (VirtIO 1.2 §5.14.6.6.3.1.2).
// 5512=0, 8000=1, 11025=2, 16000=3, 22050=4, 32000=5, 44100=6, 48000=7, ...
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;

pub const VIRTIO_SND_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_SND_PCI_DEVICE: u16 = 0x1059;

/// Virtio-sound device-cfg layout (VirtIO 1.2 §5.14.4). All fields
/// little-endian; `repr(C)` mirrors the wire format so we can read
/// the cfg BAR directly.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VirtioSndConfig {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
}

#[derive(Debug)]
pub struct VirtioSoundPci {
    /// Common configuration window retained so teardown can reset the
    /// transport before any queue-backed DMA memory is released.
    common: VirtioRegion,
    control_q: IrqSafeSpinLock<Option<Virtqueue>>,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    event_q: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_q: IrqSafeSpinLock<Option<Virtqueue>>,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    rx_q: IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf_control: DmaBuffer,
    _q_buf_event: DmaBuffer,
    _q_buf_tx: DmaBuffer,
    _q_buf_rx: DmaBuffer,
    /// Notify region + per-queue notify offsets, captured at probe.
    /// Writing a 2-byte 0 to `notify.virt + notify_off_mul *
    /// queue_notify_off[i]` kicks queue `i`.
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    queue_notify_off: [u16; 4],
    /// Scratch DMA region for synchronous control-vq round-trips.
    /// Big enough for `virtio_snd_pcm_set_params` (24 B) + the
    /// response (4 B); we lay them out at +0 and +64 so the
    /// device-write-back doesn't stomp the request mid-flight.
    ctrl_buf: DmaBuffer,
    /// Scratch DMA region for tx-vq submissions: header (8 B at
    /// +0) + payload (up to 4024 B at +64) + status (8 B at
    /// +4088). One outstanding submission at a time today; a
    /// pool lands when the user-facing surface needs concurrency.
    tx_buf: DmaBuffer,
    /// Tracks whether the playback stream (id 0) is in the
    /// STARTED state. set_params + prepare + start are
    /// idempotent on first play; subsequent plays skip them.
    /// Written only under `req_gate`, so a plain atomic suffices —
    /// crucially it is NOT an IRQ-masking lock held across the three
    /// control round-trips the start sequence issues.
    started: AtomicBool,
    params: IrqSafeSpinLock<Option<PcmParams>>,
    claimed: AtomicBool,
    failed: AtomicBool,
    playback_info: Option<PlaybackInfo>,
    /// Serialises the shared ctrl/tx scratch and the SET_PARAMS →
    /// PREPARE → START sequence WITHOUT masking interrupts while
    /// waiting — see [`crate::req_gate`]. The device may legitimately
    /// hold a PCM buffer for multiple milliseconds before acking, so
    /// waiting here with interrupts masked (as the old global
    /// CONTROLLER hold did) starved timers/RCU on every submit.
    req_gate: AtomicBool,
    pub cfg: VirtioSndConfig,
    pub ready: bool,
}

impl VirtioSoundPci {
    /// Reset the device and wait until it can no longer access the old
    /// virtqueues.
    ///
    /// VirtIO 1.2 section 2.4.2 requires the driver to observe
    /// `device_status == 0` before reinitializing a device. Linux's modern
    /// virtio-pci reset path follows the same ordering before freeing queues.
    fn reset_device(&self) -> bool {
        // SAFETY: `common` remains mapped for the controller's lifetime and
        // this controller exclusively owns the device.
        unsafe {
            self.common.write8(CC_DEVICE_STATUS, 0);
        }
        narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same live common-cfg mapping as the reset write.
                unsafe { self.common.read8(CC_DEVICE_STATUS) == 0 }
            },
            narf_time::Deadline::after_ms(1_000),
        )
    }

    /// # Safety
    /// Caller owns the device exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;

        // Reset + ACK + DRIVER. The specification requires observing zero
        // before reinitializing; in particular, that observation guarantees
        // that the device has stopped using queue memory from a prior driver.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
        }
        let reset = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: caller-owned, live common-cfg mapping.
                unsafe { common.read8(CC_DEVICE_STATUS) == 0 }
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if !reset {
            return Err(VirtioPciError::CompletionTimeout);
        }
        // SAFETY: reset completion was observed above; status negotiation may
        // now begin on the same caller-owned common-cfg mapping.
        unsafe {
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
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

        // Read device-cfg topology. The device cap's BAR is the
        // start of the device-cfg window; layout is
        // `virtio_snd_config { u32 jacks, streams, chmaps }`.
        // device_cfg is optional in the spec, but every QEMU
        // virtio-sound advertises it.
        let dev_cap = caps
            .device_cfg
            .as_ref()
            .ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        // SAFETY: caller-owned device, identity-mapped MMIO.
        let dev_cfg = unsafe { map_cap(device, dev_cap) }?;
        // SAFETY: same.
        let cfg = unsafe {
            VirtioSndConfig {
                jacks: dev_cfg.read32(0),
                streams: dev_cfg.read32(4),
                chmaps: dev_cfg.read32(8),
            }
        };

        // Map the notify cap and capture its multiplier — needed
        // to kick queues after submission.
        // SAFETY: caller-owned device.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;
        let mut queue_notify_off = [0u16; 4];

        // Set up four virtqueues: 0=control, 1=event, 2=tx, 3=rx.
        // Each gets a 4 KiB coherent buffer for descriptor + ring
        // storage. Stage-4: queue depth 4 per queue — virtio-sound
        // spec's minimum + matches balloon's stub footprint. Real
        // playback wants tx depth 32+, but that's a tx-data-plane
        // concern that lands with the unified DmaBuffer surface.
        let mut setup_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            let qsize = 4u16.min(qmax);
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout = VirtqueueLayout::new(qsize, buf.dma_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
                common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // SAFETY: same.
            let off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            queue_notify_off[idx as usize] = off;
            Ok((layout, buf))
        };
        let (ctrl_layout, ctrl_buf) = setup_q(0)?;
        let (event_layout, event_buf) = setup_q(1)?;
        let (tx_layout, tx_buf) = setup_q(2)?;
        let (rx_layout, rx_buf) = setup_q(3)?;

        // Scratch DMA buffers for ctrl + tx round-trips. Allocated
        // once at probe so submissions don't allocate on the hot
        // path.
        let ctrl_scratch =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let tx_scratch =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let control_q = unsafe { Virtqueue::new(ctrl_layout) };
        // SAFETY: same.
        let event_q = unsafe { Virtqueue::new(event_layout) };
        // SAFETY: same.
        let tx_q = unsafe { Virtqueue::new(tx_layout) };
        // SAFETY: same.
        let rx_q = unsafe { Virtqueue::new(rx_layout) };
        Ok(Self {
            common,
            control_q: IrqSafeSpinLock::new(Some(control_q)),
            event_q: IrqSafeSpinLock::new(Some(event_q)),
            tx_q: IrqSafeSpinLock::new(Some(tx_q)),
            rx_q: IrqSafeSpinLock::new(Some(rx_q)),
            _q_buf_control: ctrl_buf,
            _q_buf_event: event_buf,
            _q_buf_tx: tx_buf,
            _q_buf_rx: rx_buf,
            notify,
            notify_off_multiplier,
            queue_notify_off,
            ctrl_buf: ctrl_scratch,
            tx_buf: tx_scratch,
            started: AtomicBool::new(false),
            params: IrqSafeSpinLock::new(None),
            claimed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            playback_info: None,
            req_gate: AtomicBool::new(false),
            cfg,
            ready: true,
        })
    }

    /// Submit a request to the control vq + poll for the response.
    /// `req` is copied into the ctrl scratch buffer at offset 0;
    /// the device writes its `virtio_snd_hdr { u32 status }` at
    /// offset 64. Returns the response status code.
    ///
    /// Caller must hold the request gate (the ctrl scratch is shared).
    fn ctrl_request(&self, req: &[u8]) -> Result<u32, VirtioPciError> {
        self.ctrl_request_data(req, &mut [])
    }

    fn ctrl_request_data(&self, req: &[u8], response: &mut [u8]) -> Result<u32, VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if req.len() > 60 || response.len() > 4028 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let req_phys = self.ctrl_buf.dma_addr().raw();
        let resp_phys = req_phys + 64;
        // SAFETY: identity-mapped DMA. Bulk copy — coherent DMA memory,
        // not MMIO; ordering vs. the device comes from the SeqCst fence
        // before the notify write below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                req.as_ptr(),
                self.ctrl_buf.cpu_mut_ptr::<u8>(),
                req.len(),
            );
            // Pre-clear the response slot so we can detect a
            // device that didn't write anything.
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(resp_phys).kernel_mut_ptr::<u32>(),
                0xFFFF_FFFF,
            );
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
                len: 4 + response.len() as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.control_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[0] as u64,
                0,
            );
        }
        // Poll used ring for the matching head, bounded.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.control_q.lock();
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
            self.failed.store(true, Ordering::Release);
            // A timed-out request still belongs to the device. Reset before
            // returning; never recycle its descriptor or shared scratch.
            assert!(self.reset_device(), "virtio-snd control reset failed");
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(resp_phys).kernel_ptr::<u32>())
        };
        if status == VIRTIO_SND_S_OK {
            // SAFETY: completion transferred ownership back to the driver;
            // the response length fits the coherent scratch allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    narf_memory::PhysAddr::new(resp_phys + 4).kernel_ptr::<u8>(),
                    response.as_mut_ptr(),
                    response.len(),
                );
            }
        }
        let mut g = self.control_q.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(status)
    }

    /// Run SET_PARAMS + PREPARE + START on stream id 0 if not
    /// already started. Idempotent.
    ///
    /// Caller must hold the request gate, which is what makes the
    /// check-then-sequence race-free; `started` itself is a plain
    /// atomic so no IRQ-masking lock is held across the three control
    /// round-trips this issues on first play.
    fn ensure_started(&self, params: PcmParams) -> Result<(), VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if !self.playback_info.is_some_and(|info| info.supports(params)) {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        if self.started.load(Ordering::Acquire) && *self.params.lock() == Some(params) {
            return Ok(());
        }
        self.stop_pcm_locked()?;

        // SET_PARAMS request: virtio_snd_pcm_set_params layout.
        //   +0  hdr.code (u32)        = VIRTIO_SND_R_PCM_SET_PARAMS
        //   +4  hdr.stream_id (u32)   = 0
        //   +8  buffer_bytes (u32)
        //   +12 period_bytes (u32)
        //   +16 features (u32)        = 0
        //   +20 channels (u8)
        //   +21 format (u8)
        //   +22 rate (u8)
        //   +23 padding (u8)
        let mut req = [0u8; 24];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_SET_PARAMS.to_le_bytes());
        req[4..8].copy_from_slice(&0u32.to_le_bytes());
        req[8..12].copy_from_slice(&params.buffer_bytes.to_le_bytes());
        req[12..16].copy_from_slice(&params.period_bytes.to_le_bytes());
        req[16..20].copy_from_slice(&0u32.to_le_bytes());
        req[20] = params.channels;
        req[21] = params.format;
        req[22] = params.rate;
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // PREPARE: virtio_snd_pcm_hdr { code, stream_id }.
        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_PREPARE.to_le_bytes());
        req[4..8].copy_from_slice(&0u32.to_le_bytes());
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // START.
        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_START.to_le_bytes());
        req[4..8].copy_from_slice(&0u32.to_le_bytes());
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        self.started.store(true, Ordering::Release);
        *self.params.lock() = Some(params);
        Ok(())
    }

    /// Caller holds the request gate; no IRQ-masking guard spans device waits.
    fn stop_pcm_locked(&self) -> Result<(), VirtioPciError> {
        if !self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        for command in [VIRTIO_SND_R_PCM_STOP, VIRTIO_SND_R_PCM_RELEASE] {
            let mut request = [0; 8];
            request[..4].copy_from_slice(&command.to_le_bytes());
            if self.ctrl_request(&request)? != VIRTIO_SND_S_OK {
                self.failed.store(true, Ordering::Release);
                assert!(self.reset_device(), "virtio-snd stop reset failed");
                return Err(VirtioPciError::DeviceRejectedFeatures);
            }
        }
        self.started.store(false, Ordering::Release);
        *self.params.lock() = None;
        Ok(())
    }

    /// Generic PCM submit: header + status come from the
    /// per-controller scratch (small, fixed); the payload
    /// descriptor points at caller-supplied phys. The payload
    /// must be physically contiguous for `payload_len` bytes
    /// (single-page from a `narf-shmem` region, or any kernel
    /// `DmaBuffer`).
    ///
    /// Blocks until the device acks via the tx vq used ring — which
    /// routinely takes multiple milliseconds, since the device may not
    /// ack a PCM buffer until it has consumed it. The wait happens
    /// under the device's request gate with interrupts ENABLED; no
    /// global or IRQ-masking lock is held.
    pub fn play_buffer_phys(
        &self,
        params: PcmParams,
        payload_phys: u64,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        let _gate = ReqGate::acquire(&self.req_gate);
        if self.claimed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        self.play_buffer_phys_locked(params, payload_phys, payload_len)
    }

    /// Gate-free body of [`play_buffer_phys`]; caller must hold the
    /// request gate (it protects the shared ctrl/tx scratch and the
    /// single-outstanding-submission contract).
    fn play_buffer_phys_locked(
        &self,
        params: PcmParams,
        payload_phys: u64,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        if payload_len == 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        // virtio-spec requires the payload not cross into
        // unmapped pages; that's the caller's contract on
        // `payload_phys + payload_len`.
        self.ensure_started(params)?;

        // Header (+0) and status (+4088) live in the controller's
        // 4 KiB scratch. Per-controller, single-outstanding-submit
        // today; concurrency lands when AudioWriter grows a
        // submission ring.
        let base = self.tx_buf.dma_addr().raw();
        let hdr_phys = base;
        let status_phys = base + 4088;

        // SAFETY: identity-mapped scratch DMA.
        unsafe {
            // virtio_snd_pcm_xfer { u32 stream_id, u32 padding }
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(hdr_phys).kernel_mut_ptr::<u32>(),
                0u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(hdr_phys + 4).kernel_mut_ptr::<u32>(),
                0u32,
            );
            // Pre-clear status to detect non-write-back.
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u32>(),
                0xFFFF_FFFF,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys + 4).kernel_mut_ptr::<u32>(),
                0u32,
            );
        }
        let descs = [
            VirtqDesc {
                addr: hdr_phys,
                len: 8,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: payload_len,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 8,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.tx_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[2] as u64,
                2,
            );
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB / audio
        // pump itself stay alive while waiting for tx-q completion.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.tx_q.lock();
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
            self.failed.store(true, Ordering::Release);
            // Caller-owned PCM storage cannot be released until DMA stops.
            assert!(self.reset_device(), "virtio-snd playback reset failed");
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u32>())
        };
        let mut g = self.tx_q.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        if status != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Slice-friendly wrapper. Copies `pcm` into the controller's
    /// payload-scratch region within the existing tx_buf, then
    /// submits whole-frame chunks of at most 4024 bytes. The completion
    /// status occupies the remaining eight bytes of the scratch page.
    pub fn play_buffer(&self, params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
        // The gate must cover the payload copy too, or two concurrent
        // players could interleave their copies into the shared scratch
        // and then serialise only the submits.
        let _gate = ReqGate::acquire(&self.req_gate);
        if self.claimed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        let frame_bytes = usize::from(params.channels) * 2;
        if frame_bytes == 0 || frame_bytes > 4024 || pcm.len() % frame_bytes != 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        for chunk in pcm.chunks(4024 / frame_bytes * frame_bytes) {
            self.play_buffer_locked(params, chunk)?;
        }
        Ok(())
    }

    fn play_buffer_locked(&self, params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
        // Status starts at 4088 and payload at 64: 4024 usable bytes.
        if pcm.is_empty() || pcm.len() > 4024 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let base = self.tx_buf.dma_addr().raw();
        let payload_phys = base + 64;
        // SAFETY: identity-mapped scratch DMA; the gate makes the slot
        // ours. Bulk copy — this is the per-PCM-buffer hot path, and a
        // per-byte volatile loop paid 4024 single-byte stores per
        // period. Ordering vs. the device comes from the SeqCst fence
        // before the notify write in `play_buffer_phys_locked`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                pcm.as_ptr(),
                narf_memory::PhysAddr::new(payload_phys).kernel_mut_ptr::<u8>(),
                pcm.len(),
            );
        }
        self.play_buffer_phys_locked(params, payload_phys, pcm.len() as u32)
    }
}

/// PCM stream parameters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcmParams {
    pub buffer_bytes: u32,
    pub period_bytes: u32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl PcmParams {
    /// Stage-4 default: 8 KiB ring, 2 KiB period, S16LE @ 48 kHz
    /// stereo. Matches `narf_audio::AudioFormat::default_playback`.
    pub const fn default_playback() -> Self {
        Self {
            buffer_bytes: 8192,
            period_bytes: 2048,
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_48000,
        }
    }
}

/// The probed controller, behind an `Arc` so callers can snapshot the
/// handle under a brief lock hold and release `CONTROLLER` BEFORE the
/// device round-trip (the same clone-and-release pattern as the mount
/// registry and virtio-net). An `&'static` handout (as virtio-blk uses)
/// would be unsound here: `__reset_for_test` legitimately drops the
/// controller, so the install-once invariant that justifies `&'static`
/// does not hold for this driver. The `Arc` keeps a snapshotted device
/// alive across that window instead.
static CONTROLLER: IrqSafeSpinLock<Option<Arc<VirtioSoundPci>>> = IrqSafeSpinLock::new(None);
static CARD_INDEX: IrqSafeSpinLock<Option<u32>> = IrqSafeSpinLock::new(None);

#[derive(Clone, Copy, Debug)]
struct PlaybackInfo {
    formats: u64,
    rates: u64,
    channels_min: u8,
    channels_max: u8,
}

impl PlaybackInfo {
    fn supports(self, params: PcmParams) -> bool {
        let frame_bytes = u32::from(params.channels) * 2;
        params.format == VIRTIO_SND_PCM_FMT_S16
            && matches!(
                params.rate,
                VIRTIO_SND_PCM_RATE_44100 | VIRTIO_SND_PCM_RATE_48000
            )
            && (1..=2).contains(&params.channels)
            && (self.channels_min..=self.channels_max).contains(&params.channels)
            && self.formats & (1u64 << params.format) != 0
            && self.rates & (1u64 << params.rate) != 0
            && params.period_bytes != 0
            && params.period_bytes % frame_bytes == 0
            && params.buffer_bytes >= params.period_bytes.saturating_mul(2)
            && params.buffer_bytes <= 256 * 1024
            && params.buffer_bytes % params.period_bytes == 0
    }
}

fn playback_info(device: &VirtioSoundPci) -> Result<PlaybackInfo, VirtioPciError> {
    if device.cfg.streams == 0 {
        return Err(VirtioPciError::NoQueues);
    }
    // VirtIO 1.2 5.14: query one 32-byte virtio_snd_pcm_info for stream 0.
    let mut request = [0; 16];
    request[..4].copy_from_slice(&0x100u32.to_le_bytes());
    request[8..12].copy_from_slice(&1u32.to_le_bytes());
    request[12..].copy_from_slice(&32u32.to_le_bytes());
    let mut response = [0; 32];
    let _gate = ReqGate::acquire(&device.req_gate);
    if device.ctrl_request_data(&request, &mut response)? != VIRTIO_SND_S_OK || response[24] != 0 {
        return Err(VirtioPciError::DeviceRejectedFeatures);
    }
    let info = PlaybackInfo {
        formats: u64::from_le_bytes(response[8..16].try_into().unwrap()),
        rates: u64::from_le_bytes(response[16..24].try_into().unwrap()),
        channels_min: response[25],
        channels_max: response[26],
    };
    if info.channels_min > 2
        || info.channels_max == 0
        || info.channels_min > info.channels_max
        || info.formats & (1 << VIRTIO_SND_PCM_FMT_S16) == 0
        || info.rates & ((1 << VIRTIO_SND_PCM_RATE_44100) | (1 << VIRTIO_SND_PCM_RATE_48000)) == 0
    {
        return Err(VirtioPciError::DeviceRejectedFeatures);
    }
    Ok(info)
}

/// Snapshot the installed controller. Takes `CONTROLLER` only long
/// enough to clone the `Arc`.
fn probed() -> Option<Arc<VirtioSoundPci>> {
    CONTROLLER.lock().clone()
}

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
    // SAFETY: caller-authority.
    let mut dev = match unsafe { VirtioSoundPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    dev.playback_info = match playback_info(&dev) {
        Ok(info) => Some(info),
        Err(_) => {
            assert!(
                dev.reset_device(),
                "unsupported virtio-snd device did not reset"
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
    };
    let dev = Arc::new(dev);
    *CONTROLLER.lock() = Some(dev.clone());
    let card = narf_drivers_sound::register_hardware_card_at(
        narf_drivers_sound::CardInfo {
            index: 0,
            driver: "virtio-sound",
            id: "VirtIO",
            name: "VirtIO Sound",
            playback_count: u32::from(dev.cfg.streams != 0),
            capture_count: 0,
        },
        Arc::new(sound_card::Card(dev)),
        Some(device.addr),
    );
    *CARD_INDEX.lock() = Some(card);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vsnd0"),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(VIRTIO_SND_PCI_VENDOR),
        pci_did: Some(VIRTIO_SND_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
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

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Whether stream 0 advertised the requested format through PCM_INFO.
pub fn supports_playback(params: PcmParams) -> bool {
    probed().is_some_and(|device| {
        !device.failed.load(Ordering::Acquire)
            && device
                .playback_info
                .is_some_and(|info| info.supports(params))
    })
}

/// Topology snapshot — `(jacks, streams, chmaps)`. Returns `None`
/// if the device hasn't probed.
pub fn topology() -> Option<(u32, u32, u32)> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|c| (c.cfg.jacks, c.cfg.streams, c.cfg.chmaps))
}

/// Submit one PCM buffer through the probed virtio-sound device's
/// stream 0. Blocks until the device acks. Slice-friendly; copies
/// into the per-controller scratch.
///
/// The `CONTROLLER` lock is released before the submit: the device
/// may hold a PCM buffer for milliseconds before acking, and waiting
/// that out under an IRQ-masking global lock starved timers/RCU on
/// this CPU and spun every other audio submitter interrupts-masked.
/// Mutual exclusion is provided by the device's own request gate.
pub fn play_buffer(params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
    let c = probed().ok_or(VirtioPciError::NoQueues)?;
    c.play_buffer(params, pcm)
}

/// Zero-copy submit: the payload descriptor points directly at
/// `(payload_phys, payload_len)`. The header + status still come
/// from the per-controller scratch. Use this when the PCM source
/// is already in DMA-coherent memory — typically a `narf-shmem`
/// region's `phys_at(handle, offset)`. Locking as [`play_buffer`].
pub fn play_buffer_phys(
    params: PcmParams,
    payload_phys: u64,
    payload_len: u32,
) -> Result<(), VirtioPciError> {
    let c = probed().ok_or(VirtioPciError::NoQueues)?;
    c.play_buffer_phys(params, payload_phys, payload_len)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let card = CARD_INDEX.lock().take();
    if let Some(card) = card {
        narf_drivers_sound::unregister_hardware_card(card);
    }
    // Snapshot + release, then take the device's request gate so a
    // submit that already snapshotted the controller finishes before
    // the device is reset underneath it (the old whole-function
    // CONTROLLER hold provided that exclusion implicitly).
    let Some(current) = probed() else {
        return;
    };
    let _gate = ReqGate::acquire(&current.req_gate);
    current.failed.store(true, Ordering::Release);
    // Do not release queue-backed DMA while the device may still access it.
    // Failing loudly is preferable to either hiding a stale controller or
    // manufacturing a use-after-free in the host device model. The `Arc`
    // keeps the allocation alive until the last in-flight snapshot drops.
    assert!(
        current.reset_device(),
        "virtio-snd device did not acknowledge reset"
    );
    *CONTROLLER.lock() = None;
}

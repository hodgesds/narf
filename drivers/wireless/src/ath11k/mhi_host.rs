//! MHI host controller — boots WCN6855 firmware to mission mode and
//! runs the IPCR channels (20 UL / 21 DL) QRTR sits on.
//!
//! A port of the parts of Linux `drivers/bus/mhi/host/` that ath11k's
//! station bring-up exercises, against a [`MhiBus`] so a scripted fake
//! device can drive the whole sequence offline (QEMU emulates no MHI
//! device).
//!
//! Ported (Linux function → here):
//! - `init.c`: `parse_ch_cfg` / `parse_ev_cfg` / `parse_config`
//!   (→ [`MhiController::new`]), `mhi_alloc_aligned_ring`,
//!   `mhi_init_dev_ctxt`, `mhi_init_mmio`, `mhi_init_chan_ctxt`,
//!   `mhi_deinit_chan_ctxt`, `mhi_prepare_for_power_up`.
//! - `pm.c`: `mhi_tryset_pm_state`, `mhi_set_mhi_state`,
//!   `mhi_ready_state_transition`, `mhi_pm_m0_transition`,
//!   `mhi_pm_m1_transition`, `mhi_pm_m3_transition`,
//!   `mhi_pm_mission_mode_transition`, `mhi_pm_st_worker`,
//!   `__mhi_device_get_sync`, `mhi_assert_dev_wake`,
//!   `mhi_deassert_dev_wake`, `mhi_async_power_up`,
//!   `mhi_sync_power_up`, `mhi_device_get_sync` / `mhi_device_put`.
//! - `boot.c`: `mhi_fw_load_handler`, `mhi_fw_load_bhi`,
//!   `mhi_fw_load_bhie`, `mhi_alloc_bhie_table`,
//!   `mhi_firmware_copy_bhie`, `mhi_load_image_bhi`,
//!   `mhi_download_amss_image`, `mhi_fw_load_error_dump`.
//! - `main.c`: `mhi_read_reg_field` / `mhi_write_reg_field` /
//!   `mhi_poll_reg_field`, `mhi_write_db`, `mhi_db_brstmode`,
//!   `mhi_db_brstmode_disable`, `mhi_ring_er_db`, `mhi_ring_cmd_db`,
//!   `mhi_ring_chan_db`, `mhi_get_exec_env`, `mhi_get_mhi_state`,
//!   `get_nr_avail_ring_elements`, `is_valid_ring_ptr`,
//!   `mhi_irq_handler`, `mhi_intvec_threaded_handler`,
//!   `mhi_ctrl_ev_task`, `mhi_ev_task`,
//!   `mhi_recycle_ev_ring_element`, `parse_xfer_event`,
//!   `mhi_process_cmd_completion`, `mhi_process_ctrl_ev_ring`,
//!   `mhi_process_data_event_ring`, `mhi_is_ring_full`, `mhi_queue`,
//!   `mhi_gen_tre`, `mhi_send_cmd`, `mhi_update_channel_state`,
//!   `mhi_prepare_channel`, `mhi_prepare_for_transfer`,
//!   `mhi_get_free_desc_count`.
//! - `net/qrtr/mhi.c`: `qcom_mhi_qrtr_queue_dl_buffers`,
//!   `qcom_mhi_qrtr_dl_callback`, `qcom_mhi_qrtr_send`,
//!   `qcom_mhi_qrtr_ul_callback` (the buffer policy of the IPCR
//!   client, so Phase 3 only has to parse QRTR packets).
//!
//! Deliberately not ported (station bring-up does not need them):
//! RDDM (ramdump table + `mhi_rddm_prepare` + `mhi_download_rddm_image`),
//! SYS_ERR *recovery* (`mhi_pm_sys_error_transition` — a SYS_ERR is
//! reported and ends bring-up), power-down / `mhi_pm_disable_transition`,
//! suspend / resume (M3 entry), bandwidth scaling (BW_REQ is logged),
//! RSC / coalesced channels, bounce buffers, offload and
//! client-managed event rings, EDL images, `mhi_soc_reset`.
//!
//! ## Concurrency model
//!
//! Linux runs the state worker, IRQ handlers and tasklets
//! concurrently. Here a single async task owns the controller: every
//! wait ([`MhiController::wait_event`]) services the "interrupt"
//! work (intvec handler + event rings) between sleeps, and queued
//! state transitions run in order from [`MhiController::sync_power_up`]
//! — the same serialisation Linux's ordered `hiprio_wq` gives
//! `mhi_pm_st_worker`. Event rings are also polled on every 25 ms wait
//! slice, not only on MSI: with no serial console on the target a lost
//! MSI must not look like a dead device. [`MhiStats`] counts events
//! that were found without an interrupt so the console shows it.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use narf_io::DmaBuffer;
use narf_lib::id::DomainId;

use super::mhi::*;

/// Failing-step codes latched into `narf_memory::diag` by the PCI
/// glue (`wifi: <stage> FAILED step=N detail=D`). Continues
/// [`super::pci::step`].
pub mod step {
    /// Coherent DMA allocation (contexts / rings / images) failed.
    pub const NO_DMA_MEMORY: u32 = 10;
    /// `BHIOFF` beyond BAR0 (detail = offset).
    pub const BHI_OFFSET_RANGE: u32 = 11;
    /// `BHIEOFF` beyond BAR0 (detail = offset).
    pub const BHIE_OFFSET_RANGE: u32 = 12;
    /// EE at power-up not PBL/PTHRU/EDL/AMSS (detail = EE).
    pub const POWER_UP_BAD_EE: u32 = 13;
    /// Device stayed in SYS_ERR reset at power-up (detail = MHICTRL).
    pub const SYSERR_RESET_TIMEOUT: u32 = 14;
    /// No firmware image for the EE (detail = EE).
    pub const NO_FIRMWARE_IMAGE: u32 = 15;
    /// BHI reported an error (detail = `BHI_ERRCODE`).
    pub const BHI_ERROR: u32 = 16;
    /// BHI transfer did not finish (detail = `BHI_STATUS`).
    pub const BHI_TIMEOUT: u32 = 17;
    /// BHIe transfer failed (detail = `BHIE_TXVECSTATUS`).
    pub const BHIE_ERROR: u32 = 18;
    /// BHIe transfer did not finish (detail = `BHIE_TXVECSTATUS`).
    pub const BHIE_TIMEOUT: u32 = 19;
    /// Device never cleared `MHICTRL.RESET` (detail = MHICTRL).
    pub const MHI_RESET_TIMEOUT: u32 = 20;
    /// Device never set `MHISTATUS.READY` (detail = MHISTATUS).
    pub const READY_TIMEOUT: u32 = 21;
    /// `CHDBOFF` beyond BAR0 (detail = offset).
    pub const CHDB_RANGE: u32 = 22;
    /// `ERDBOFF` beyond BAR0 (detail = offset).
    pub const ERDB_RANGE: u32 = 23;
    /// Device signalled SYS_ERR (detail = `ee << 8 | 0xff`).
    pub const SYS_ERR: u32 = 24;
    /// Mission-mode transition read a non-mission EE (detail = EE).
    pub const MISSION_BAD_EE: u32 = 25;
    /// Device did not reach M0 for a wake (detail = pm_state).
    pub const M0_TIMEOUT: u32 = 26;
    /// Mission mode not reached in time (detail = `ee << 16 | pm_state`).
    pub const POWER_UP_TIMEOUT: u32 = 27;
    /// Channel START not completed (detail = `chan << 8 | ccs`).
    pub const CHAN_START: u32 = 28;
    /// Channel not allowed in the current EE (detail = `chan << 8 | ee`).
    pub const CHAN_WRONG_EE: u32 = 29;
    /// Firmware file not found / unreadable (detail = error code).
    pub const FW_NOT_FOUND: u32 = 30;
    /// PM state machine refused a transition (detail = `from << 16 | to`).
    pub const PM_TRANSITION: u32 = 31;
    /// Event ring read pointer outside the ring (detail = er index).
    pub const EVENT_RING_RP: u32 = 32;
    /// Pre-posting the IPCR receive buffers failed (detail = queued).
    pub const DL_QUEUE: u32 = 33;
    /// Controller configuration rejected (`mhi_register_controller`).
    pub const BAD_CONFIG: u32 = 34;
    /// Device registers not accessible in the PM state (detail = pm).
    pub const REG_ACCESS: u32 = 35;
}

/// A bring-up failure, with the diag step + detail it latches.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MhiError {
    pub step: u32,
    pub detail: u32,
    /// The Linux errno the same failure produces (`-ENOMEM`, `-EIO`,
    /// `-ETIMEDOUT`, `-ERANGE`, `-EAGAIN`, `-ENODEV`, `-ENOTCONN`, …),
    /// as a positive number.
    pub errno: i32,
}

pub mod errno {
    pub const EIO: i32 = 5;
    pub const EAGAIN: i32 = 11;
    pub const ENOMEM: i32 = 12;
    pub const ENODEV: i32 = 19;
    pub const EINVAL: i32 = 22;
    pub const ERANGE: i32 = 34;
    pub const ENOTCONN: i32 = 107;
    pub const ETIMEDOUT: i32 = 110;
}

impl MhiError {
    pub const fn new(step: u32, detail: u32, errno: i32) -> Self {
        MhiError {
            step,
            detail,
            errno,
        }
    }
}

/// `enum mhi_callback` — what `status_cb` would be told, plus the two
/// milestones the framebuffer panel tracks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MhiNotify {
    Idle,
    EeRddm,
    EeMissionMode,
    SysError,
    FatalError,
    BwReq {
        speed: u32,
        width: u32,
    },
    /// First entry to M0 — the MHI transport is up.
    FirstM0,
}

/// The device as the host controller sees it: BAR0 registers (Linux
/// `mhi_cntrl->read_reg` / `write_reg` on `regs + offset` — direct
/// BAR0, *not* ath11k's windowed `ath11k_pcic_read32`), MSI delivery,
/// time and randomness.
pub trait MhiBus {
    /// `readl(regs + offset)`.
    fn read32(&self, offset: u32) -> u32;
    /// `writel(value, regs + offset)`.
    fn write32(&self, offset: u32, value: u32);
    /// Bitmask of `mhi_cntrl->irq[i]` indexes that fired since the
    /// last call (bit 0 = BHI / intvec, bit `n` = event-ring irq `n`);
    /// clears them.
    fn take_irqs(&self) -> u32;
    /// Sleep up to `ms`, returning early when an MHI interrupt fires.
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send;
    /// Sleep `ms` regardless of interrupts (Linux `fsleep`).
    fn sleep(&self, ms: u32) -> impl Future<Output = ()> + Send;
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// `get_random_u32_inclusive(1, max)`.
    fn random_nonzero(&self, max: u32) -> u32;
    /// `status_cb` and milestones.
    fn notify(&self, _ev: MhiNotify) {}
    /// One console line.
    fn log(&self, _args: fmt::Arguments<'_>) {}
}

/// `mhi_controller` fields ath11k fills in `ath11k_mhi_register` /
/// `ath11k_mhi_start`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ControllerParams {
    /// `mhi_cntrl->reg_len` = BAR0 length.
    pub reg_len: u32,
    pub iova_start: u64,
    pub iova_stop: u64,
    /// Coherent DMA mask every host buffer must satisfy.
    pub coherent_mask: u64,
    /// `mhi_cntrl->timeout_ms` after `ath11k_mhi_start`.
    pub timeout_ms: u32,
    pub sbl_size: usize,
    pub seg_len: usize,
    pub fbc_download: bool,
    /// Number of `irq[]` entries (`nr_irqs`).
    pub nr_irqs: u32,
}

impl ControllerParams {
    /// ath11k's values for a PCI part with `reg_len`-byte BAR0 and
    /// `nr_irqs` MHI vectors.
    pub const fn ath11k(reg_len: u32, nr_irqs: u32) -> Self {
        ControllerParams {
            reg_len,
            iova_start: 0,
            iova_stop: ATH11K_PCI_DMA_MASK,
            coherent_mask: ATH11K_PCI_COHERENT_DMA_MASK,
            timeout_ms: ATH11K_MHI_TIMEOUT_DEFAULT_MS,
            sbl_size: ATH11K_SBL_SIZE,
            seg_len: ATH11K_SEG_LEN,
            fbc_download: true,
            nr_irqs,
        }
    }
}

/// `enum dev_st_transition`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DevStTransition {
    Pbl,
    Ready,
    Sbl,
    MissionMode,
    Fp,
    SysErr,
    Disable,
}

/// Counters for the console / panel.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MhiStats {
    /// Interrupts seen per `irq[]` index.
    pub irqs: [u32; 4],
    /// Event-ring elements processed per ring.
    pub events: [u32; 2],
    /// Elements found on a poll slice with no interrupt flagged —
    /// non-zero means MSI delivery is not working.
    pub events_without_irq: u32,
    pub m0_entries: u32,
    pub ul_completed: u32,
    pub dl_completed: u32,
}

/// Linux's poll interval for `mhi_poll_reg_field` callers (25 ms), also
/// the slice between event-ring polls.
pub const POLL_INTERVAL_MS: u32 = 25;

const EL: usize = MhiRingElement::SIZE;
const DMA_DOMAIN: DomainId = DomainId::DRIVER_0;

// ── DMA memory ────────────────────────────────────────────────────

/// A coherent buffer with volatile little-endian accessors.
struct Dma {
    buf: DmaBuffer,
}

impl Dma {
    fn alloc(len: usize, mask: u64) -> Result<Dma, MhiError> {
        narf_io::alloc_coherent_masked(len.max(1), DMA_DOMAIN, mask)
            .map(|buf| Dma { buf })
            .map_err(|_| MhiError::new(step::NO_DMA_MEMORY, len as u32, errno::ENOMEM))
    }
    fn dma(&self) -> u64 {
        self.buf.dma_addr().raw()
    }
    fn len(&self) -> usize {
        self.buf.len()
    }
    fn rd32(&self, off: usize) -> u32 {
        assert!(off + 4 <= self.buf.len() && off % 4 == 0);
        // SAFETY: in bounds + 4-aligned (asserted); the buffer is a live
        // kernel-mapped coherent allocation owned by `self`.
        unsafe { core::ptr::read_volatile(self.buf.cpu_ptr_at::<u32>(off as u64)) }
    }
    fn wr32(&self, off: usize, v: u32) {
        assert!(off + 4 <= self.buf.len() && off % 4 == 0);
        // SAFETY: as `rd32`; the device only reads host-written fields.
        unsafe { core::ptr::write_volatile(self.buf.cpu_mut_ptr_at::<u32>(off as u64), v) }
    }
    /// A `__le64 __packed __aligned(4)` field, as two 32-bit halves
    /// (every host buffer is below 4 GiB, so the high half of a device
    /// written pointer never changes and cannot tear).
    fn rd64(&self, off: usize) -> u64 {
        self.rd32(off) as u64 | ((self.rd32(off + 4) as u64) << 32)
    }
    fn wr64(&self, off: usize, v: u64) {
        self.wr32(off, v as u32);
        self.wr32(off + 4, (v >> 32) as u32);
    }
    fn rd_el(&self, off: usize) -> MhiRingElement {
        MhiRingElement {
            ptr: self.rd64(off),
            dword: [self.rd32(off + 8), self.rd32(off + 12)],
        }
    }
    fn wr_el(&self, off: usize, e: &MhiRingElement) {
        self.wr64(off, e.ptr);
        self.wr32(off + 8, e.dword[0]);
        self.wr32(off + 12, e.dword[1]);
    }
    fn bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
    fn copy_in(&mut self, off: usize, src: &[u8]) {
        self.buf.as_mut_slice()[off..off + src.len()].copy_from_slice(src);
    }
}

/// `dma_wmb()` / `smp_wmb()`: order descriptor writes before the
/// doorbell / context update that publishes them.
fn dma_wmb() {
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::Release);
    compiler_fence(Ordering::SeqCst);
}

/// `struct mhi_ring` for a DMA ring: `pre_aligned` = `mem`,
/// `iommu_base` = aligned DMA address, `rp`/`wp` as byte offsets from
/// `base`.
struct Ring {
    mem: Dma,
    base_off: usize,
    iommu_base: u64,
    len: usize,
    elements: usize,
    rp: usize,
    wp: usize,
    /// Doorbell register (BAR0 offset).
    db_addr: u32,
}

impl Ring {
    /// `mhi_alloc_aligned_ring`: "MHI protocol requires the transfer
    /// ring to be aligned with ring length".
    fn alloc_aligned(elements: usize, mask: u64) -> Result<Ring, MhiError> {
        let len = elements * EL;
        let alloc_size = len + (len - 1);
        let mem = Dma::alloc(alloc_size, mask)?;
        let dma = mem.dma();
        let iommu_base = (dma + (len as u64 - 1)) & !(len as u64 - 1);
        Ok(Ring {
            base_off: (iommu_base - dma) as usize,
            iommu_base,
            len,
            elements,
            rp: 0,
            wp: 0,
            db_addr: 0,
            mem,
        })
    }
    fn el(&self, off: usize) -> MhiRingElement {
        self.mem.rd_el(self.base_off + off)
    }
    fn set_el(&self, off: usize, e: &MhiRingElement) {
        self.mem.wr_el(self.base_off + off, e)
    }
    /// `is_valid_ring_ptr`.
    fn valid_ptr(&self, addr: u64) -> bool {
        addr >= self.iommu_base
            && addr < self.iommu_base + self.len as u64
            && addr & (EL as u64 - 1) == 0
    }
    /// `mhi_to_virtual` (as an offset).
    fn to_off(&self, addr: u64) -> usize {
        (addr - self.iommu_base) as usize
    }
    fn dma_of(&self, off: usize) -> u64 {
        self.iommu_base + off as u64
    }
    fn next(&self, off: usize) -> usize {
        let n = off + EL;
        if n >= self.len {
            0
        } else {
            n
        }
    }
    /// `get_nr_avail_ring_elements`.
    fn nr_avail(&self) -> usize {
        if self.wp < self.rp {
            (self.rp - self.wp) / EL - 1
        } else {
            self.rp / EL + (self.len - self.wp) / EL - 1
        }
    }
    /// `mhi_is_ring_full`.
    fn is_full(&self) -> bool {
        self.next(self.wp) == self.rp
    }
}

/// Doorbell config (`struct db_cfg`).
#[derive(Copy, Clone, Debug)]
struct DbCfg {
    reset_req: bool,
    db_mode: bool,
    pollcfg: u32,
    brstmode: u32,
    db_val: u64,
}

impl DbCfg {
    const fn new(brstmode: u32, pollcfg: u32, reset_req: bool) -> Self {
        DbCfg {
            reset_req,
            db_mode: false,
            pollcfg,
            brstmode,
            db_val: 0,
        }
    }
}

/// `struct mhi_event`.
struct Event {
    er_index: u32,
    intmod: u32,
    irq: u32,
    chan: u32,
    priority: u32,
    data_type: ErDataType,
    hw_ring: bool,
    cl_manage: bool,
    offload_ev: bool,
    elements: usize,
    db_cfg: DbCfg,
    ring: Option<Ring>,
}

/// One host-owned buffer queued on a channel (`struct mhi_buf_info`).
struct BufInfo {
    mem: Dma,
    len: usize,
}

/// A completed IPCR receive (`struct mhi_result` delivered to
/// `qcom_mhi_qrtr_dl_callback`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlPacket {
    pub data: Vec<u8>,
}

/// `struct mhi_chan`.
struct Chan {
    name: &'static str,
    chan: u32,
    er_index: u32,
    intmod: u32,
    ch_type: u32,
    dir: DmaDir,
    ee_mask: u32,
    lpm_notify: bool,
    offload_ch: bool,
    configured: bool,
    tre_elements: usize,
    buf_elements: usize,
    db_cfg: DbCfg,
    ch_state: u32,
    ccs: u32,
    completion: bool,
    tre_ring: Option<Ring>,
    db_addr: u32,
    /// `buf_ring` — one slot per TRE, indexed by element number.
    bufs: Vec<Option<BufInfo>>,
    buf_rp: usize,
    buf_wp: usize,
}

/// The host controller.
pub struct MhiController<B: MhiBus> {
    pub bus: B,
    cfg: &'static ControllerConfig,
    params: ControllerParams,
    max_chan: u32,
    chans: Vec<Chan>,
    events: Vec<Event>,
    hw_ev_rings: u32,
    sw_ev_rings: u32,
    /// `mhi_ctxt`: channel / event / command context arrays.
    chan_ctxt: Option<Dma>,
    er_ctxt: Option<Dma>,
    cmd_ctxt: Option<Dma>,
    cmd_ring: Option<Ring>,
    bhi: u32,
    bhie: u32,
    wake_db: u32,
    wake_set: bool,
    dev_wake: i32,
    pending_pkts: i32,
    pub pm_state: u32,
    pub dev_state: MhiState,
    pub ee: MhiEe,
    db_access: u32,
    buffer_len: u32,
    serial_number: u32,
    transitions: VecDeque<DevStTransition>,
    fw_image: Option<Vec<u8>>,
    fbc_image: Option<Vec<Dma>>,
    /// First failure (Linux logs and leaves the PM state; we keep the
    /// reason so the panel can show it).
    pub failure: Option<MhiError>,
    pub stats: MhiStats,
    rx: VecDeque<DlPacket>,
    ipcr_ul: Option<usize>,
    ipcr_dl: Option<usize>,
}

impl<B: MhiBus> fmt::Debug for MhiController<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MhiController")
            .field("pm_state", &pm::name(self.pm_state))
            .field("dev_state", &self.dev_state)
            .field("ee", &self.ee)
            .field("failure", &self.failure)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

macro_rules! mlog {
    ($self:ident, $($arg:tt)*) => {
        $self.bus.log(format_args!($($arg)*))
    };
}

impl<B: MhiBus> MhiController<B> {
    // ── mhi_register_controller / parse_config ───────────────────

    /// `mhi_register_controller` (minus IRQ / device registration,
    /// which the PCI glue owns).
    pub fn new(
        bus: B,
        cfg: &'static ControllerConfig,
        params: ControllerParams,
    ) -> Result<Self, MhiError> {
        let bad = |d: u32| MhiError::new(step::BAD_CONFIG, d, errno::EINVAL);
        if params.reg_len == 0 || params.nr_irqs == 0 {
            return Err(bad(0));
        }
        // parse_ch_cfg
        let max_chan = cfg.max_channels;
        let mut chans: Vec<Chan> = (0..max_chan)
            .map(|i| Chan {
                name: "",
                chan: i,
                er_index: 0,
                intmod: 0,
                ch_type: 0,
                dir: DmaDir::ToDevice,
                ee_mask: 0,
                lpm_notify: false,
                offload_ch: false,
                configured: false,
                tre_elements: 0,
                buf_elements: 0,
                db_cfg: DbCfg::new(0, 0, false),
                ch_state: ch_state::DISABLED,
                ccs: ccs::INVALID,
                completion: false,
                tre_ring: None,
                db_addr: 0,
                bufs: Vec::new(),
                buf_rp: 0,
                buf_wp: 0,
            })
            .collect();
        for c in cfg.ch_cfg {
            if c.num >= max_chan || c.num_elements == 0 {
                return Err(bad(c.num));
            }
            let ch = &mut chans[c.num as usize];
            ch.name = c.name;
            ch.tre_elements = c.num_elements as usize;
            ch.buf_elements = if c.local_elements == 0 {
                c.num_elements as usize
            } else {
                c.local_elements as usize
            };
            ch.er_index = c.event_ring;
            ch.dir = c.dir;
            // "chtype is identical to channel directions"
            ch.ch_type = c.dir as u32;
            ch.ee_mask = c.ee_mask;
            ch.lpm_notify = c.lpm_notify;
            ch.offload_ch = c.offload_channel;
            ch.db_cfg = DbCfg::new(c.doorbell as u32, c.pollcfg, c.doorbell_mode_switch);
            ch.configured = true;
        }
        // parse_ev_cfg
        let mut events = Vec::with_capacity(cfg.event_cfg.len());
        let (mut hw, mut sw) = (0, 0);
        for (i, e) in cfg.event_cfg.iter().enumerate() {
            if e.channel != u32::MAX && e.channel >= max_chan {
                return Err(bad(0x100 | i as u32));
            }
            if e.hardware_event {
                hw += 1;
            } else {
                sw += 1;
            }
            events.push(Event {
                er_index: i as u32,
                intmod: e.irq_moderation_ms,
                irq: e.irq,
                chan: e.channel,
                // "Priority is fixed to 1 for now"
                priority: 1,
                data_type: e.data_type,
                hw_ring: e.hardware_event,
                cl_manage: e.client_managed,
                offload_ev: e.offload_channel,
                elements: e.num_elements as usize,
                db_cfg: DbCfg::new(e.mode as u32, 0, false),
                ring: None,
            });
        }
        // mhi_register_controller: chan intmod from its event ring.
        for ch in chans.iter_mut() {
            let er = ch.er_index as usize;
            if er >= events.len() {
                if ch.configured {
                    return Err(bad(0x200 | ch.chan));
                }
                continue;
            }
            ch.intmod = events[er].intmod;
        }
        // mhi_init_irq_setup: every non-offload event ring needs an irq.
        for e in &events {
            if !e.offload_ev && e.irq >= params.nr_irqs {
                return Err(bad(0x300 | e.irq));
            }
        }
        let mut params = params;
        if params.timeout_ms == 0 {
            params.timeout_ms = if cfg.timeout_ms != 0 {
                cfg.timeout_ms
            } else {
                MHI_TIMEOUT_MS
            };
        }
        Ok(MhiController {
            bus,
            cfg,
            params,
            max_chan,
            chans,
            events,
            hw_ev_rings: hw,
            sw_ev_rings: sw,
            chan_ctxt: None,
            er_ctxt: None,
            cmd_ctxt: None,
            cmd_ring: None,
            bhi: 0,
            bhie: 0,
            wake_db: 0,
            wake_set: false,
            dev_wake: 0,
            pending_pkts: 0,
            pm_state: pm::DISABLE,
            dev_state: MhiState::RESET,
            ee: MhiEe::MAX,
            // "By default, host is allowed to ring DB in both M0 and M2"
            db_access: pm::M0 | pm::M2,
            buffer_len: if cfg.buf_len != 0 {
                cfg.buf_len
            } else {
                MHI_MAX_MTU
            },
            serial_number: 0,
            transitions: VecDeque::new(),
            fw_image: None,
            fbc_image: None,
            failure: None,
            stats: MhiStats::default(),
            rx: VecDeque::new(),
            ipcr_ul: None,
            ipcr_dl: None,
        })
    }

    pub fn params(&self) -> &ControllerParams {
        &self.params
    }

    /// The firmware `request_firmware(mhi_cntrl->fw_image)` returns.
    pub fn set_firmware(&mut self, image: Vec<u8>) {
        self.fw_image = Some(image);
    }

    pub fn serial_number(&self) -> u32 {
        self.serial_number
    }

    fn fail(&mut self, e: MhiError) -> MhiError {
        if self.failure.is_none() {
            self.failure = Some(e);
        }
        e
    }

    // ── register helpers (main.c) ────────────────────────────────

    fn read_reg(&self, base: u32, off: u32) -> u32 {
        self.bus.read32(base + off)
    }
    fn write_reg(&self, base: u32, off: u32, v: u32) {
        self.bus.write32(base + off, v)
    }
    /// `mhi_read_reg_field`.
    fn read_reg_field(&self, base: u32, off: u32, mask: u32) -> u32 {
        field_get(mask, self.read_reg(base, off))
    }
    /// `mhi_write_reg_field`.
    fn write_reg_field(&self, base: u32, off: u32, mask: u32, val: u32) {
        let mut tmp = self.read_reg(base, off);
        tmp &= !mask;
        tmp |= val << mask.trailing_zeros();
        self.write_reg(base, off, tmp);
    }
    /// `mhi_write_db`: upper half first, then lower.
    fn write_db(&self, db_addr: u32, val: u64) {
        self.write_reg(db_addr, 4, (val >> 32) as u32);
        self.write_reg(db_addr, 0, val as u32);
    }
    /// `db_cfg->process_db` (`mhi_db_brstmode` / `_disable`).
    fn process_db(&self, db: &mut DbCfg, db_addr: u32, val: u64) {
        if db.brstmode == BrstMode::Enable as u32 {
            if db.db_mode {
                db.db_val = val;
                self.write_db(db_addr, val);
                db.db_mode = false;
            }
        } else {
            db.db_val = val;
            self.write_db(db_addr, val);
        }
    }
    /// `mhi_get_exec_env`: the raw `BHI_EXECENV` word.
    pub fn get_exec_env(&self) -> MhiEe {
        MhiEe(self.read_reg(self.bhi, BHI_EXECENV))
    }
    /// `mhi_get_mhi_state`.
    pub fn get_mhi_state(&self) -> MhiState {
        MhiState(self.read_reg_field(0, MHISTATUS, MHISTATUS_MHISTATE_MASK))
    }
    /// `mhi_set_mhi_state`.
    fn set_mhi_state(&self, state: MhiState) {
        if state == MhiState::RESET {
            self.write_reg_field(0, MHICTRL, MHICTRL_RESET_MASK, 1);
        } else {
            self.write_reg_field(0, MHICTRL, MHICTRL_MHISTATE_MASK, state.0);
        }
    }
    /// `mhi_tryset_pm_state`.
    fn tryset_pm_state(&mut self, to: u32) -> u32 {
        self.pm_state = pm::tryset(self.pm_state, to);
        self.pm_state
    }

    /// `mhi_poll_reg_field`: `timeout_ms * 1000 / delayus` reads,
    /// `fsleep(delayus)` between them. Interrupt work is serviced
    /// during the sleeps (Linux runs it concurrently).
    async fn poll_reg_field(
        &mut self,
        base: u32,
        off: u32,
        mask: u32,
        val: u32,
        delay_ms: u32,
        timeout_ms: u32,
    ) -> Result<(), u32> {
        let mut retry = (timeout_ms as u64 * 1000) / (delay_ms as u64 * 1000);
        let mut last = 0;
        while retry > 0 {
            retry -= 1;
            last = self.read_reg(base, off);
            if field_get(mask, last) == val {
                return Ok(());
            }
            self.bus.sleep(delay_ms).await;
            self.service_interrupts();
        }
        Err(last)
    }

    /// `wait_event_timeout(mhi_cntrl->state_event, cond, timeout)`:
    /// `true` if `cond` held before the timeout (re-checked once at
    /// expiry, as the kernel macro does).
    async fn wait_event(
        &mut self,
        timeout_ms: u32,
        mut cond: impl FnMut(&mut Self) -> bool,
    ) -> bool {
        let start = self.bus.now_ms();
        loop {
            if cond(self) {
                return true;
            }
            let elapsed = self.bus.now_ms().saturating_sub(start);
            if elapsed >= timeout_ms as u64 {
                return cond(self);
            }
            let slice = (timeout_ms as u64 - elapsed).min(POLL_INTERVAL_MS as u64) as u32;
            self.bus.wait_irq(slice.max(1)).await;
            self.service_interrupts();
        }
    }

    // ── mhi_init_dev_ctxt ────────────────────────────────────────

    fn mask(&self) -> u64 {
        self.params.coherent_mask
    }

    /// `mhi_init_dev_ctxt`.
    fn init_dev_ctxt(&mut self) -> Result<(), MhiError> {
        self.dev_wake = 0;
        self.pending_pkts = 0;
        let mask = self.mask();
        let chan_ctxt = Dma::alloc(CTXT_SIZE * self.max_chan as usize, mask)?;
        for ch in self.chans.iter_mut() {
            if ch.offload_ch {
                continue;
            }
            let off = ch.chan as usize * CTXT_SIZE;
            let mut tmp = chan_ctxt.rd32(off);
            tmp &= !CHAN_CTX_CHSTATE_MASK;
            tmp |= field_prep(CHAN_CTX_CHSTATE_MASK, ch_state::DISABLED);
            tmp &= !CHAN_CTX_BRSTMODE_MASK;
            tmp |= field_prep(CHAN_CTX_BRSTMODE_MASK, ch.db_cfg.brstmode);
            tmp &= !CHAN_CTX_POLLCFG_MASK;
            tmp |= field_prep(CHAN_CTX_POLLCFG_MASK, ch.db_cfg.pollcfg);
            chan_ctxt.wr32(off, tmp);
            chan_ctxt.wr32(off + 4, ch.ch_type);
            chan_ctxt.wr32(off + 8, ch.er_index);
            ch.ch_state = ch_state::DISABLED;
        }

        let er_ctxt = Dma::alloc(CTXT_SIZE * self.events.len(), mask)?;
        for ev in self.events.iter_mut() {
            if ev.offload_ev {
                continue;
            }
            let off = ev.er_index as usize * CTXT_SIZE;
            let mut tmp = er_ctxt.rd32(off);
            tmp &= !EV_CTX_INTMODC_MASK;
            tmp &= !EV_CTX_INTMODT_MASK;
            tmp |= field_prep(EV_CTX_INTMODT_MASK, ev.intmod);
            er_ctxt.wr32(off, tmp);
            er_ctxt.wr32(off + 4, MHI_ER_TYPE_VALID);
            er_ctxt.wr32(off + 8, ev.irq);
            ev.db_cfg.db_mode = true;
            let ring = Ring::alloc_aligned(ev.elements, mask)?;
            er_ctxt.wr64(off + CTXT_RBASE, ring.iommu_base);
            er_ctxt.wr64(off + CTXT_RP, ring.iommu_base);
            er_ctxt.wr64(off + CTXT_WP, ring.iommu_base);
            er_ctxt.wr64(off + CTXT_RLEN, ring.len as u64);
            ev.ring = Some(ring);
        }

        let cmd_ctxt = Dma::alloc(CTXT_SIZE * NR_OF_CMD_RINGS, mask)?;
        let ring = Ring::alloc_aligned(CMD_EL_PER_RING, mask)?;
        cmd_ctxt.wr64(CTXT_RBASE, ring.iommu_base);
        cmd_ctxt.wr64(CTXT_RP, ring.iommu_base);
        cmd_ctxt.wr64(CTXT_WP, ring.iommu_base);
        cmd_ctxt.wr64(CTXT_RLEN, ring.len as u64);
        dma_wmb();
        self.cmd_ring = Some(ring);
        self.chan_ctxt = Some(chan_ctxt);
        self.er_ctxt = Some(er_ctxt);
        self.cmd_ctxt = Some(cmd_ctxt);
        Ok(())
    }

    /// DMA addresses of the three context arrays (`chan`, `er`, `cmd`).
    pub fn ctxt_addrs(&self) -> Option<(u64, u64, u64)> {
        Some((
            self.chan_ctxt.as_ref()?.dma(),
            self.er_ctxt.as_ref()?.dma(),
            self.cmd_ctxt.as_ref()?.dma(),
        ))
    }

    // ── mhi_prepare_for_power_up ─────────────────────────────────

    /// `mhi_prepare_for_power_up` (RDDM table omitted; the BHIe RX
    /// registers are still cleared because `rddm_size` is set).
    pub fn prepare_for_power_up(&mut self) -> Result<(), MhiError> {
        if let Err(e) = self.init_dev_ctxt() {
            self.deinit_dev_ctxt();
            return Err(self.fail(e));
        }
        let bhi_off = self.read_reg(0, BHIOFF);
        if bhi_off >= self.params.reg_len {
            mlog!(
                self,
                "BHI offset: {:#x} is out of range: {:#x}",
                bhi_off,
                self.params.reg_len
            );
            self.deinit_dev_ctxt();
            return Err(self.fail(MhiError::new(
                step::BHI_OFFSET_RANGE,
                bhi_off,
                errno::ERANGE,
            )));
        }
        self.bhi = bhi_off;
        // fbc_download || rddm_size || seg_len — all set by ath11k.
        let bhie_off = self.read_reg(0, BHIEOFF);
        if bhie_off >= self.params.reg_len {
            mlog!(
                self,
                "BHIe offset: {:#x} is out of range: {:#x}",
                bhie_off,
                self.params.reg_len
            );
            self.deinit_dev_ctxt();
            return Err(self.fail(MhiError::new(
                step::BHIE_OFFSET_RANGE,
                bhie_off,
                errno::ERANGE,
            )));
        }
        self.bhie = bhie_off;
        // rddm_size: "manually clear BHIE RX registers since POR values
        // are undefined" (memset_io of RXVECADDR_LOW..RXVECSTATUS).
        let mut off = BHIE_RXVECADDR_LOW_OFFS;
        while off <= BHIE_RXVECSTATUS_OFFS {
            self.write_reg(self.bhie, off, 0);
            off += 4;
        }
        Ok(())
    }

    fn deinit_dev_ctxt(&mut self) {
        self.cmd_ring = None;
        for ev in self.events.iter_mut() {
            ev.ring = None;
        }
        self.chan_ctxt = None;
        self.er_ctxt = None;
        self.cmd_ctxt = None;
    }

    // ── mhi_init_mmio ────────────────────────────────────────────

    /// `mhi_init_mmio`.
    fn init_mmio(&mut self) -> Result<(), MhiError> {
        let (chan_addr, er_addr, cmd_addr) = match self.ctxt_addrs() {
            Some(a) => a,
            None => return Err(MhiError::new(step::NO_DMA_MEMORY, 0, errno::EIO)),
        };
        let reg_info: [(u32, u32); 14] = [
            (CCABAP_HIGHER, (chan_addr >> 32) as u32),
            (CCABAP_LOWER, chan_addr as u32),
            (ECABAP_HIGHER, (er_addr >> 32) as u32),
            (ECABAP_LOWER, er_addr as u32),
            (CRCBAP_HIGHER, (cmd_addr >> 32) as u32),
            (CRCBAP_LOWER, cmd_addr as u32),
            (MHICTRLBASE_HIGHER, (self.params.iova_start >> 32) as u32),
            (MHICTRLBASE_LOWER, self.params.iova_start as u32),
            (MHIDATABASE_HIGHER, (self.params.iova_start >> 32) as u32),
            (MHIDATABASE_LOWER, self.params.iova_start as u32),
            (MHICTRLLIMIT_HIGHER, (self.params.iova_stop >> 32) as u32),
            (MHICTRLLIMIT_LOWER, self.params.iova_stop as u32),
            (MHIDATALIMIT_HIGHER, (self.params.iova_stop >> 32) as u32),
            (MHIDATALIMIT_LOWER, self.params.iova_stop as u32),
        ];

        let mut val = self.read_reg(0, CHDBOFF);
        let lim = self.params.reg_len.wrapping_sub(8 * MHI_DEV_WAKE_DB);
        if val >= lim {
            mlog!(self, "CHDB offset: {:#x} is out of range: {:#x}", val, lim);
            return Err(MhiError::new(step::CHDB_RANGE, val, errno::ERANGE));
        }
        self.wake_db = val + 8 * MHI_DEV_WAKE_DB;
        self.wake_set = false;
        for ch in self.chans.iter_mut() {
            ch.db_addr = val;
            if let Some(r) = ch.tre_ring.as_mut() {
                r.db_addr = val;
            }
            val = val.wrapping_add(8);
        }

        let mut val = self.read_reg(0, ERDBOFF);
        let lim = self
            .params
            .reg_len
            .wrapping_sub(8 * self.events.len() as u32);
        if val >= lim {
            mlog!(self, "ERDB offset: {:#x} is out of range: {:#x}", val, lim);
            return Err(MhiError::new(step::ERDB_RANGE, val, errno::ERANGE));
        }
        for ev in self.events.iter_mut() {
            if !ev.offload_ev {
                if let Some(r) = ev.ring.as_mut() {
                    r.db_addr = val;
                }
            }
            val = val.wrapping_add(8);
        }
        if let Some(r) = self.cmd_ring.as_mut() {
            r.db_addr = CRDB_LOWER;
        }

        for (off, v) in reg_info {
            self.write_reg(0, off, v);
        }
        self.write_reg_field(0, MHICFG, MHICFG_NER_MASK, self.events.len() as u32);
        self.write_reg_field(0, MHICFG, MHICFG_NHWER_MASK, self.hw_ev_rings);
        Ok(())
    }

    // ── doorbells ────────────────────────────────────────────────

    /// `mhi_ring_er_db`.
    fn ring_er_db(&mut self, i: usize) {
        let off = i * CTXT_SIZE + CTXT_WP;
        let wp = match self.er_ctxt.as_ref() {
            Some(c) => c.rd64(off),
            None => return,
        };
        let db_addr = match self.events[i].ring.as_ref() {
            Some(r) => r.db_addr,
            None => return,
        };
        let mut db = self.events[i].db_cfg;
        self.process_db(&mut db, db_addr, wp);
        self.events[i].db_cfg = db;
    }

    /// `mhi_ring_cmd_db`.
    fn ring_cmd_db(&mut self) {
        let (db, db_addr) = match self.cmd_ring.as_ref() {
            Some(r) => (r.dma_of(r.wp), r.db_addr),
            None => return,
        };
        if let Some(c) = self.cmd_ctxt.as_ref() {
            c.wr64(CTXT_WP, db);
        }
        self.write_db(db_addr, db);
    }

    /// `mhi_ring_chan_db`.
    fn ring_chan_db(&mut self, ci: usize) {
        let (db, db_addr) = match self.chans[ci].tre_ring.as_ref() {
            Some(r) => (r.dma_of(r.wp), r.db_addr),
            None => return,
        };
        // "Writes to the new ring element must be visible to the
        // hardware before letting h/w know there is new element".
        dma_wmb();
        if let Some(c) = self.chan_ctxt.as_ref() {
            c.wr64(ci * CTXT_SIZE + CTXT_WP, db);
        }
        let mut dbc = self.chans[ci].db_cfg;
        self.process_db(&mut dbc, db_addr, db);
        self.chans[ci].db_cfg = dbc;
    }

    fn db_access_valid(&self) -> bool {
        self.pm_state & self.db_access != 0
    }

    // ── device wake (pm.c) ───────────────────────────────────────

    /// `mhi_assert_dev_wake` (`wake_get`).
    fn wake_get(&mut self, force: bool) {
        if force {
            self.dev_wake += 1;
            if pm::wake_db_force_set_valid(self.pm_state) && !self.wake_set {
                self.write_db(self.wake_db, 1);
                self.wake_set = true;
            }
        } else {
            if self.dev_wake != 0 {
                self.dev_wake += 1;
                return;
            }
            self.dev_wake += 1;
            if self.dev_wake == 1 && pm::wake_db_set_valid(self.pm_state) && !self.wake_set {
                self.write_db(self.wake_db, 1);
                self.wake_set = true;
            }
        }
    }

    /// `mhi_deassert_dev_wake` (`wake_put`).
    fn wake_put(&mut self, override_: bool) {
        if self.dev_wake != 1 {
            self.dev_wake -= 1;
            return;
        }
        self.dev_wake -= 1;
        if self.dev_wake == 0
            && pm::wake_db_clear_valid(self.pm_state)
            && !override_
            && self.wake_set
        {
            self.write_db(self.wake_db, 0);
            self.wake_set = false;
        }
    }

    /// `__mhi_device_get_sync`.
    async fn device_get_sync(&mut self) -> Result<(), MhiError> {
        if pm::in_error_state(self.pm_state) {
            return Err(MhiError::new(step::M0_TIMEOUT, self.pm_state, errno::EIO));
        }
        self.wake_get(true);
        // (No runtime PM: never in M3, so no mhi_trigger_resume.)
        let t = self.params.timeout_ms;
        let ok = self
            .wait_event(t, |s| {
                s.pm_state == pm::M0 || pm::in_error_state(s.pm_state)
            })
            .await;
        if !ok || pm::in_error_state(self.pm_state) {
            self.wake_put(false);
            return Err(MhiError::new(step::M0_TIMEOUT, self.pm_state, errno::EIO));
        }
        Ok(())
    }

    /// `mhi_device_put`.
    fn device_put(&mut self) {
        self.wake_put(false);
    }

    // ── interrupt work ───────────────────────────────────────────

    /// What the MSI handlers + tasklets do between waits. Every ring is
    /// examined on every call (see the module doc); `irqs` only feeds
    /// the statistics and the intvec decision.
    fn service_interrupts(&mut self) {
        let irqs = self.bus.take_irqs();
        for i in 0..4 {
            if irqs & (1 << i) != 0 {
                self.stats.irqs[i] += 1;
            }
        }
        // mhi_intvec_handler → mhi_intvec_threaded_handler.
        self.intvec_threaded_handler();
        for i in 0..self.events.len() {
            if self.events[i].offload_ev {
                continue;
            }
            let irq_bit = 1u32 << self.events[i].irq;
            let n = self.irq_handler(i);
            if n > 0 && irqs & irq_bit == 0 {
                self.stats.events_without_irq += n as u32;
            }
        }
    }

    /// `mhi_intvec_threaded_handler`.
    fn intvec_threaded_handler(&mut self) {
        if !pm::reg_access_valid(self.pm_state) {
            return;
        }
        let state = self.get_mhi_state();
        let ee = self.get_exec_env();
        let mut pm_state = 0;
        if state == MhiState::SYS_ERR {
            mlog!(self, "mhi: system error detected (EE {})", ee.name());
            pm_state = self.tryset_pm_state(pm::SYS_ERR_DETECT);
        }
        if pm_state != pm::SYS_ERR_DETECT {
            return;
        }
        match ee {
            MhiEe::RDDM => {
                // No RDDM image: Linux does nothing more here.
            }
            MhiEe::PBL | MhiEe::EDL | MhiEe::PTHRU => {
                self.bus.notify(MhiNotify::FatalError);
                self.ee = ee;
                self.sys_err_handler(ee);
            }
            _ => self.sys_err_handler(ee),
        }
    }

    /// `mhi_pm_sys_err_handler`. Without an RDDM image Linux queues
    /// `DEV_ST_TRANSITION_SYS_ERR` (recovery); bring-up instead stops
    /// here and reports.
    fn sys_err_handler(&mut self, ee: MhiEe) {
        self.bus.notify(MhiNotify::SysError);
        let st = self.read_reg(0, MHISTATUS);
        mlog!(
            self,
            "mhi: SYS_ERR in EE {} ({:#x}), MHISTATUS {:#x}",
            ee.name(),
            ee.0,
            st
        );
        self.fail(MhiError::new(step::SYS_ERR, (ee.0 << 8) | 0xff, errno::EIO));
    }

    /// `mhi_irq_handler` + the tasklet it schedules. Returns the number
    /// of elements processed.
    fn irq_handler(&mut self, i: usize) -> usize {
        if self.er_ctxt.is_none() || self.events[i].ring.is_none() {
            return 0;
        }
        let ptr = self.er_rp(i);
        let ring = self.events[i].ring.as_ref().unwrap();
        if !ring.valid_ptr(ptr) {
            mlog!(
                self,
                "mhi: event ring {} rp points outside of the event ring",
                i
            );
            return 0;
        }
        if ring.rp == ring.to_off(ptr) {
            return 0;
        }
        if self.events[i].cl_manage {
            return 0;
        }
        match self.events[i].data_type {
            ErDataType::Ctrl => self.ctrl_ev_task(i),
            ErDataType::Data => self.ev_task(i),
        }
    }

    fn er_rp(&self, i: usize) -> u64 {
        self.er_ctxt
            .as_ref()
            .map(|c| c.rd64(i * CTXT_SIZE + CTXT_RP))
            .unwrap_or(0)
    }

    /// `mhi_ev_task`.
    fn ev_task(&mut self, i: usize) -> usize {
        self.process_data_event_ring(i, u32::MAX).unwrap_or(0)
    }

    /// `mhi_ctrl_ev_task`.
    fn ctrl_ev_task(&mut self, i: usize) -> usize {
        if !pm::reg_access_valid(self.pm_state) {
            return 0;
        }
        let ret = self.process_ctrl_ev_ring(i);
        if ret == Ok(0) {
            let mut pm_state = 0;
            let state = self.get_mhi_state();
            if state == MhiState::SYS_ERR {
                pm_state = self.tryset_pm_state(pm::SYS_ERR_DETECT);
            }
            if pm_state == pm::SYS_ERR_DETECT {
                let ee = self.get_exec_env();
                self.sys_err_handler(ee);
            }
        }
        ret.unwrap_or(0)
    }

    /// `mhi_recycle_ev_ring_element`.
    fn recycle_ev_ring_element(&mut self, i: usize) {
        let er = self.er_ctxt.as_ref().unwrap();
        let ring = self.events[i].ring.as_mut().unwrap();
        ring.wp = ring.next(ring.wp);
        er.wr64(i * CTXT_SIZE + CTXT_WP, ring.iommu_base + ring.wp as u64);
        ring.rp = ring.next(ring.rp);
        dma_wmb();
    }

    /// The shared loop of `mhi_process_ctrl_ev_ring` /
    /// `mhi_process_data_event_ring`.
    fn process_ring(&mut self, i: usize, ctrl: bool, mut quota: u32) -> Result<usize, ()> {
        if pm::event_access_invalid(self.pm_state) {
            return Err(());
        }
        let mut ptr = self.er_rp(i);
        if !self.events[i].ring.as_ref().unwrap().valid_ptr(ptr) {
            mlog!(
                self,
                "mhi: event ring {} rp points outside of the event ring",
                i
            );
            self.fail(MhiError::new(step::EVENT_RING_RP, i as u32, errno::EIO));
            return Err(());
        }
        let mut count = 0usize;
        loop {
            let ring = self.events[i].ring.as_ref().unwrap();
            let dev_rp = ring.to_off(ptr);
            let local_rp = ring.rp;
            if dev_rp == local_rp || (!ctrl && quota == 0) {
                break;
            }
            let el = ring.el(local_rp);
            if ctrl {
                self.ctrl_event(&el);
            } else {
                let chan = el.ev_chid();
                if chan < self.max_chan && self.chans[chan as usize].configured {
                    let t = el.ev_type();
                    if t == pkt::TX_EVENT {
                        self.parse_xfer_event(&el, chan as usize);
                        quota -= 1;
                    } else if t == pkt::RSC_TX_EVENT {
                        // RSC channels not supported (none configured).
                        quota -= 1;
                    }
                }
            }
            self.recycle_ev_ring_element(i);
            ptr = self.er_rp(i);
            if !self.events[i].ring.as_ref().unwrap().valid_ptr(ptr) {
                mlog!(
                    self,
                    "mhi: event ring {} rp points outside of the event ring",
                    i
                );
                self.fail(MhiError::new(step::EVENT_RING_RP, i as u32, errno::EIO));
                return Err(());
            }
            count += 1;
        }
        if i < self.stats.events.len() {
            self.stats.events[i] += count as u32;
        }
        // "Ring EV DB only if there is any pending element to process"
        if self.db_access_valid() && count > 0 {
            self.ring_er_db(i);
        }
        Ok(count)
    }

    /// `mhi_process_ctrl_ev_ring`.
    fn process_ctrl_ev_ring(&mut self, i: usize) -> Result<usize, ()> {
        self.process_ring(i, true, u32::MAX)
    }

    /// `mhi_process_data_event_ring`.
    fn process_data_event_ring(&mut self, i: usize, quota: u32) -> Result<usize, ()> {
        self.process_ring(i, false, quota)
    }

    /// One element of `mhi_process_ctrl_ev_ring`'s switch.
    fn ctrl_event(&mut self, el: &MhiRingElement) {
        match el.ev_type() {
            pkt::BW_REQ_EVENT => {
                let (speed, width) = (el.ev_linkspeed(), el.ev_linkwidth());
                mlog!(self, "mhi: BW_REQ speed={} width={}", speed, width);
                self.bus.notify(MhiNotify::BwReq { speed, width });
            }
            pkt::STATE_CHANGE_EVENT => {
                let new_state = MhiState(el.ev_state());
                mlog!(
                    self,
                    "mhi: state change event to state: {}",
                    new_state.name()
                );
                match new_state {
                    MhiState::M0 => {
                        let _ = self.pm_m0_transition();
                    }
                    MhiState::M1 => self.pm_m1_transition(),
                    MhiState::M3 => {
                        let _ = self.pm_m3_transition();
                    }
                    MhiState::SYS_ERR => {
                        let pm_state = self.tryset_pm_state(pm::SYS_ERR_DETECT);
                        if pm_state == pm::SYS_ERR_DETECT {
                            let ee = self.get_exec_env();
                            self.sys_err_handler(ee);
                        }
                    }
                    _ => mlog!(self, "mhi: invalid state: {}", new_state.name()),
                }
            }
            pkt::CMD_COMPLETION_EVENT => self.process_cmd_completion(el),
            pkt::EE_EVENT => {
                let event = MhiEe(el.ev_execenv());
                mlog!(self, "mhi: received EE event: {}", event.name());
                let st = match event {
                    MhiEe::SBL => Some(DevStTransition::Sbl),
                    MhiEe::WFW | MhiEe::AMSS => Some(DevStTransition::MissionMode),
                    MhiEe::FP => Some(DevStTransition::Fp),
                    MhiEe::RDDM => {
                        self.bus.notify(MhiNotify::EeRddm);
                        self.ee = event;
                        None
                    }
                    _ => {
                        // Linux prints the packet type here, not the EE.
                        mlog!(self, "mhi: unhandled EE event: {:#x}", el.ev_type());
                        None
                    }
                };
                if let Some(st) = st {
                    self.transitions.push_back(st);
                }
            }
            pkt::TX_EVENT => {
                let chan = el.ev_chid();
                if chan < self.max_chan && self.chans[chan as usize].configured {
                    self.parse_xfer_event(el, chan as usize);
                }
            }
            t => mlog!(self, "mhi: unhandled event type: {}", t),
        }
    }

    /// `mhi_process_cmd_completion`.
    fn process_cmd_completion(&mut self, el: &MhiRingElement) {
        let ptr = el.ptr;
        let ring = self.cmd_ring.as_ref().unwrap();
        if !ring.valid_ptr(ptr) {
            mlog!(self, "mhi: event element points outside of the cmd ring");
            return;
        }
        let cmd_pkt = ring.el(ring.to_off(ptr));
        let chan = cmd_pkt.cmd_chid();
        if chan < self.max_chan && self.chans[chan as usize].configured {
            let ch = &mut self.chans[chan as usize];
            ch.ccs = el.ev_code();
            ch.completion = true;
        } else {
            mlog!(
                self,
                "mhi: completion packet for invalid channel ID: {}",
                chan
            );
        }
        // mhi_del_ring_element
        let ring = self.cmd_ring.as_mut().unwrap();
        ring.rp = ring.next(ring.rp);
    }

    /// `parse_xfer_event` for EOT / EOB / OVERFLOW / OOB / DB_MODE.
    fn parse_xfer_event(&mut self, ev: &MhiRingElement, ci: usize) {
        let ev_code = ev.ev_code();
        let overflow = ev_code == ccs::OVERFLOW;
        if self.chans[ci].ch_state != ch_state::ENABLED {
            return;
        }
        match ev_code {
            ccs::OVERFLOW | ccs::EOB | ccs::EOT => {
                let ptr = ev.ptr;
                let (ev_tre, dev_rp, local_rp, chain) = {
                    let tre = match self.chans[ci].tre_ring.as_ref() {
                        Some(t) => t,
                        None => return,
                    };
                    if !tre.valid_ptr(ptr) {
                        mlog!(self, "mhi: event element points outside of the tre ring");
                        return;
                    }
                    let ev_tre = tre.to_off(ptr);
                    let dev_rp = tre.next(ev_tre);
                    let local_rp = tre.rp;
                    (ev_tre, dev_rp, local_rp, tre.el(local_rp).data_chain())
                };
                let next_rp = self.chans[ci].tre_ring.as_ref().unwrap().next(local_rp);
                if dev_rp != next_rp && !chain {
                    mlog!(self, "mhi: event element points to an unexpected TRE");
                    return;
                }
                let mut local_rp = local_rp;
                while local_rp != dev_rp {
                    let ch = &mut self.chans[ci];
                    let slot = ch.buf_rp;
                    let buf = ch.bufs[slot].take();
                    let buf_len = buf.as_ref().map(|b| b.len).unwrap_or(0);
                    let xfer_len = if local_rp == ev_tre {
                        ev.ev_len() as usize
                    } else {
                        buf_len
                    };
                    let bytes = xfer_len.min(buf_len) & 0xffff;
                    // mhi_del_ring_element(buf_ring), (tre_ring)
                    ch.buf_rp = (ch.buf_rp + 1) % ch.buf_elements;
                    let tre = ch.tre_ring.as_mut().unwrap();
                    tre.rp = tre.next(tre.rp);
                    local_rp = tre.rp;
                    let dir = ch.dir;
                    // xfer_cb
                    match dir {
                        DmaDir::FromDevice => self.dl_xfer_cb(ci, buf, bytes, overflow),
                        DmaDir::ToDevice => {
                            self.pending_pkts -= 1;
                            self.ul_xfer_cb(buf);
                        }
                    }
                }
            }
            ccs::OOB | ccs::DB_MODE => {
                self.chans[ci].db_cfg.db_mode = true;
                let ring_db = {
                    let t = self.chans[ci].tre_ring.as_ref();
                    t.map(|t| t.wp != t.rp).unwrap_or(false)
                };
                if ring_db && self.db_access_valid() {
                    self.ring_chan_db(ci);
                }
            }
            c => mlog!(self, "mhi: unknown event {:#x}", c),
        }
    }

    // ── pm.c transitions ─────────────────────────────────────────

    /// `mhi_pm_m0_transition`.
    fn pm_m0_transition(&mut self) -> Result<(), MhiError> {
        self.dev_state = MhiState::M0;
        let cur = self.tryset_pm_state(pm::M0);
        if cur != pm::M0 {
            mlog!(self, "mhi: unable to transition to M0 state");
            return Err(MhiError::new(
                step::PM_TRANSITION,
                (cur << 16) | pm::M0,
                errno::EIO,
            ));
        }
        self.stats.m0_entries += 1;
        if self.stats.m0_entries == 1 {
            self.bus.notify(MhiNotify::FirstM0);
        }
        self.wake_get(true);
        if self.ee.in_mission_mode() {
            for i in 0..self.events.len() {
                if !self.events[i].offload_ev {
                    self.ring_er_db(i);
                }
            }
            let nonempty = self
                .cmd_ring
                .as_ref()
                .map(|r| r.rp != r.wp)
                .unwrap_or(false);
            if nonempty {
                self.ring_cmd_db();
            }
        }
        for ci in 0..self.chans.len() {
            if self.chans[ci].db_cfg.reset_req {
                self.chans[ci].db_cfg.db_mode = true;
            }
            let ring_it = match self.chans[ci].tre_ring.as_ref() {
                Some(t) => t.wp != t.rp && self.chans[ci].ch_state == ch_state::ENABLED,
                None => false,
            };
            if ring_it {
                self.ring_chan_db(ci);
            }
        }
        self.wake_put(false);
        Ok(())
    }

    /// `mhi_pm_m1_transition`.
    fn pm_m1_transition(&mut self) {
        let state = self.tryset_pm_state(pm::M2);
        if state == pm::M2 {
            self.set_mhi_state(MhiState::M2);
            self.dev_state = MhiState::M2;
            if self.pending_pkts != 0 || self.dev_wake != 0 {
                self.wake_get(true);
                self.wake_put(true);
            } else {
                self.bus.notify(MhiNotify::Idle);
            }
        }
    }

    /// `mhi_pm_m3_transition`.
    fn pm_m3_transition(&mut self) -> Result<(), MhiError> {
        self.dev_state = MhiState::M3;
        let state = self.tryset_pm_state(pm::M3);
        if state != pm::M3 {
            mlog!(self, "mhi: unable to transition to M3 state");
            return Err(MhiError::new(
                step::PM_TRANSITION,
                (state << 16) | pm::M3,
                errno::EIO,
            ));
        }
        Ok(())
    }

    /// `mhi_ready_state_transition`.
    async fn ready_state_transition(&mut self) -> Result<(), MhiError> {
        if pm::in_fatal_state(self.pm_state) {
            mlog!(self, "mhi: device link is not accessible");
            return Err(MhiError::new(step::REG_ACCESS, self.pm_state, errno::EIO));
        }
        let t = self.params.timeout_ms;
        if let Err(v) = self
            .poll_reg_field(0, MHICTRL, MHICTRL_RESET_MASK, 0, POLL_INTERVAL_MS, t)
            .await
        {
            mlog!(
                self,
                "mhi: device failed to clear MHI Reset (MHICTRL {:#x})",
                v
            );
            return Err(MhiError::new(step::MHI_RESET_TIMEOUT, v, errno::ETIMEDOUT));
        }
        let rt = if self.cfg.ready_timeout_ms != 0 {
            self.cfg.ready_timeout_ms
        } else {
            t
        };
        if let Err(v) = self
            .poll_reg_field(0, MHISTATUS, MHISTATUS_READY_MASK, 1, POLL_INTERVAL_MS, rt)
            .await
        {
            mlog!(
                self,
                "mhi: device failed to enter MHI Ready (MHISTATUS {:#x})",
                v
            );
            return Err(MhiError::new(step::READY_TIMEOUT, v, errno::ETIMEDOUT));
        }
        mlog!(self, "mhi: device in READY state");
        let cur = self.tryset_pm_state(pm::POR);
        self.dev_state = MhiState::READY;
        if cur != pm::POR {
            mlog!(
                self,
                "mhi: error moving to state {} from {}",
                pm::name(pm::POR),
                pm::name(cur)
            );
            return Err(MhiError::new(
                step::PM_TRANSITION,
                (cur << 16) | pm::POR,
                errno::EIO,
            ));
        }
        if !pm::reg_access_valid(self.pm_state) {
            mlog!(self, "mhi: device registers not accessible");
            return Err(MhiError::new(step::REG_ACCESS, self.pm_state, errno::EIO));
        }
        if let Err(e) = self.init_mmio() {
            mlog!(self, "mhi: error configuring MMIO registers");
            return Err(MhiError::new(e.step, e.detail, errno::EIO));
        }
        // "Add elements to all SW event rings"
        for i in 0..self.events.len() {
            if self.events[i].offload_ev || self.events[i].hw_ring {
                continue;
            }
            let wp = {
                let ring = self.events[i].ring.as_mut().unwrap();
                ring.wp = ring.len - EL;
                ring.iommu_base + (ring.len - EL) as u64
            };
            self.er_ctxt
                .as_ref()
                .unwrap()
                .wr64(i * CTXT_SIZE + CTXT_WP, wp);
            dma_wmb();
            self.ring_er_db(i);
        }
        self.set_mhi_state(MhiState::M0);
        Ok(())
    }

    /// `mhi_pm_mission_mode_transition`.
    async fn pm_mission_mode_transition(&mut self) -> Result<(), MhiError> {
        mlog!(self, "mhi: processing mission mode transition");
        let mut ee = MhiEe::MAX;
        if pm::reg_access_valid(self.pm_state) {
            ee = self.get_exec_env();
        }
        if !ee.in_mission_mode() {
            self.pm_state = pm::LD_ERR_FATAL_DETECT;
            mlog!(
                self,
                "mhi: mission mode transition in EE {} ({:#x})",
                ee.name(),
                ee.0
            );
            return Err(self.fail(MhiError::new(step::MISSION_BAD_EE, ee.0, errno::EIO)));
        }
        self.ee = ee;
        mlog!(self, "mhi: EE {} ({:#x})", ee.name(), ee.0);
        self.bus.notify(MhiNotify::EeMissionMode);
        // "Force MHI to be in M0 state before continuing"
        if let Err(e) = self.device_get_sync().await {
            return Err(self.fail(e));
        }
        let mut ret = Ok(());
        if pm::in_error_state(self.pm_state) {
            ret = Err(MhiError::new(step::M0_TIMEOUT, self.pm_state, errno::EIO));
        } else {
            // "Add elements to all HW event rings"
            for i in 0..self.events.len() {
                if self.events[i].offload_ev || !self.events[i].hw_ring {
                    continue;
                }
                let wp = {
                    let ring = self.events[i].ring.as_mut().unwrap();
                    ring.wp = ring.len - EL;
                    ring.iommu_base + (ring.len - EL) as u64
                };
                self.er_ctxt
                    .as_ref()
                    .unwrap()
                    .wr64(i * CTXT_SIZE + CTXT_WP, wp);
                dma_wmb();
                if self.db_access_valid() {
                    self.ring_er_db(i);
                }
            }
        }
        self.wake_put(false);
        ret.map_err(|e| self.fail(e))
    }

    // ── boot.c ───────────────────────────────────────────────────

    /// `mhi_fw_load_error_dump`.
    fn fw_load_error_dump(&self) -> u32 {
        let mut code = 0;
        if pm::reg_access_valid(self.pm_state) {
            for (name, off) in [
                ("ERROR_CODE", BHI_ERRCODE),
                ("ERROR_DBG1", BHI_ERRDBG1),
                ("ERROR_DBG2", BHI_ERRDBG2),
                ("ERROR_DBG3", BHI_ERRDBG3),
            ] {
                let v = self.read_reg(self.bhi, off);
                if off == BHI_ERRCODE {
                    code = v;
                }
                mlog!(self, "mhi: Reg: {} value: {:#x}", name, v);
            }
        }
        code
    }

    /// `mhi_fw_load_bhi`.
    async fn fw_load_bhi(&mut self, dma_addr: u64, len: usize) -> Result<(), MhiError> {
        if !pm::reg_access_valid(self.pm_state) {
            return Err(MhiError::new(step::REG_ACCESS, self.pm_state, errno::EIO));
        }
        let session_id = self.bus.random_nonzero(BHI_TXDB_SEQNUM_BMSK);
        mlog!(
            self,
            "mhi: starting image download via BHI, session ID {}",
            session_id
        );
        let base = self.bhi;
        self.write_reg(base, BHI_STATUS, 0);
        self.write_reg(base, BHI_IMGADDR_HIGH, (dma_addr >> 32) as u32);
        self.write_reg(base, BHI_IMGADDR_LOW, dma_addr as u32);
        self.write_reg(base, BHI_IMGSIZE, len as u32);
        self.write_reg(base, BHI_IMGTXDB, session_id);

        let mut tx_status = 0;
        let t = self.params.timeout_ms;
        let done = self
            .wait_event(t, |s| {
                if pm::in_error_state(s.pm_state) {
                    return true;
                }
                tx_status = s.read_reg_field(base, BHI_STATUS, BHI_STATUS_MASK);
                tx_status != 0
            })
            .await;
        if pm::in_error_state(self.pm_state) {
            return Err(MhiError::new(step::REG_ACCESS, self.pm_state, errno::EIO));
        }
        if tx_status == BHI_STATUS_ERROR {
            mlog!(self, "mhi: image transfer failed");
            let code = self.fw_load_error_dump();
            return Err(MhiError::new(step::BHI_ERROR, code, errno::EIO));
        }
        if !done {
            let raw = self.read_reg(base, BHI_STATUS);
            return Err(MhiError::new(step::BHI_TIMEOUT, raw, errno::ETIMEDOUT));
        }
        Ok(())
    }

    /// `mhi_fw_load_bhie` (`vec` = the vector table segment).
    async fn fw_load_bhie(&mut self, vec_addr: u64, vec_len: usize) -> Result<(), MhiError> {
        if !pm::reg_access_valid(self.pm_state) {
            return Err(MhiError::new(step::REG_ACCESS, self.pm_state, errno::EIO));
        }
        let base = self.bhie;
        let sequence_id = self.bus.random_nonzero(BHIE_TXVECSTATUS_SEQNUM_BMSK);
        mlog!(
            self,
            "mhi: starting image download via BHIe, sequence ID {}",
            sequence_id
        );
        self.write_reg(base, BHIE_TXVECADDR_HIGH_OFFS, (vec_addr >> 32) as u32);
        self.write_reg(base, BHIE_TXVECADDR_LOW_OFFS, vec_addr as u32);
        self.write_reg(base, BHIE_TXVECSIZE_OFFS, vec_len as u32);
        self.write_reg_field(
            base,
            BHIE_TXVECDB_OFFS,
            BHIE_TXVECDB_SEQNUM_BMSK,
            sequence_id,
        );

        let mut tx_status = 0;
        let t = self.params.timeout_ms;
        let done = self
            .wait_event(t, |s| {
                if pm::in_error_state(s.pm_state) {
                    return true;
                }
                tx_status =
                    s.read_reg_field(base, BHIE_TXVECSTATUS_OFFS, BHIE_TXVECSTATUS_STATUS_BMSK);
                tx_status != 0
            })
            .await;
        let raw = self.read_reg(base, BHIE_TXVECSTATUS_OFFS);
        if pm::in_error_state(self.pm_state) || tx_status != BHIE_TXVECSTATUS_STATUS_XFER_COMPL {
            if !done {
                return Err(MhiError::new(step::BHIE_TIMEOUT, raw, errno::EIO));
            }
            return Err(MhiError::new(step::BHIE_ERROR, raw, errno::EIO));
        }
        if !done {
            return Err(MhiError::new(step::BHIE_TIMEOUT, raw, errno::ETIMEDOUT));
        }
        Ok(())
    }

    /// `mhi_alloc_bhie_table` + `mhi_firmware_copy_bhie`: data
    /// segments of `seg_len`, then the vector table as the last entry
    /// (`sizeof(struct bhi_vec_entry) * (segments - 1)` bytes).
    fn build_bhie_table(&self, image: &[u8]) -> Result<Vec<Dma>, MhiError> {
        let seg = self.params.seg_len;
        let segments = image.len().div_ceil(seg) + 1;
        let mut bufs = Vec::with_capacity(segments);
        for i in 0..segments {
            let vec_size = if i == segments - 1 {
                core::mem::size_of::<BhiVecEntry>() * i
            } else {
                seg
            };
            bufs.push(Dma::alloc(vec_size, self.mask())?);
        }
        // mhi_firmware_copy_bhie
        let mut remainder = image.len();
        let mut src = 0;
        let mut i = 0;
        while remainder > 0 {
            let to_cpy = remainder.min(seg);
            bufs[i].copy_in(0, &image[src..src + to_cpy]);
            let addr = bufs[i].dma();
            let vt = bufs.last().unwrap();
            vt.wr64(i * 16, addr);
            vt.wr64(i * 16 + 8, to_cpy as u64);
            src += to_cpy;
            remainder -= to_cpy;
            i += 1;
        }
        Ok(bufs)
    }

    /// Length the vector table occupies (`mhi_buf->len` of the last
    /// entry).
    fn bhie_vec_len(&self, image_len: usize) -> usize {
        core::mem::size_of::<BhiVecEntry>() * image_len.div_ceil(self.params.seg_len)
    }

    /// `mhi_fw_load_handler`.
    async fn fw_load_handler(&mut self) {
        if pm::in_error_state(self.pm_state) {
            mlog!(self, "mhi: device MHI is not in valid state");
            return;
        }
        self.serial_number = self.read_reg(self.bhi, BHI_SERIALNU);
        let ret: Result<(), MhiError> = async {
            if !self.ee.fw_load_capable() {
                return Ok(false);
            }
            // fw_name = EDL ? edl_image : fw_image. ath11k sets no EDL
            // image.
            let fw = match (self.ee, self.fw_image.take()) {
                (MhiEe::EDL, img) => {
                    self.fw_image = img;
                    None
                }
                (_, img) => img,
            };
            let fw = match fw {
                Some(f)
                    if !self.params.fbc_download
                        || (self.params.sbl_size != 0 && self.params.seg_len != 0) =>
                {
                    f
                }
                other => {
                    self.fw_image = other;
                    mlog!(
                        self,
                        "mhi: no firmware image defined or !sbl_size || !seg_len"
                    );
                    return Err(MhiError::new(
                        step::NO_FIRMWARE_IMAGE,
                        self.ee.0,
                        errno::EIO,
                    ));
                }
            };
            let size = if self.params.fbc_download {
                self.params.sbl_size.min(fw.len())
            } else {
                fw.len()
            };
            // MHI_FW_LOAD_FBC / MHI_FW_LOAD_BHI → mhi_load_image_bhi.
            let r = async {
                let mut img = Dma::alloc(size, self.mask())?;
                img.copy_in(0, &fw[..size]);
                let addr = img.dma();
                let r = self.fw_load_bhi(addr, size).await;
                drop(img);
                r
            }
            .await;
            if let Err(e) = r {
                mlog!(
                    self,
                    "mhi: MHI did not load image over BHI, ret: -{}",
                    e.errno
                );
                self.fw_image = Some(fw);
                return Err(e);
            }
            self.dev_state = MhiState::RESET;
            if self.params.fbc_download {
                // "Some FW combine two separate ELF images (SBL + WLAN
                // FW) in a single file."
                let sbl = self.params.sbl_size;
                let body: &[u8] = if fw.len() >= sbl + 4 && &fw[sbl..sbl + 4] == b"\x7fELF" {
                    &fw[sbl..]
                } else {
                    &fw[..]
                };
                let table = self.build_bhie_table(body)?;
                self.fbc_image = Some(table);
                mlog!(
                    self,
                    "mhi: BHIe image {} bytes in {} segments",
                    body.len(),
                    body.len().div_ceil(self.params.seg_len)
                );
            }
            self.fw_image = Some(fw);
            Ok(true)
        }
        .await
        .and(Ok(()));
        if let Err(e) = ret {
            self.fail(e);
            self.fw_dl_err();
            return;
        }
        // fw_load_ready_state
        if let Err(e) = self.ready_state_transition().await {
            mlog!(self, "mhi: MHI did not enter READY state");
            self.fbc_image = None;
            self.fail(e);
            self.fw_dl_err();
            return;
        }
        mlog!(self, "mhi: wait for device to enter SBL or Mission mode");
    }

    fn fw_dl_err(&mut self) {
        let _ = self.tryset_pm_state(pm::FW_DL_ERR);
    }

    /// `mhi_download_amss_image`.
    async fn download_amss_image(&mut self) -> Result<(), MhiError> {
        let (addr, len) = match self.fbc_image.as_ref() {
            Some(t) => {
                let vt = t.last().unwrap();
                (
                    vt.dma(),
                    core::mem::size_of::<BhiVecEntry>() * (t.len() - 1),
                )
            }
            None => return Err(MhiError::new(step::NO_FIRMWARE_IMAGE, 0, errno::EIO)),
        };
        let r = self.fw_load_bhie(addr, len).await;
        if let Err(e) = r {
            mlog!(self, "mhi: MHI did not load AMSS, ret: -{}", e.errno);
            if e.step == step::BHIE_ERROR || e.step == step::BHIE_TIMEOUT {
                let base = self.bhie;
                let st = self.read_reg(base, BHIE_TXVECSTATUS_OFFS);
                mlog!(self, "mhi: BHIE_TXVECSTATUS {:#x}", st);
                let _ = self.fw_load_error_dump();
            }
            self.fail(e);
            self.fw_dl_err();
        }
        r
    }

    // ── power up ─────────────────────────────────────────────────

    /// `mhi_async_power_up` (IRQ enabling is the glue's job).
    pub async fn async_power_up(&mut self) -> Result<(), MhiError> {
        mlog!(self, "mhi: requested to power ON");
        self.pm_state = pm::DISABLE;
        self.write_reg(self.bhi, BHI_INTVEC, 0);
        self.pm_state = pm::POR;
        self.ee = MhiEe::MAX;
        let current_ee = self.get_exec_env();
        if !current_ee.power_up_capable() {
            mlog!(
                self,
                "mhi: {} ({:#x}) is not a valid EE for power on",
                current_ee.name(),
                current_ee.0
            );
            self.pm_state = pm::DISABLE;
            return Err(self.fail(MhiError::new(
                step::POWER_UP_BAD_EE,
                current_ee.0,
                errno::EIO,
            )));
        }
        let state = self.get_mhi_state();
        mlog!(
            self,
            "mhi: attempting power on with EE: {}, state: {}",
            current_ee.name(),
            state.name()
        );
        if state == MhiState::SYS_ERR {
            self.set_mhi_state(MhiState::RESET);
            let t = self.params.timeout_ms;
            if let Err(v) = self
                .poll_reg_field(0, MHICTRL, MHICTRL_RESET_MASK, 0, POLL_INTERVAL_MS, t)
                .await
            {
                mlog!(self, "mhi: failed to reset MHI due to syserr state");
                self.pm_state = pm::DISABLE;
                return Err(self.fail(MhiError::new(
                    step::SYSERR_RESET_TIMEOUT,
                    v,
                    errno::ETIMEDOUT,
                )));
            }
            // "device cleares INTVEC as part of RESET processing,
            // re-program it"
            self.write_reg(self.bhi, BHI_INTVEC, 0);
        }
        let next = if current_ee.in_pbl() {
            DevStTransition::Pbl
        } else {
            DevStTransition::Ready
        };
        self.transitions.push_back(next);
        mlog!(self, "mhi: power on setup success");
        Ok(())
    }

    /// `mhi_pm_st_worker` for one item.
    async fn run_transition(&mut self, st: DevStTransition) {
        match st {
            DevStTransition::Pbl => {
                if pm::reg_access_valid(self.pm_state) {
                    self.ee = self.get_exec_env();
                }
                mlog!(self, "mhi: EE {} ({:#x})", self.ee.name(), self.ee.0);
                self.fw_load_handler().await;
            }
            DevStTransition::Sbl => {
                self.ee = MhiEe::SBL;
                mlog!(self, "mhi: EE {}", self.ee.name());
                if self.params.fbc_download {
                    let _ = self.download_amss_image().await;
                }
            }
            DevStTransition::MissionMode => {
                let _ = self.pm_mission_mode_transition().await;
            }
            DevStTransition::Fp => {
                self.ee = MhiEe::FP;
            }
            DevStTransition::Ready => {
                if let Err(e) = self.ready_state_transition().await {
                    self.fail(e);
                }
            }
            // Recovery / shutdown are not ported (see the module doc).
            DevStTransition::SysErr | DevStTransition::Disable => {}
        }
    }

    /// `mhi_sync_power_up`: power up and wait for mission mode (or a
    /// fatal error). A SYS_ERR ends the wait too (bring-up does not run
    /// Linux's recovery path).
    pub async fn sync_power_up(&mut self) -> Result<(), MhiError> {
        self.async_power_up().await?;
        let timeout = if self.cfg.ready_timeout_ms != 0 {
            self.cfg.ready_timeout_ms
        } else {
            self.params.timeout_ms
        };
        let start = self.bus.now_ms();
        loop {
            self.service_interrupts();
            if let Some(st) = self.transitions.pop_front() {
                self.run_transition(st).await;
                continue;
            }
            if self.ee.in_mission_mode() || pm::fatal_error(self.pm_state) {
                break;
            }
            if let Some(f) = self.failure {
                if f.step == step::SYS_ERR {
                    break;
                }
            }
            // The deadline only covers waiting for the device: each
            // transition bounds its own waits by timeout_ms, like the
            // Linux worker running alongside `wait_event_timeout`.
            if self.bus.now_ms().saturating_sub(start) >= timeout as u64 {
                break;
            }
            self.bus.wait_irq(POLL_INTERVAL_MS).await;
        }
        if self.ee.in_mission_mode() && self.failure.is_none() {
            return Ok(());
        }
        let e = self.failure.unwrap_or(MhiError::new(
            step::POWER_UP_TIMEOUT,
            (self.ee.0 << 16) | (self.pm_state & 0xffff),
            errno::ETIMEDOUT,
        ));
        mlog!(
            self,
            "mhi: power up failed: step {} detail {:#x} (EE {}, PM {}, MHISTATUS {:#x})",
            e.step,
            e.detail,
            self.ee.name(),
            pm::name(self.pm_state),
            self.read_reg(0, MHISTATUS)
        );
        Err(self.fail(e))
    }

    // ── channels ─────────────────────────────────────────────────

    /// `mhi_init_chan_ctxt`.
    fn init_chan_ctxt(&mut self, ci: usize) -> Result<(), MhiError> {
        let mask = self.mask();
        let mut ring = Ring::alloc_aligned(self.chans[ci].tre_elements, mask)?;
        ring.db_addr = self.chans[ci].db_addr;
        let ctxt = self.chan_ctxt.as_ref().unwrap();
        let off = ci * CTXT_SIZE;
        let mut tmp = ctxt.rd32(off);
        tmp &= !CHAN_CTX_CHSTATE_MASK;
        tmp |= field_prep(CHAN_CTX_CHSTATE_MASK, ch_state::ENABLED);
        ctxt.wr32(off, tmp);
        ctxt.wr64(off + CTXT_RBASE, ring.iommu_base);
        ctxt.wr64(off + CTXT_RP, ring.iommu_base);
        ctxt.wr64(off + CTXT_WP, ring.iommu_base);
        ctxt.wr64(off + CTXT_RLEN, ring.len as u64);
        dma_wmb();
        let ch = &mut self.chans[ci];
        ch.bufs = (0..ch.buf_elements).map(|_| None).collect();
        ch.buf_rp = 0;
        ch.buf_wp = 0;
        ch.tre_ring = Some(ring);
        ch.db_cfg.db_mode = true;
        Ok(())
    }

    /// `mhi_deinit_chan_ctxt`.
    fn deinit_chan_ctxt(&mut self, ci: usize) {
        let ctxt = match self.chan_ctxt.as_ref() {
            Some(c) => c,
            None => return,
        };
        let off = ci * CTXT_SIZE;
        if ctxt.rd64(off + CTXT_RBASE) == 0 {
            return;
        }
        ctxt.wr64(off + CTXT_RBASE, 0);
        ctxt.wr64(off + CTXT_RLEN, 0);
        ctxt.wr64(off + CTXT_RP, 0);
        ctxt.wr64(off + CTXT_WP, 0);
        let mut tmp = ctxt.rd32(off);
        tmp &= !CHAN_CTX_CHSTATE_MASK;
        tmp |= field_prep(CHAN_CTX_CHSTATE_MASK, ch_state::DISABLED);
        ctxt.wr32(off, tmp);
        dma_wmb();
        let ch = &mut self.chans[ci];
        ch.tre_ring = None;
        ch.bufs.clear();
    }

    /// `mhi_send_cmd`.
    fn send_cmd(&mut self, ci: Option<usize>, cmd_type: u32) -> Result<(), MhiError> {
        let chan = ci.map(|c| self.chans[c].chan).unwrap_or(0);
        let ring = self.cmd_ring.as_mut().unwrap();
        if ring.nr_avail() == 0 {
            return Err(MhiError::new(step::CHAN_START, chan << 8, errno::ENOMEM));
        }
        match MhiRingElement::command(cmd_type, chan) {
            Some(el) => ring.set_el(ring.wp, &el),
            None => {
                mlog!(self, "mhi: command not supported");
            }
        }
        let ring = self.cmd_ring.as_mut().unwrap();
        ring.wp = ring.next(ring.wp);
        dma_wmb();
        if self.db_access_valid() {
            self.ring_cmd_db();
        }
        Ok(())
    }

    /// `mhi_update_channel_state` for START (the only transition
    /// bring-up issues; RESET/STOP need the unprepare path).
    async fn start_channel(&mut self, ci: usize) -> Result<(), MhiError> {
        let chan = self.chans[ci].chan;
        let st = self.chans[ci].ch_state;
        if st != ch_state::STOP && st != ch_state::DISABLED {
            return Err(MhiError::new(
                step::CHAN_START,
                (chan << 8) | 0xff,
                errno::EINVAL,
            ));
        }
        self.device_get_sync().await?;
        self.chans[ci].completion = false;
        if let Err(e) = self.send_cmd(Some(ci), cmd::START_CHAN) {
            mlog!(self, "mhi: {}: failed to send START channel command", chan);
            self.device_put();
            return Err(e);
        }
        let t = self.params.timeout_ms;
        let ok = self.wait_event(t, |s| s.chans[ci].completion).await;
        let ccs_v = self.chans[ci].ccs;
        let ret = if !ok || ccs_v != ccs::SUCCESS {
            mlog!(
                self,
                "mhi: {}: failed to receive START channel command completion (ccs {:#x})",
                chan,
                ccs_v
            );
            Err(MhiError::new(
                step::CHAN_START,
                (chan << 8) | (ccs_v & 0xff),
                errno::EIO,
            ))
        } else {
            self.chans[ci].ch_state = ch_state::ENABLED;
            Ok(())
        };
        self.device_put();
        ret
    }

    /// `mhi_prepare_channel`.
    async fn prepare_channel(&mut self, ci: usize) -> Result<(), MhiError> {
        let ch = &self.chans[ci];
        if self.ee.bit() & ch.ee_mask == 0 {
            mlog!(
                self,
                "mhi: current EE: {} required EE mask: {:#x}",
                self.ee.name(),
                ch.ee_mask
            );
            return Err(MhiError::new(
                step::CHAN_WRONG_EE,
                (ch.chan << 8) | (self.ee.0 & 0xff),
                errno::ENOTCONN,
            ));
        }
        if !ch.offload_ch {
            self.init_chan_ctxt(ci)?;
        }
        if let Err(e) = self.start_channel(ci).await {
            if !self.chans[ci].offload_ch {
                self.deinit_chan_ctxt(ci);
            }
            return Err(e);
        }
        Ok(())
    }

    /// `mhi_prepare_for_transfer` for the device `mhi_create_devices`
    /// builds from channel `name` (UL first, then DL), followed by
    /// `qcom_mhi_qrtr_queue_dl_buffers` when `name == "IPCR"`.
    pub async fn prepare_for_transfer(&mut self, name: &str) -> Result<(), MhiError> {
        let ul = self
            .chans
            .iter()
            .position(|c| c.configured && c.name == name && c.dir == DmaDir::ToDevice);
        let dl = self
            .chans
            .iter()
            .position(|c| c.configured && c.name == name && c.dir == DmaDir::FromDevice);
        for ci in [ul, dl].into_iter().flatten() {
            if let Err(e) = self.prepare_channel(ci).await {
                // error_open_chan: unprepare what was started (channel
                // RESET is not ported; drop host state).
                if ci != ul.unwrap_or(usize::MAX) {
                    if let Some(u) = ul {
                        self.chans[u].ch_state = ch_state::DISABLED;
                        self.deinit_chan_ctxt(u);
                    }
                }
                return Err(self.fail(e));
            }
        }
        if name == "IPCR" {
            self.ipcr_ul = ul;
            self.ipcr_dl = dl;
            if let Some(d) = dl {
                self.queue_dl_buffers(d)?;
            }
        }
        Ok(())
    }

    /// `ch_state` of channel `chan`.
    pub fn channel_state(&self, chan: u32) -> Option<u32> {
        self.chans.get(chan as usize).map(|c| c.ch_state)
    }

    /// `mhi_get_free_desc_count`.
    pub fn free_desc_count(&self, chan: u32) -> usize {
        self.chans
            .get(chan as usize)
            .and_then(|c| c.tre_ring.as_ref())
            .map(|r| r.nr_avail())
            .unwrap_or(0)
    }

    /// `mhi_gen_tre`.
    fn gen_tre(
        &mut self,
        ci: usize,
        buf: BufInfo,
        len: usize,
        eob: bool,
        eot: bool,
        chain: bool,
    ) -> Result<(), MhiError> {
        let ch = &mut self.chans[ci];
        if ch.ch_state != ch_state::ENABLED {
            return Err(MhiError::new(step::DL_QUEUE, ch.chan, errno::ENODEV));
        }
        let bei = ch.intmod != 0;
        let el = MhiRingElement::data(buf.mem.dma(), len as u32, bei, eot, eob, chain);
        let tre = ch.tre_ring.as_mut().unwrap();
        tre.set_el(tre.wp, &el);
        tre.wp = tre.next(tre.wp);
        ch.bufs[ch.buf_wp] = Some(buf);
        ch.buf_wp = (ch.buf_wp + 1) % ch.buf_elements;
        Ok(())
    }

    /// `mhi_queue` with `MHI_EOT` (all ath11k / QRTR traffic).
    fn queue(&mut self, ci: usize, buf: BufInfo, len: usize) -> Result<(), MhiError> {
        if pm::in_error_state(self.pm_state) {
            return Err(MhiError::new(step::DL_QUEUE, self.pm_state, errno::EIO));
        }
        let full = self.chans[ci]
            .tre_ring
            .as_ref()
            .map(|r| r.is_full())
            .unwrap_or(true);
        if full {
            return Err(MhiError::new(
                step::DL_QUEUE,
                self.chans[ci].chan,
                errno::EAGAIN,
            ));
        }
        let dir = self.chans[ci].dir;
        self.gen_tre(ci, buf, len, false, true, false)?;
        // runtime_get (no-op for ath11k), wake_toggle (no-op: db_access
        // includes M2).
        if dir == DmaDir::ToDevice {
            self.pending_pkts += 1;
        }
        if self.db_access_valid() {
            self.ring_chan_db(ci);
        }
        Ok(())
    }

    /// `qcom_mhi_qrtr_queue_dl_buffers`: fill every free DL descriptor
    /// with a `buffer_len` buffer.
    fn queue_dl_buffers(&mut self, ci: usize) -> Result<(), MhiError> {
        let mut free = self.free_desc_count(self.chans[ci].chan);
        let mut queued = 0;
        while free > 0 {
            free -= 1;
            let len = self.buffer_len as usize;
            let mem = Dma::alloc(len, self.mask()).map_err(|e| self.fail(e))?;
            if let Err(e) = self.queue(ci, BufInfo { mem, len }, len) {
                mlog!(self, "mhi: failed to queue buffer: -{}", e.errno);
                return Err(self.fail(MhiError::new(step::DL_QUEUE, queued, e.errno)));
            }
            queued += 1;
        }
        Ok(())
    }

    /// `qcom_mhi_qrtr_dl_callback`: deliver, then recycle the buffer.
    /// A failed transfer (`-EOVERFLOW`) drops the buffer without
    /// recycling it, as QRTR does.
    fn dl_xfer_cb(&mut self, ci: usize, buf: Option<BufInfo>, bytes: usize, overflow: bool) {
        let buf = match buf {
            Some(b) => b,
            None => return,
        };
        self.stats.dl_completed += 1;
        if overflow {
            return;
        }
        self.rx.push_back(DlPacket {
            data: buf.mem.bytes()[..bytes].to_vec(),
        });
        let len = self.buffer_len as usize;
        if let Err(e) = self.queue(ci, buf, len) {
            mlog!(self, "mhi: failed to recycle the buffer: -{}", e.errno);
        }
    }

    /// `qcom_mhi_qrtr_ul_callback`: the bounce buffer is freed.
    fn ul_xfer_cb(&mut self, buf: Option<BufInfo>) {
        drop(buf);
        self.stats.ul_completed += 1;
    }

    /// `qcom_mhi_qrtr_send` → `mhi_queue_skb(…, MHI_EOT)`: queue one
    /// QRTR packet on the IPCR UL channel. The bytes are copied to a
    /// DMA32 buffer (Linux maps the skb under the 36-bit streaming
    /// mask; a copy below 4 GiB satisfies that too).
    pub fn queue_ul(&mut self, data: &[u8]) -> Result<(), MhiError> {
        let ci = self
            .ipcr_ul
            .ok_or(MhiError::new(step::DL_QUEUE, 0, errno::ENODEV))?;
        if data.len() > 0xffff {
            return Err(MhiError::new(
                step::DL_QUEUE,
                data.len() as u32,
                errno::EINVAL,
            ));
        }
        let mut mem = Dma::alloc(data.len(), self.mask())?;
        mem.copy_in(0, data);
        self.queue(
            ci,
            BufInfo {
                mem,
                len: data.len(),
            },
            data.len(),
        )
    }

    /// The next QRTR packet received on IPCR DL, if any.
    pub fn take_dl(&mut self) -> Option<DlPacket> {
        self.rx.pop_front()
    }

    /// Run the interrupt work once (for a QRTR pump that waits on the
    /// MHI vectors itself).
    pub fn poll(&mut self) {
        self.service_interrupts();
    }

    /// Wait up to `ms` for traffic, then service the rings.
    pub async fn wait_and_poll(&mut self, ms: u32) {
        self.bus.wait_irq(ms).await;
        self.service_interrupts();
    }

    // ── introspection for tests / diagnostics ────────────────────

    /// `(iommu_base, len)` of an event ring.
    pub fn event_ring_info(&self, i: usize) -> Option<(u64, usize)> {
        self.events
            .get(i)?
            .ring
            .as_ref()
            .map(|r| (r.iommu_base, r.len))
    }

    /// `(iommu_base, len)` of a channel's transfer ring.
    pub fn chan_ring_info(&self, chan: u32) -> Option<(u64, usize)> {
        self.chans
            .get(chan as usize)?
            .tre_ring
            .as_ref()
            .map(|r| (r.iommu_base, r.len))
    }

    /// `(iommu_base, len)` of the command ring.
    pub fn cmd_ring_info(&self) -> Option<(u64, usize)> {
        self.cmd_ring.as_ref().map(|r| (r.iommu_base, r.len))
    }

    /// BAR0 offsets of the BHI / BHIe blocks.
    pub fn bhi_offsets(&self) -> (u32, u32) {
        (self.bhi, self.bhie)
    }

    pub fn dev_wake_count(&self) -> i32 {
        self.dev_wake
    }

    pub fn pending_transitions(&self) -> usize {
        self.transitions.len()
    }

    /// The BHIe table held for the AMSS download: `(vector table DMA
    /// address, vector table length, segment count)`.
    pub fn fbc_table(&self) -> Option<(u64, usize, usize)> {
        self.fbc_image.as_ref().map(|t| {
            (
                t.last().unwrap().dma(),
                core::mem::size_of::<BhiVecEntry>() * (t.len() - 1),
                t.len() - 1,
            )
        })
    }
}

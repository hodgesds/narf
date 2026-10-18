//! Copy Engines — the host ↔ target pipes HTC (and through it WMI /
//! HTT) runs on.
//!
//! A port of Linux `drivers/net/wireless/ath/ath11k/ce.{c,h}` plus the
//! CE half of `pcic.c` (MSI assignment, interrupt gating):
//!
//! - [`HOST_CE_CONFIG_QCA6390`] = `ath11k_host_ce_config_qca6390`
//!   (QCA6390 and every WCN6855-family part, `ce_count` = 9).
//! - [`Ce::alloc`] = `ath11k_hal_srng_init` + `ath11k_ce_alloc_pipes`
//!   (`ath11k_ce_alloc_pipe` / `ath11k_ce_alloc_ring`) +
//!   `ath11k_ce_get_shadow_config`.
//! - [`Ce::init_pipes`] = `ath11k_ce_init_pipes` / `ath11k_ce_init_ring`
//!   (MSI per ring from `ath11k_ce_srng_msi_ring_params_setup`).
//! - [`Ce::start`] = `ath11k_pcic_start`: CE interrupts on
//!   (`ath11k_pcic_ce_irqs_enable`), `ath11k_ce_rx_post_buf`.
//! - [`Ce::send`] = `ath11k_ce_send`; [`Ce::per_engine_service`] =
//!   `ath11k_ce_per_engine_service` (`ath11k_ce_tx_process_cb`,
//!   `ath11k_ce_recv_process_cb`, `ath11k_ce_rx_post_pipe`).
//! - CE4's shadow-register HP refresh timer
//!   (`ath11k_dp_shadow_{init,start}_timer` /
//!   `ath11k_dp_shadow_timer_handler`) and the RX replenish retry
//!   (`ath11k_ce_rx_replenish_retry`), both driven from [`Ce::service`].
//!
//! Buffers: Linux hands the CE `sk_buff`s (`dev_alloc_skb(buf_sz)` per
//! posted RX entry, the caller's skb on TX). NARF gives every ring slot
//! a fixed region of one DMA32 bounce area per direction —
//! `slot * buf_sz` — so `ring->skb[index]` becomes "slot `index` is in
//! flight". RX payloads are copied out into a per-pipe queue
//! ([`Ce::take_rx`]) before the slot is re-posted; TX data is copied in
//! on [`Ce::send`].
//!
//! Interrupts: on PCI the CE interrupt enable/disable is host-side IRQ
//! masking only (the `CE_HOST_IE_*` registers are AHB-only). Each
//! interrupt-enabled CE gets the MSI vector
//! `(msi_data_idx % num_vectors) + base_vector` of the "CE" user;
//! [`install_ce_irq_handlers`] hooks those vectors, the handler records
//! which pipes fired and wakes the owner task, which calls
//! [`Ce::service`]. Like the MHI host, every service pass also polls
//! the interrupt-enabled pipes and counts completions found without an
//! interrupt ([`CeStats::polled_without_irq`]).
//!
//! [`Ce::cleanup_pipes`] = `ath11k_ce_cleanup_pipes` (crash recovery).
//!
//! Not ported: `ath11k_ce_byte_swap` (little-endian host), the
//! `CE_ATTR_DIS_INTR` "except wake IRQ" suspend helpers.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

use super::hal::{
    ce_get_desc_size, errno, flags, DmaMem, Hal, HalCeDesc, HalRingType, SrngParams, TransportError,
};
use super::hw::{HwParams, MsiConfig};
use super::power::ChipIo;

// ── ce.h ──────────────────────────────────────────────────────────

pub const CE_COUNT_MAX: usize = 12;
/// Byte swap data words.
pub const CE_ATTR_BYTE_SWAP_DATA: u32 = 2;
/// No interrupt on copy completion.
pub const CE_ATTR_DIS_INTR: u32 = 8;
/// `CE_ATTR_FLAGS` on a little-endian host.
pub const CE_ATTR_FLAGS: u32 = 0;
/// Poll TX completions of an interrupt-less CE once this many are in
/// flight.
pub const ATH11K_CE_USAGE_THRESHOLD: u32 = 32;
pub const CE_DESC_RING_ALIGN: usize = 8;
/// `ATH11K_CE_RX_POST_RETRY_JIFFIES` (50 jiffies; NARF uses 50 ms).
pub const ATH11K_CE_RX_POST_RETRY_MS: u64 = 50;
/// `ATH11K_SHADOW_CTRL_TIMER_INTERVAL` (dp.h), ms.
pub const ATH11K_SHADOW_CTRL_TIMER_INTERVAL_MS: u64 = 10;
/// pcic.h `ATH11K_PCI_IRQ_CE0_OFFSET`.
pub const ATH11K_PCI_IRQ_CE0_OFFSET: u32 = 3;
/// pci.h `ATH11K_PCI_CE_WAKE_IRQ`.
pub const ATH11K_PCI_CE_WAKE_IRQ: u32 = 2;

/// `CE_RING_IDX_INCR`.
pub const fn ce_ring_idx_incr(nentries_mask: u32, idx: u32) -> u32 {
    (idx + 1) & nentries_mask
}

/// `recv_cb` of a CE: who consumes what arrives on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CeRecv {
    /// `ath11k_htc_rx_completion_handler`.
    Htc,
    /// `ath11k_dp_htt_htc_t2h_msg_handler`.
    HttT2h,
}

/// `send_cb` of a CE.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CeSend {
    /// `ath11k_htc_tx_completion_handler`.
    Htc,
}

/// `struct ce_attr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CeAttr {
    pub flags: u32,
    pub src_nentries: u32,
    /// Max source send size; also the destination buffer size.
    pub src_sz_max: u32,
    pub dest_nentries: u32,
    pub recv_cb: Option<CeRecv>,
    pub send_cb: Option<CeSend>,
}

const fn attr(
    flags: u32,
    src_nentries: u32,
    src_sz_max: u32,
    dest_nentries: u32,
    recv_cb: Option<CeRecv>,
    send_cb: Option<CeSend>,
) -> CeAttr {
    CeAttr {
        flags,
        src_nentries,
        src_sz_max,
        dest_nentries,
        recv_cb,
        send_cb,
    }
}

/// Linux `ath11k_host_ce_config_qca6390` (ce.c).
pub const HOST_CE_CONFIG_QCA6390: [CeAttr; 9] = [
    // CE0: host->target HTC control and raw streams
    attr(CE_ATTR_FLAGS, 16, 2048, 0, None, None),
    // CE1: target->host HTT + HTC control
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    // CE2: target->host WMI
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    // CE3: host->target WMI (mac0)
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    // CE4: host->target HTT
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 2048, 256, 0, None, None),
    // CE5: target->host pktlog
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::HttT2h), None),
    // CE6: target autonomous hif_memcpy
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 0, 0, 0, None, None),
    // CE7: host->target WMI (mac1)
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    // CE8: target autonomous hif_memcpy
    attr(CE_ATTR_FLAGS, 0, 0, 0, None, None),
];

/// Linux `ath11k_host_ce_config_qcn9074` (ce.c).
pub const HOST_CE_CONFIG_QCN9074: [CeAttr; 6] = [
    attr(CE_ATTR_FLAGS, 16, 2048, 0, None, None),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 0, 2048, 32, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 2048, 256, 0, None, None),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::HttT2h), None),
];

/// `ath11k_ce_need_shadow_fix`: only CE4 needs the HP refresh timer.
pub const fn ce_need_shadow_fix(ce_id: u32) -> bool {
    ce_id == 4
}

/// CE failing-step codes (`narf_memory::diag`). Bring-up failures
/// ([`Ce::alloc`], [`Ce::init_pipes`]) are latched by those calls;
/// [`Ce::send`] returns its errors for the caller (HTC) to report if it
/// gives up.
pub mod step {
    /// Source ring memory (detail = ce << 24 | bytes).
    pub const ALLOC_SRC_RING: u32 = 90;
    /// Destination ring memory.
    pub const ALLOC_DST_RING: u32 = 91;
    /// Destination status ring memory.
    pub const ALLOC_STATUS_RING: u32 = 92;
    /// TX bounce buffers.
    pub const ALLOC_TX_BUF: u32 = 93;
    /// RX buffers.
    pub const ALLOC_RX_BUF: u32 = 94;
    /// `ath11k_hal_srng_setup` failed (detail = ce << 24 | type << 16 |
    /// HAL step).
    pub const INIT_RING: u32 = 95;
    /// Pipe out of range or without the needed ring (detail = pipe).
    pub const BAD_PIPE: u32 = 96;
    /// Send larger than the pipe's `src_sz_max` (detail = pipe << 24 |
    /// len).
    pub const OVERSIZE: u32 = 97;
    /// No free source ring entry (`-ENOBUFS`; detail = pipe).
    pub const RING_FULL: u32 = 98;
    /// Send after a crash flush (`-ESHUTDOWN`; detail = pipe).
    pub const SHUTDOWN: u32 = 99;
    /// RX status descriptor length 0 or larger than the buffer (detail =
    /// pipe << 24 | nbytes).
    pub const RX_BAD_LEN: u32 = 100;
    /// RX buffer post failed with something other than `-ENOSPC`
    /// (detail = pipe).
    pub const RX_POST: u32 = 101;
}

// ── MSI ───────────────────────────────────────────────────────────

/// What the CE needs from the PCI MSI setup (`ab->pci.msi`).
#[derive(Copy, Clone, Debug)]
pub struct CeMsi {
    /// Programmed Message Address (`addr_lo | addr_hi << 32`).
    pub addr: u64,
    /// `ep_base_data`.
    pub ep_base_data: u32,
    /// The user layout in force (chip table or single-MSI fallback).
    pub config: &'static MsiConfig,
}

/// Linux `ath11k_pcic_get_ce_msi_idx`: index of `ce_id` among the
/// interrupt-enabled CEs.
pub fn ce_msi_idx(host_ce_config: &[CeAttr], ce_id: u32) -> u32 {
    let mut idx = 0;
    for (i, a) in host_ce_config.iter().enumerate() {
        if a.flags & CE_ATTR_DIS_INTR != 0 {
            continue;
        }
        if i as u32 == ce_id {
            break;
        }
        idx += 1;
    }
    idx
}

/// Linux `ath11k_ce_srng_msi_ring_params_setup`: `(msi_addr,
/// msi_data)` for a ring of `ce_id`, or `None` when there is no "CE"
/// MSI user (Linux then leaves the ring without MSI).
pub fn ce_ring_msi(host_ce_config: &[CeAttr], msi: &CeMsi, ce_id: u32) -> Option<(u64, u32)> {
    let (count, start, _base_vector) = msi.config.user_assignment("CE", msi.ep_base_data)?;
    if count == 0 {
        return None;
    }
    let idx = ce_msi_idx(host_ce_config, ce_id);
    Some((msi.addr, (idx % count) + start))
}

/// Linux `ath11k_pcic_config_irq` (CE part): the vector, relative to
/// the device's first vector, CE `ce_id` interrupts on. `None` for an
/// interrupt-less CE.
pub fn ce_irq_vector(host_ce_config: &[CeAttr], config: &MsiConfig, ce_id: u32) -> Option<u32> {
    let a = host_ce_config.get(ce_id as usize)?;
    if a.flags & CE_ATTR_DIS_INTR != 0 {
        return None;
    }
    let (count, _start, base_vector) = config.user_assignment("CE", 0)?;
    if count == 0 {
        return None;
    }
    Some(ce_msi_idx(host_ce_config, ce_id) % count + base_vector)
}

/// Handler cookie for device vector `i`: bitmask of the CEs that
/// interrupt on it (`None` if none).
pub fn ce_vector_cookie(host_ce_config: &[CeAttr], config: &MsiConfig, i: u32) -> Option<u64> {
    let mut mask = 0u64;
    for ce in 0..host_ce_config.len() as u32 {
        if ce_irq_vector(host_ce_config, config, ce) == Some(i) {
            mask |= 1 << ce;
        }
    }
    (mask != 0).then_some(mask)
}

/// CEs whose interrupt fired and that [`Ce::service`] has not handled.
static CE_IRQ_PENDING: AtomicU32 = AtomicU32::new(0);
/// `ATH11K_FLAG_CE_IRQ_ENABLED`.
static CE_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
static CE_IRQS_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Tasks parked in [`MsiCeIrq::wait`]. After bring-up more than one task
/// waits on the device (the runtime service loop and a mac-layer
/// operation polling for its event), so every waiter is kept and woken:
/// a single slot would leave all but the last to their sleep timeout.
const CE_WAITERS: usize = 4;
static CE_WAKER: IrqSafeSpinLock<[Option<Waker>; CE_WAITERS]> =
    IrqSafeSpinLock::new([const { None }; CE_WAITERS]);

/// Wake every task parked in [`MsiCeIrq::wait`] (CE and DP interrupt
/// handlers).
pub(crate) fn wake_waiters() {
    let taken: [Option<Waker>; CE_WAITERS] = {
        let mut g = CE_WAKER.lock();
        core::array::from_fn(|i| g[i].take())
    };
    for w in taken.into_iter().flatten() {
        w.wake();
    }
}

fn register_waiter(w: &Waker) {
    let mut g = CE_WAKER.lock();
    if g.iter().flatten().any(|o| o.will_wake(w)) {
        return;
    }
    match g.iter_mut().find(|s| s.is_none()) {
        Some(slot) => *slot = Some(w.clone()),
        // Full: replace the oldest-registered slot; that task still
        // wakes on its sleep deadline.
        None => g[0] = Some(w.clone()),
    }
}

/// Some interrupt the device owner services is pending (CE, or a DP
/// ext group — [`super::runtime::dp_irq_pending`]).
fn irq_pending() -> bool {
    CE_IRQ_PENDING.load(Ordering::Acquire) != 0 || super::runtime::dp_irq_pending()
}
/// CE interrupts delivered (any CE vector).
pub static CE_MSI_FIRES: AtomicU64 = AtomicU64::new(0);

/// `ath11k_pcic_ce_interrupt_handler`: note the CEs (cookie) and wake
/// the owner task (the tasklet's work runs there). Ignored while CE
/// interrupts are disabled, as in Linux.
fn ce_msi_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    if !CE_IRQ_ENABLED.load(Ordering::Acquire) {
        return narf_interrupts::IrqStatus::Handled;
    }
    CE_MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    CE_IRQ_PENDING.fetch_or(cookie as u32, Ordering::AcqRel);
    wake_waiters();
    narf_interrupts::IrqStatus::Handled
}

/// Hook the CE MSI vectors (`ath11k_pcic_config_irq`, CE part). The
/// vectors keep their probe-time counting handler; this adds the CE
/// one. `base_irq` is the device's first IDT vector, `n_vectors` the
/// count granted. Idempotent.
pub fn install_ce_irq_handlers(
    host_ce_config: &'static [CeAttr],
    config: &'static MsiConfig,
    base_irq: u8,
    n_vectors: u8,
) {
    if CE_IRQS_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    for i in 0..n_vectors {
        if let Some(cookie) = ce_vector_cookie(host_ce_config, config, i as u32) {
            narf_interrupts::install_handler_named(base_irq + i, "ath11k-ce", cookie, ce_msi_irq);
        }
    }
}

/// `ath11k_pcic_ce_irqs_enable` / `_disable` (the flag the handler
/// checks; MSI itself stays on).
pub fn set_ce_irqs_enabled(on: bool) {
    CE_IRQ_ENABLED.store(on, Ordering::Release);
}

/// Interrupt + time source for the CE owner task.
pub trait CeIrq {
    /// Take the bitmask of CEs that interrupted.
    fn take_pending(&self) -> u32;
    /// Resolve when a CE interrupt arrives or `ms` pass.
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send;
}

/// The real CE interrupts (MSI handlers above).
#[derive(Copy, Clone, Debug, Default)]
pub struct MsiCeIrq;

struct CeIrqWait {
    sleep: narf_time::SleepUntil,
}

impl Future for CeIrqWait {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if irq_pending() {
            return Poll::Ready(());
        }
        register_waiter(cx.waker());
        // Re-check after publishing the waker.
        if irq_pending() {
            return Poll::Ready(());
        }
        Pin::new(&mut self.sleep).poll(cx)
    }
}

impl CeIrq for MsiCeIrq {
    fn take_pending(&self) -> u32 {
        CE_IRQ_PENDING.swap(0, Ordering::AcqRel)
    }
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send {
        CeIrqWait {
            sleep: narf_time::SleepUntil::new(
                narf_time::Deadline::after_ms(ms as u64).as_instant(),
            ),
        }
    }
}

/// Monotonic milliseconds (the real [`Ce`] clock).
pub fn monotonic_ms() -> u64 {
    narf_time::wall::monotonic_ns() / 1_000_000
}

// ── rings / pipes ─────────────────────────────────────────────────

/// `struct ath11k_ce_ring`.
#[derive(Debug)]
struct CeRing {
    nentries: u32,
    nentries_mask: u32,
    sw_index: u32,
    write_index: u32,
    /// Descriptor memory until `init_ring` hands it to the HAL.
    mem: Option<DmaMem>,
    /// `base_addr_ce_space` (aligned).
    base_addr_ce_space: u64,
    hal_ring_id: u32,
}

/// `ath11k_ce_alloc_ring`.
fn ce_alloc_ring(nentries: u32, desc_sz: usize) -> Result<CeRing, TransportError> {
    let mem = DmaMem::alloc(nentries as usize * desc_sz, CE_DESC_RING_ALIGN)?;
    Ok(CeRing {
        nentries,
        nentries_mask: nentries - 1,
        sw_index: 0,
        write_index: 0,
        base_addr_ce_space: mem.paddr(),
        mem: Some(mem),
        hal_ring_id: 0,
    })
}

/// Shadow-register HP refresh (`struct ath11k_hp_update_timer`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HpUpdateTimer {
    pub init: bool,
    pub started: bool,
    pub tx_num: u32,
    pub timer_tx_num: u32,
    pub ring_id: u32,
    pub interval_ms: u64,
    pub deadline_ms: u64,
}

impl HpUpdateTimer {
    /// `ath11k_dp_shadow_start_timer`.
    pub fn start(&mut self, now_ms: u64) {
        if !self.init {
            return;
        }
        self.tx_num = self.tx_num.wrapping_add(1);
        if self.started {
            return;
        }
        self.started = true;
        self.timer_tx_num = self.tx_num;
        self.deadline_ms = now_ms + self.interval_ms;
    }

    /// `ath11k_dp_shadow_timer_handler` if the timer is due: `true` when
    /// the HP must be re-published (no TX in the last interval).
    pub fn expire(&mut self, now_ms: u64) -> bool {
        if !self.started || now_ms < self.deadline_ms {
            return false;
        }
        if self.timer_tx_num != self.tx_num {
            self.timer_tx_num = self.tx_num;
            self.deadline_ms = now_ms + self.interval_ms;
            false
        } else {
            self.started = false;
            true
        }
    }
}

/// Per-pipe counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CePipeStats {
    pub tx_posted: u32,
    pub tx_completed: u32,
    pub tx_full: u32,
    pub rx_posted: u32,
    pub rx_completed: u32,
    pub rx_bad_len: u32,
}

/// `struct ath11k_ce_pipe`.
#[derive(Debug)]
pub struct CePipe {
    pub pipe_num: u32,
    pub attr_flags: u32,
    pub buf_sz: u32,
    pub rx_buf_needed: u32,
    pub send_cb: Option<CeSend>,
    pub recv_cb: Option<CeRecv>,
    src_ring: Option<CeRing>,
    dest_ring: Option<CeRing>,
    status_ring: Option<CeRing>,
    /// TX bounce area: `src nentries * src_sz_max`.
    tx_buf: Option<DmaMem>,
    /// Length of the send in flight on each source slot.
    tx_inflight: Vec<Option<u32>>,
    /// RX buffers: `dest nentries * buf_sz`.
    rx_buf: Option<DmaMem>,
    rx_posted: Vec<bool>,
    rx_queue: VecDeque<Vec<u8>>,
    /// Completed sends handed to `send_cb` (only without credit flow).
    tx_done: VecDeque<u32>,
    tx_transfer_id: Vec<u32>,
    hp_timer: HpUpdateTimer,
    pub stats: CePipeStats,
}

impl CePipe {
    fn empty(pipe_num: u32) -> Self {
        CePipe {
            pipe_num,
            attr_flags: 0,
            buf_sz: 0,
            rx_buf_needed: 0,
            send_cb: None,
            recv_cb: None,
            src_ring: None,
            dest_ring: None,
            status_ring: None,
            tx_buf: None,
            tx_inflight: Vec::new(),
            rx_buf: None,
            rx_posted: Vec::new(),
            rx_queue: VecDeque::new(),
            tx_done: VecDeque::new(),
            tx_transfer_id: Vec::new(),
            hp_timer: HpUpdateTimer::default(),
            stats: CePipeStats::default(),
        }
    }

    /// HAL ring ids `(src, dest, status)` once initialised.
    pub fn ring_ids(&self) -> (Option<u32>, Option<u32>, Option<u32>) {
        let id = |r: &Option<CeRing>| {
            r.as_ref()
                .filter(|r| r.mem.is_none())
                .map(|r| r.hal_ring_id)
        };
        (
            id(&self.src_ring),
            id(&self.dest_ring),
            id(&self.status_ring),
        )
    }

    /// `(nentries, sw_index, write_index)` of the source ring.
    pub fn src_indices(&self) -> Option<(u32, u32, u32)> {
        self.src_ring
            .as_ref()
            .map(|r| (r.nentries, r.sw_index, r.write_index))
    }

    /// `(nentries, sw_index, write_index)` of the destination ring.
    pub fn dest_indices(&self) -> Option<(u32, u32, u32)> {
        self.dest_ring
            .as_ref()
            .map(|r| (r.nentries, r.sw_index, r.write_index))
    }

    /// Device address of RX slot `i`.
    pub fn rx_slot_paddr(&self, i: u32) -> Option<u64> {
        self.rx_buf
            .as_ref()
            .map(|b| b.paddr() + i as u64 * self.buf_sz as u64)
    }

    pub fn hp_timer(&self) -> HpUpdateTimer {
        self.hp_timer
    }
}

/// Whole-CE counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CeStats {
    /// Interrupts serviced per CE.
    pub irqs: [u32; CE_COUNT_MAX],
    /// Service passes that found completions on a CE whose interrupt
    /// had not fired — non-zero means MSI delivery is not working.
    pub polled_without_irq: u32,
    /// HP re-published by the CE4 shadow timer.
    pub shadow_refresh: u32,
    pub rx_post_retries: u32,
}

/// The Copy Engine context (`struct ath11k_ce` + the HAL it runs on).
#[derive(Debug)]
pub struct Ce {
    pub hal: Hal,
    pipes: Vec<CePipe>,
    host_ce_config: &'static [CeAttr],
    credit_flow: bool,
    supports_shadow_regs: bool,
    msi: CeMsi,
    clock: fn() -> u64,
    /// `ATH11K_FLAG_CRASH_FLUSH`.
    pub crash_flush: bool,
    /// `rx_replenish_retry` deadline.
    rx_retry_at: Option<u64>,
    pub stats: CeStats,
}

fn ce_err(step: u32, ce: u32, low: u32, errno: i32) -> TransportError {
    TransportError::new(step, (ce << 24) | (low & 0x00ff_ffff), errno)
}

impl Ce {
    /// `ath11k_hal_srng_init` + `ath11k_ce_alloc_pipes` (+ the shadow
    /// configuration). Failures are latched and printed. `clock` gives
    /// monotonic milliseconds ([`monotonic_ms`] on hardware).
    pub fn alloc(hw: &HwParams, msi: CeMsi, clock: fn() -> u64) -> Result<Ce, TransportError> {
        let r = Self::alloc_inner(hw, msi, clock);
        if let Err(e) = &r {
            e.report("ath11k CE alloc");
        }
        r
    }

    fn alloc_inner(hw: &HwParams, msi: CeMsi, clock: fn() -> u64) -> Result<Ce, TransportError> {
        let hal = Hal::new(hw)?;
        let mut pipes = Vec::with_capacity(hw.ce_count());
        for (i, attr) in hw.host_ce_config.iter().enumerate() {
            pipes.push(Self::alloc_pipe(i as u32, attr)?);
        }
        Ok(Ce {
            hal,
            pipes,
            host_ce_config: hw.host_ce_config,
            credit_flow: hw.credit_flow,
            supports_shadow_regs: hw.supports_shadow_regs,
            msi,
            clock,
            crash_flush: false,
            rx_retry_at: None,
            stats: CeStats::default(),
        })
    }

    /// `ath11k_ce_alloc_pipe` (+ NARF's per-slot bounce buffers).
    fn alloc_pipe(i: u32, attr: &CeAttr) -> Result<CePipe, TransportError> {
        let mut pipe = CePipe::empty(i);
        pipe.attr_flags = attr.flags;
        pipe.buf_sz = attr.src_sz_max;

        if attr.src_nentries != 0 {
            pipe.send_cb = attr.send_cb;
            let nentries = attr.src_nentries.next_power_of_two();
            let desc_sz = ce_get_desc_size(HalCeDesc::Src);
            pipe.src_ring = Some(
                ce_alloc_ring(nentries, desc_sz)
                    .map_err(|e| ce_err(step::ALLOC_SRC_RING, i, e.detail, e.errno))?,
            );
            let bytes = nentries as usize * attr.src_sz_max.max(4) as usize;
            pipe.tx_buf = Some(
                DmaMem::alloc(bytes, CE_DESC_RING_ALIGN)
                    .map_err(|e| ce_err(step::ALLOC_TX_BUF, i, e.detail, e.errno))?,
            );
            pipe.tx_inflight = vec![None; nentries as usize];
            pipe.tx_transfer_id = vec![0; nentries as usize];
        }

        if attr.dest_nentries != 0 {
            pipe.recv_cb = attr.recv_cb;
            let nentries = attr.dest_nentries.next_power_of_two();
            let desc_sz = ce_get_desc_size(HalCeDesc::Dst);
            pipe.dest_ring = Some(
                ce_alloc_ring(nentries, desc_sz)
                    .map_err(|e| ce_err(step::ALLOC_DST_RING, i, e.detail, e.errno))?,
            );
            let desc_sz = ce_get_desc_size(HalCeDesc::DstStatus);
            pipe.status_ring = Some(
                ce_alloc_ring(nentries, desc_sz)
                    .map_err(|e| ce_err(step::ALLOC_STATUS_RING, i, e.detail, e.errno))?,
            );
            let bytes = nentries as usize * attr.src_sz_max.max(4) as usize;
            pipe.rx_buf = Some(
                DmaMem::alloc(bytes, CE_DESC_RING_ALIGN)
                    .map_err(|e| ce_err(step::ALLOC_RX_BUF, i, e.detail, e.errno))?,
            );
            pipe.rx_posted = vec![false; nentries as usize];
        }
        Ok(pipe)
    }

    /// The QMI `WLAN_CFG` shadow register v2 list
    /// (`ath11k_ce_get_shadow_config`); empty without shadow registers.
    pub fn shadow_reg_v2(&self) -> &[u32] {
        self.hal.shadow_reg_v2()
    }

    pub fn ce_count(&self) -> usize {
        self.pipes.len()
    }

    pub fn pipe(&self, ce_id: u32) -> Option<&CePipe> {
        self.pipes.get(ce_id as usize)
    }

    /// `ath11k_ce_get_attr_flags`.
    pub fn attr_flags(&self, ce_id: u32) -> Option<u32> {
        self.host_ce_config.get(ce_id as usize).map(|a| a.flags)
    }

    /// `ath11k_ce_init_ring`.
    fn init_ring(
        &mut self,
        io: &impl ChipIo,
        ce_id: u32,
        ty: HalRingType,
    ) -> Result<(), TransportError> {
        let attr = self.host_ce_config[ce_id as usize];
        let msi = if attr.flags & CE_ATTR_DIS_INTR == 0 {
            ce_ring_msi(self.host_ce_config, &self.msi, ce_id)
        } else {
            None
        };
        let pipe = &mut self.pipes[ce_id as usize];
        let ring = match ty {
            HalRingType::CeSrc => pipe.src_ring.as_mut(),
            HalRingType::CeDst => pipe.dest_ring.as_mut(),
            HalRingType::CeDstStatus => pipe.status_ring.as_mut(),
            _ => None,
        };
        let Some(ring) = ring else {
            return Err(ce_err(
                step::INIT_RING,
                ce_id,
                (ty as u32) << 16,
                errno::EINVAL,
            ));
        };
        let Some(mem) = ring.mem.take() else {
            // Already initialised.
            return Err(ce_err(
                step::INIT_RING,
                ce_id,
                ((ty as u32) << 16) | super::hal::step::RING_IN_USE,
                errno::EINVAL,
            ));
        };
        let mut params = SrngParams::new(mem, ring.nentries);
        if let Some((addr, data)) = msi {
            params.msi_addr = addr;
            params.msi_data = data;
            params.flags |= flags::MSI_INTR;
        }
        let intr = attr.flags & CE_ATTR_DIS_INTR == 0;
        match ty {
            HalRingType::CeSrc => {
                if intr {
                    params.intr_batch_cntr_thres_entries = 1;
                }
            }
            HalRingType::CeDst => {
                params.max_buffer_len = attr.src_sz_max;
                if intr {
                    params.intr_timer_thres_us = 1024;
                    params.flags |= flags::LOW_THRESH_INTR_EN;
                    params.low_threshold = ring.nentries - 3;
                }
            }
            HalRingType::CeDstStatus => {
                if intr {
                    params.intr_batch_cntr_thres_entries = 1;
                    params.intr_timer_thres_us = 0x1000;
                }
            }
            _ => unreachable!(),
        }
        let nentries = ring.nentries;
        let id = self.hal.srng_setup(io, ty, ce_id, 0, params).map_err(|e| {
            ce_err(
                step::INIT_RING,
                ce_id,
                ((ty as u32) << 16) | (e.step & 0xffff),
                e.errno,
            )
        })?;
        let pipe = &mut self.pipes[ce_id as usize];
        let ring = match ty {
            HalRingType::CeSrc => pipe.src_ring.as_mut(),
            HalRingType::CeDst => pipe.dest_ring.as_mut(),
            _ => pipe.status_ring.as_mut(),
        };
        if let Some(r) = ring {
            r.hal_ring_id = id;
        }
        let _ = nentries;
        if self.supports_shadow_regs && ce_need_shadow_fix(ce_id) {
            pipe.hp_timer = HpUpdateTimer {
                init: true,
                ring_id: id,
                interval_ms: ATH11K_SHADOW_CTRL_TIMER_INTERVAL_MS,
                ..HpUpdateTimer::default()
            };
        }
        Ok(())
    }

    /// `ath11k_ce_init_pipes`. Failures are latched and printed.
    pub fn init_pipes(&mut self, io: &impl ChipIo) -> Result<(), TransportError> {
        let r = self.init_pipes_inner(io);
        if let Err(e) = &r {
            e.report("ath11k CE init");
        }
        r
    }

    fn init_pipes_inner(&mut self, io: &impl ChipIo) -> Result<(), TransportError> {
        for i in 0..self.pipes.len() as u32 {
            if self.pipes[i as usize].src_ring.is_some() {
                self.init_ring(io, i, HalRingType::CeSrc)?;
                let r = self.pipes[i as usize].src_ring.as_mut().unwrap();
                r.write_index = 0;
                r.sw_index = 0;
            }
            if self.pipes[i as usize].dest_ring.is_some() {
                self.init_ring(io, i, HalRingType::CeDst)?;
                let p = &mut self.pipes[i as usize];
                let r = p.dest_ring.as_mut().unwrap();
                p.rx_buf_needed = if r.nentries != 0 { r.nentries - 2 } else { 0 };
                r.write_index = 0;
                r.sw_index = 0;
            }
            if self.pipes[i as usize].status_ring.is_some() {
                self.init_ring(io, i, HalRingType::CeDstStatus)?;
                let r = self.pipes[i as usize].status_ring.as_mut().unwrap();
                r.write_index = 0;
                r.sw_index = 0;
            }
        }
        Ok(())
    }

    /// `ath11k_pcic_start`: CE interrupts on, RX buffers posted.
    pub fn start(&mut self, io: &impl ChipIo) {
        set_ce_irqs_enabled(true);
        self.rx_post_buf(io);
    }

    /// `ath11k_pcic_stop` minus the buffer frees (they go with `self`):
    /// CE interrupts off.
    pub fn stop(&mut self) {
        set_ce_irqs_enabled(false);
    }

    /// Linux `ath11k_ce_cleanup_pipes` (crash recovery, after the device
    /// reset): every posted RX buffer is dropped (`ath11k_ce_rx_pipe_cleanup`),
    /// interrupt-less source rings are reaped
    /// (`ath11k_ce_poll_send_completed`). NARF also hands each ring's
    /// descriptor memory back from the HAL (`Hal::srng_free`; Linux keeps
    /// it in `ce_ring->base_addr_owner_unaligned` and re-runs the setup
    /// over it after `ath11k_hal_srng_clear`) and forgets the sends still
    /// in flight, so [`Self::init_pipes`] can run again.
    pub fn cleanup_pipes(&mut self) {
        for i in 0..self.pipes.len() as u32 {
            self.poll_send_completed(i);
            let pipe = &mut self.pipes[i as usize];
            for p in pipe.rx_posted.iter_mut() {
                *p = false;
            }
            pipe.rx_buf_needed = 0;
            pipe.rx_queue.clear();
            for t in pipe.tx_inflight.iter_mut() {
                *t = None;
            }
            pipe.tx_done.clear();
            pipe.hp_timer = HpUpdateTimer::default();
            let (s, d, st) = pipe.ring_ids();
            for (id, which) in [(s, 0), (d, 1), (st, 2)] {
                let Some(id) = id else { continue };
                let mem = self.hal.srng_free(id);
                let pipe = &mut self.pipes[i as usize];
                let ring = match which {
                    0 => pipe.src_ring.as_mut(),
                    1 => pipe.dest_ring.as_mut(),
                    _ => pipe.status_ring.as_mut(),
                };
                if let Some(r) = ring {
                    r.mem = mem;
                    r.sw_index = 0;
                    r.write_index = 0;
                }
            }
        }
        self.rx_retry_at = None;
    }

    // ── RX ────────────────────────────────────────────────────────

    /// `ath11k_ce_rx_buf_enqueue_pipe`.
    fn rx_buf_enqueue_pipe(&mut self, io: &impl ChipIo, ce_id: u32) -> Result<(), i32> {
        let pipe = &self.pipes[ce_id as usize];
        let ring = pipe.dest_ring.as_ref().ok_or(errno::EINVAL)?;
        let id = ring.hal_ring_id;
        let write_index = ring.write_index;
        let nentries_mask = ring.nentries_mask;
        let paddr = pipe.rx_slot_paddr(write_index).ok_or(errno::EINVAL)?;

        self.hal.access_begin(id);
        let ret = if self.hal.src_num_free(id, false) < 1 {
            Err(errno::ENOSPC)
        } else {
            match self.hal.src_get_next_entry(id) {
                None => Err(errno::ENOSPC),
                Some(desc) => {
                    self.hal.ce_dst_set_desc(id, desc, paddr);
                    let pipe = &mut self.pipes[ce_id as usize];
                    pipe.rx_posted[write_index as usize] = true;
                    let ring = pipe.dest_ring.as_mut().unwrap();
                    ring.write_index = ce_ring_idx_incr(nentries_mask, write_index);
                    pipe.rx_buf_needed -= 1;
                    pipe.stats.rx_posted += 1;
                    Ok(())
                }
            }
        };
        self.hal.access_end(io, id);
        ret
    }

    /// `ath11k_ce_rx_post_pipe`.
    fn rx_post_pipe(&mut self, io: &impl ChipIo, ce_id: u32) -> Result<(), i32> {
        let p = &self.pipes[ce_id as usize];
        if p.dest_ring.is_none() && p.status_ring.is_none() {
            return Ok(());
        }
        if p.ring_ids().1.is_none() {
            // Not initialised (Linux would post into a NULL srng).
            return Err(errno::EINVAL);
        }
        while self.pipes[ce_id as usize].rx_buf_needed != 0 {
            self.rx_buf_enqueue_pipe(io, ce_id)?;
        }
        Ok(())
    }

    /// `ath11k_ce_rx_post_buf`.
    pub fn rx_post_buf(&mut self, io: &impl ChipIo) {
        for i in 0..self.pipes.len() as u32 {
            match self.rx_post_pipe(io, i) {
                Ok(()) | Err(errno::ENOSPC) => {}
                Err(e) => {
                    TransportError::new(step::RX_POST, i, e).report("ath11k CE rx post");
                    self.rx_retry_at = Some((self.clock)() + ATH11K_CE_RX_POST_RETRY_MS);
                    return;
                }
            }
        }
    }

    /// `ath11k_ce_completed_recv_next`: `(slot, nbytes)`.
    fn completed_recv_next(&mut self, io: &impl ChipIo, ce_id: u32) -> Option<(u32, u32)> {
        let pipe = &self.pipes[ce_id as usize];
        let dest = pipe.dest_ring.as_ref()?;
        let sw_index = dest.sw_index;
        let nentries_mask = dest.nentries_mask;
        let id = pipe.status_ring.as_ref()?.hal_ring_id;

        self.hal.access_begin(id);
        let ret = match self.hal.dst_get_next_entry(id) {
            None => None,
            Some(desc) => {
                let nbytes = self.hal.ce_dst_status_get_length(id, desc);
                let pipe = &mut self.pipes[ce_id as usize];
                pipe.rx_posted[sw_index as usize] = false;
                pipe.dest_ring.as_mut().unwrap().sw_index =
                    ce_ring_idx_incr(nentries_mask, sw_index);
                pipe.rx_buf_needed += 1;
                Some((sw_index, nbytes))
            }
        };
        self.hal.access_end(io, id);
        ret
    }

    /// `ath11k_ce_recv_process_cb`: returns completions handled.
    fn recv_process_cb(&mut self, io: &impl ChipIo, ce_id: u32) -> u32 {
        let mut n = 0;
        while let Some((slot, nbytes)) = self.completed_recv_next(io, ce_id) {
            n += 1;
            let pipe = &mut self.pipes[ce_id as usize];
            let max_nbytes = pipe.buf_sz;
            if max_nbytes < nbytes || nbytes == 0 {
                pipe.stats.rx_bad_len += 1;
                TransportError::new(
                    step::RX_BAD_LEN,
                    (ce_id << 24) | (nbytes & 0x00ff_ffff),
                    errno::EIO,
                )
                .report("ath11k CE rx length");
                continue;
            }
            let mut buf = vec![0u8; nbytes as usize];
            if let Some(b) = pipe.rx_buf.as_ref() {
                b.read_bytes(slot as usize * max_nbytes as usize, &mut buf);
            }
            pipe.stats.rx_completed += 1;
            pipe.rx_queue.push_back(buf);
        }
        match self.rx_post_pipe(io, ce_id) {
            Ok(()) | Err(errno::ENOSPC) => {}
            Err(e) => {
                TransportError::new(step::RX_POST, ce_id, e).report("ath11k CE rx post");
                self.rx_retry_at = Some((self.clock)() + ATH11K_CE_RX_POST_RETRY_MS);
            }
        }
        n
    }

    /// Next received payload on `ce_id` (`recv_cb` consumer side).
    pub fn take_rx(&mut self, ce_id: u32) -> Option<Vec<u8>> {
        self.pipes.get_mut(ce_id as usize)?.rx_queue.pop_front()
    }

    /// Next received payload on any pipe, lowest pipe first.
    pub fn take_rx_any(&mut self) -> Option<(u32, Vec<u8>)> {
        for p in self.pipes.iter_mut() {
            if let Some(b) = p.rx_queue.pop_front() {
                return Some((p.pipe_num, b));
            }
        }
        None
    }

    /// Payloads queued on `ce_id`.
    pub fn rx_pending(&self, ce_id: u32) -> usize {
        self.pipes
            .get(ce_id as usize)
            .map_or(0, |p| p.rx_queue.len())
    }

    // ── TX ────────────────────────────────────────────────────────

    /// `ath11k_ce_completed_send_next`: the completed slot.
    fn completed_send_next(&mut self, ce_id: u32) -> Option<u32> {
        let ring = self.pipes[ce_id as usize].src_ring.as_ref()?;
        let sw_index = ring.sw_index;
        let nentries_mask = ring.nentries_mask;
        let id = ring.hal_ring_id;
        self.hal.access_begin(id);
        self.hal.src_reap_next(id)?;
        let ring = self.pipes[ce_id as usize].src_ring.as_mut().unwrap();
        ring.sw_index = ce_ring_idx_incr(nentries_mask, sw_index);
        Some(sw_index)
    }

    /// `ath11k_ce_tx_process_cb`: returns completions handled.
    fn tx_process_cb(&mut self, ce_id: u32) -> u32 {
        let mut n = 0;
        while let Some(slot) = self.completed_send_next(ce_id) {
            let credit_flow = self.credit_flow;
            let pipe = &mut self.pipes[ce_id as usize];
            let Some(_len) = pipe.tx_inflight[slot as usize].take() else {
                continue;
            };
            n += 1;
            pipe.stats.tx_completed += 1;
            if pipe.send_cb.is_none() || credit_flow {
                continue;
            }
            let id = pipe.tx_transfer_id[slot as usize];
            pipe.tx_done.push_back(id);
        }
        n
    }

    /// Completed sends to hand to `send_cb` (`transfer_id`s; only on a
    /// pipe with a `send_cb` and without credit flow).
    pub fn take_tx_done(&mut self, ce_id: u32) -> Option<u32> {
        self.pipes.get_mut(ce_id as usize)?.tx_done.pop_front()
    }

    /// `ath11k_ce_poll_send_completed`.
    pub fn poll_send_completed(&mut self, ce_id: u32) -> u32 {
        let Some(p) = self.pipes.get(ce_id as usize) else {
            return 0;
        };
        if p.attr_flags & CE_ATTR_DIS_INTR != 0
            && self.host_ce_config[ce_id as usize].src_nentries != 0
        {
            self.tx_process_cb(ce_id)
        } else {
            0
        }
    }

    /// Linux `ath11k_ce_send`: copy `data` into the next source slot and
    /// post it with `transfer_id` as descriptor metadata.
    ///
    /// NARF-stricter: a pipe without a source ring (Linux: NULL deref)
    /// fails `BAD_PIPE`/`-EINVAL`, and a send larger than the pipe's
    /// `src_sz_max` (Linux trusts HTC) fails `OVERSIZE`/`-EINVAL`.
    pub fn send(
        &mut self,
        io: &impl ChipIo,
        pipe_id: u32,
        data: &[u8],
        transfer_id: u16,
    ) -> Result<(), TransportError> {
        let Some(pipe) = self.pipes.get(pipe_id as usize) else {
            return Err(TransportError::new(step::BAD_PIPE, pipe_id, errno::EINVAL));
        };
        let Some(src) = pipe.src_ring.as_ref() else {
            return Err(TransportError::new(step::BAD_PIPE, pipe_id, errno::EINVAL));
        };
        if src.mem.is_some() {
            // Ring not initialised yet.
            return Err(TransportError::new(step::BAD_PIPE, pipe_id, errno::EINVAL));
        }
        if data.len() > pipe.buf_sz as usize {
            return Err(TransportError::new(
                step::OVERSIZE,
                (pipe_id << 24) | (data.len() as u32 & 0x00ff_ffff),
                errno::EINVAL,
            ));
        }

        // Regain entries of an interrupt-less CE past the threshold.
        if pipe.attr_flags & CE_ATTR_DIS_INTR != 0 {
            let (w, s, n) = (src.write_index, src.sw_index, src.nentries);
            let num_used = if w >= s { w - s } else { n - s + w };
            if num_used > ATH11K_CE_USAGE_THRESHOLD {
                self.poll_send_completed(pipe_id);
            }
        }

        if self.crash_flush {
            return Err(TransportError::new(
                step::SHUTDOWN,
                pipe_id,
                errno::ESHUTDOWN,
            ));
        }

        let pipe = &self.pipes[pipe_id as usize];
        let src = pipe.src_ring.as_ref().unwrap();
        let write_index = src.write_index;
        let nentries_mask = src.nentries_mask;
        let id = src.hal_ring_id;
        let byte_swap = (pipe.attr_flags & CE_ATTR_BYTE_SWAP_DATA != 0) as u8;
        let buf_sz = pipe.buf_sz as usize;

        self.hal.access_begin(id);
        if self.hal.src_num_free(id, false) < 1 {
            self.hal.access_end(io, id);
            self.pipes[pipe_id as usize].stats.tx_full += 1;
            return Err(TransportError::new(
                step::RING_FULL,
                pipe_id,
                errno::ENOBUFS,
            ));
        }
        let Some(desc) = self.hal.src_get_next_reaped(id) else {
            self.hal.access_end(io, id);
            self.pipes[pipe_id as usize].stats.tx_full += 1;
            return Err(TransportError::new(
                step::RING_FULL,
                pipe_id,
                errno::ENOBUFS,
            ));
        };

        let pipe = &mut self.pipes[pipe_id as usize];
        let tx = pipe.tx_buf.as_mut().unwrap();
        let off = write_index as usize * buf_sz;
        tx.write_bytes(off, data);
        let paddr = tx.paddr() + off as u64;
        pipe.tx_inflight[write_index as usize] = Some(data.len() as u32);
        pipe.tx_transfer_id[write_index as usize] = transfer_id as u32;
        pipe.stats.tx_posted += 1;
        pipe.src_ring.as_mut().unwrap().write_index = ce_ring_idx_incr(nentries_mask, write_index);
        self.hal.ce_src_set_desc(
            id,
            desc,
            paddr,
            data.len() as u32,
            transfer_id as u32,
            byte_swap,
        );
        self.hal.access_end(io, id);

        if ce_need_shadow_fix(pipe_id) {
            let now = (self.clock)();
            self.pipes[pipe_id as usize].hp_timer.start(now);
        }
        Ok(())
    }

    // ── service ───────────────────────────────────────────────────

    /// Linux `ath11k_ce_per_engine_service`: TX completions, then RX.
    /// Returns the completions handled.
    pub fn per_engine_service(&mut self, io: &impl ChipIo, ce_id: u32) -> u32 {
        let Some(attr) = self.host_ce_config.get(ce_id as usize).copied() else {
            return 0;
        };
        let mut n = 0;
        if attr.src_nentries != 0 && self.pipes[ce_id as usize].ring_ids().0.is_some() {
            n += self.tx_process_cb(ce_id);
        }
        if self.pipes[ce_id as usize].recv_cb.is_some()
            && self.pipes[ce_id as usize].ring_ids().2.is_some()
        {
            n += self.recv_process_cb(io, ce_id);
        }
        n
    }

    /// One service pass: the CEs in `pending` (interrupt bitmask), then
    /// a poll of every other interrupt-enabled CE (counted in
    /// [`CeStats::polled_without_irq`] when it finds work), then the
    /// CE4 shadow timer and the RX replenish retry.
    pub fn service(&mut self, io: &impl ChipIo, pending: u32) -> u32 {
        let mut n = 0;
        for ce in 0..self.pipes.len() as u32 {
            if pending & (1 << ce) != 0 {
                self.stats.irqs[ce as usize] += 1;
                n += self.per_engine_service(io, ce);
            }
        }
        for ce in 0..self.pipes.len() as u32 {
            if pending & (1 << ce) != 0
                || self.pipes[ce as usize].attr_flags & CE_ATTR_DIS_INTR != 0
            {
                continue;
            }
            let k = self.per_engine_service(io, ce);
            if k != 0 {
                self.stats.polled_without_irq += 1;
                n += k;
            }
        }
        self.service_timers(io);
        n
    }

    /// Run due timers (CE4 HP refresh, RX replenish retry).
    pub fn service_timers(&mut self, io: &impl ChipIo) {
        let now = (self.clock)();
        for ce in 0..self.pipes.len() {
            if self.pipes[ce].hp_timer.expire(now) {
                let id = self.pipes[ce].hp_timer.ring_id;
                self.hal.shadow_update_hp_tp(io, id);
                self.stats.shadow_refresh += 1;
            }
        }
        if let Some(at) = self.rx_retry_at {
            if now >= at {
                self.rx_retry_at = None;
                self.stats.rx_post_retries += 1;
                self.rx_post_buf(io);
            }
        }
    }

    /// Wait up to `ms` for a CE interrupt, then [`Self::service`].
    pub async fn wait_and_service(&mut self, io: &impl ChipIo, irq: &impl CeIrq, ms: u32) -> u32 {
        irq.wait(ms).await;
        let pending = irq.take_pending();
        self.service(io, pending)
    }

    /// The pollable RX stream of `ce_id`: the next payload, servicing
    /// the CEs in `slice_ms` steps until one arrives or `timeout_ms`
    /// (measured on the CE clock) passes.
    pub async fn recv(
        &mut self,
        io: &impl ChipIo,
        irq: &impl CeIrq,
        ce_id: u32,
        slice_ms: u32,
        timeout_ms: u64,
    ) -> Option<Vec<u8>> {
        let deadline = (self.clock)() + timeout_ms;
        loop {
            if let Some(b) = self.take_rx(ce_id) {
                return Some(b);
            }
            if (self.clock)() >= deadline {
                return None;
            }
            self.wait_and_service(io, irq, slice_ms).await;
        }
    }
}

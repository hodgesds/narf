//! The running device: the data path wired into bring-up, and the
//! runtime that owns the core + DP after it — Linux's `ath11k_dp_*`
//! calls from `core.c`, the DP ext interrupts of `pcic.c`, the NAPI poll
//! (`ath11k_pcic_ext_grp_napi_poll` → `ath11k_dp_service_srng`), the DP /
//! monitor timers, and the WMI / data-path services `mac.c` uses
//! ([`super::mac::WmiPort`], [`super::mac::DataPort`]).
//!
//! | NARF | Linux |
//! |---|---|
//! | [`DpHooks`] `dp_alloc` | `ath11k_dp_alloc` (after `ath11k_ce_init_pipes`) |
//! | `pdev_reo_setup` | `ath11k_dp_pdev_reo_setup` (after service ready) |
//! | `htt_ver_req` | `ath11k_dp_tx_htt_h2t_ver_req_msg` (3 s, major 3) |
//! | `pdev_create` | `ath11k_core_pdev_create` → `ath11k_dp_pdev_alloc` (HTT SRING_SETUP ×7) |
//! | `irq_enable` | `ath11k_hif_irq_enable` → `ath11k_pcic_ext_irq_enable` |
//! | [`install_dp_irq_handlers`] | `ath11k_pcic_ext_irq_config` (one vector per group with rings: `(grp % num_vectors) + base_vector` of the "DP" user) |
//! | [`Rt::service`] | `ath11k_pcic_ce_tasklet` + `ath11k_pcic_ext_grp_napi_poll` + `ath11k_dp_shadow_timer_handler` + `ath11k_dp_service_mon_ring` |
//! | [`Port`] as `WmiPort` | `ath11k_wmi_cmd_send`, the WMI RX dispatcher, `ath11k_mac_mgmt_tx_wmi`, `wmi_process_mgmt_tx_comp` |
//! | [`Port`] as `DataPort` | `ath11k_dp_tx_htt_h2t_ppdu_stats_req`, `ath11k_mac_config_mon_status_default`, `ath11k_dp_vdev_tx_attach`, `ath11k_wait_for_peer_common`, `ath11k_dp_peer_setup` / `_cleanup`, `ath11k_dp_peer_rx_pn_replay_config`, `ieee80211_tx_control_port`, the control-port RX |
//!
//! Ownership (AGENTS.md: no lock across `.await`): [`Shared`] holds the
//! [`Rt`] (core + DP + station data state) in an async [`Mutex`] that
//! every user holds only for a synchronous step; waiting happens on the
//! interrupt source ([`DpIrq::wait`]) with the lock released. Each locked
//! step first services the hardware ([`Rt::service`]: CE → HTC/WMI/HTT
//! routing → DP groups → timers), so whichever task waits drives the
//! device, and nothing depends on another task being scheduled. The few
//! `DataPort` / `WmiPort` calls that are synchronous in Linux
//! (`vdev_tx_attach`, `peer_cleanup`, `set_authorized`, `mgmt_tx_done`,
//! `set_sta_wme`) are queued ([`SyncOp`]) and applied, in order, at the
//! start of the next locked step.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_lib::mutex::{Mutex, MutexGuard};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::diag::{self, WifiStage};

use super::ce::{self, CeIrq, CeMsi, MsiCeIrq};
use super::core::{Ath11kCore, CeHif, CoreHooks, Hif, QmiFw};
use super::dp_ring::{
    enc, DpHwParams, DpRingSizes, DpServiceOutput, Idr, RxMsdu, TxEncap, TxMeta, VifTx,
};
use super::dp_ring::{Dp, ETH_HLEN, ETH_P_PAE};
use super::hal::{DmaMem, TransportError};
use super::htt::{self, HttTarget, HTT_TARGET_VERSION_TIMEOUT_MS};
use super::hw::{MsiConfig, RingMask, ATH11K_EXT_IRQ_GRP_NUM_MAX};
use super::mac::{DataPort, DeviceCaps, WmiPort};
use super::power::ChipIo;
use super::tx_hdr::{self, SeqState, StaTx};
use super::txq::{self, Queued, TxQueues, TxStatus};
use super::wmi::{self, ServiceReady, WmiCmd};

/// Failing-step codes for the integration (250–269).
pub mod step {
    /// No DP parameters for this chip (`DpHwParams::for_rev`; detail =
    /// hw_rev index).
    pub const DP_UNSUPPORTED: u32 = 250;
    /// A DP hook ran without the DP allocated (detail = hook: 1 REO
    /// setup, 2 HTT version, 3 pdev create).
    pub const DP_MISSING: u32 = 251;
    /// HTT VERSION_REQ could not be sent (detail = the core step).
    pub const HTT_VER_SEND: u32 = 252;
    /// An HTT SRING_SETUP could not be sent (detail = message index << 16
    /// | the core step).
    pub const SRING_SETUP_SEND: u32 = 253;
    /// No "DP" MSI user (`ath11k_pcic_get_user_msi_assignment` fails;
    /// detail = vectors granted).
    pub const DP_IRQ_CONFIG: u32 = 254;
    /// The bring-up events the mac layer needs are missing (detail bits:
    /// 1 SERVICE_READY_EXT, 2 READY, 4 no pdev).
    pub const MAC_CAPS: u32 = 255;
    /// The netdev could not join the capability-gated interface registry
    /// (detail: 1 no authority, 2 revoked, 3 duplicate name). Not fatal:
    /// the kernel stack path (`narf_net::iface`) is registered.
    pub const NET_REGISTER: u32 = 256;
    /// Interface down (`ieee80211_do_stop`) could not delete the vdev
    /// (console only, Linux warns; detail = the errno).
    pub const IF_DOWN_VDEV_DELETE: u32 = 257;
}

pub const ETIMEDOUT: i32 = 110;
pub const ENOSPC: i32 = 28;
pub const EIO: i32 = 5;
pub const ENOTCONN: i32 = 107;
pub const ENOENT: i32 = 2;
pub const ENODEV: i32 = 19;

/// `NAPI_POLL_WEIGHT`.
pub const NAPI_BUDGET: u32 = 64;
/// NAPI re-polls of one group in one pass before yielding.
pub const DP_MAX_ROUNDS: u32 = 8;
/// `ATH11K_MON_TIMER_INTERVAL` (ms).
pub const ATH11K_MON_TIMER_INTERVAL: u64 = 10;
/// `DP_MON_SERVICE_BUDGET`.
pub const DP_MON_SERVICE_BUDGET: u32 = 128;
/// `ATH11K_TX_MGMT_NUM_PENDING_MAX`.
pub const ATH11K_TX_MGMT_NUM_PENDING_MAX: u32 = 512;
/// Interval of the runtime loop and the longest a waiter sleeps between
/// services (the DP shadow timers need ≤ 10 ms; Linux's monitor reap
/// timer is 10 ms).
pub const SERVICE_SLICE_MS: u32 = 10;
/// QMI transport service interval after bring-up.
pub const QMI_SERVICE_MS: u64 = 100;
/// Bound on queued EAPOL frames (iwlwifi / mac80211's control port keep
/// a short queue; the supplicant handles one exchange at a time).
pub const EAPOL_QUEUE_MAX: usize = 16;
/// Bound on received data frames waiting for the interface pump.
pub const RX_QUEUE_MAX: usize = 1024;
/// `ATH11K_FLUSH_TIMEOUT` (5 s).
pub const ATH11K_FLUSH_TIMEOUT_MS: u32 = 5000;

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(narf_console::Writer, "  ath11k: {}", args);
}

// ── DP ext interrupts (pcic.c `ath11k_pcic_ext_irq_config`) ────────

/// `ab->hw_params.ring_mask->*[grp]` has a ring: Linux gives the group
/// `num_irq = 1`, else no interrupt.
pub fn group_has_rings(mask: &RingMask, grp: usize) -> bool {
    grp < ATH11K_EXT_IRQ_GRP_NUM_MAX
        && (mask.tx[grp]
            | mask.rx[grp]
            | mask.rx_err[grp]
            | mask.rx_wbm_rel[grp]
            | mask.reo_status[grp]
            | mask.rxdma2host[grp]
            | mask.host2rxdma[grp]
            | mask.rx_mon_status[grp])
            != 0
}

/// `ath11k_pcic_ext_irq_config`: the MSI vector (relative to the
/// device's first vector) ext group `grp` interrupts on —
/// `(i % num_vectors) + base_vector` of the "DP" user — or `None` for a
/// group without rings or without a DP user.
///
/// WCN6855 (`ath11k_msi_config` QCA6390 table: DP = 18 vectors from 14;
/// `ath11k_hw_ring_mask_qca6390`): groups 0–2 and 4–10 → vectors 14–16
/// and 18–24; group 3 has no ring. The ring side programs the matching
/// MSI data (`ath11k_dp_srng_msi_setup`: `group % 18 + 14 + ep_base`).
pub fn dp_irq_vector(mask: &RingMask, config: &MsiConfig, grp: usize) -> Option<u32> {
    if !group_has_rings(mask, grp) {
        return None;
    }
    let (num_vectors, _user_base_data, base_vector) = config.user_assignment("DP", 0)?;
    if num_vectors == 0 {
        return None;
    }
    Some((grp as u32 % num_vectors) + base_vector)
}

/// Handler cookie for device vector `i`: the bitmask of ext groups on it.
pub fn dp_vector_cookie(mask: &RingMask, config: &MsiConfig, i: u32) -> Option<u64> {
    let mut m = 0u64;
    for grp in 0..ATH11K_EXT_IRQ_GRP_NUM_MAX {
        if dp_irq_vector(mask, config, grp) == Some(i) {
            m |= 1 << grp;
        }
    }
    (m != 0).then_some(m)
}

/// Ext groups whose MSI fired and the runtime has not serviced.
static DP_IRQ_PENDING: AtomicU32 = AtomicU32::new(0);
/// `ATH11K_FLAG_EXT_IRQ_ENABLED`.
static DP_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
static DP_IRQS_INSTALLED: AtomicBool = AtomicBool::new(false);
/// DP interrupts delivered (any DP vector).
pub static DP_MSI_FIRES: AtomicU64 = AtomicU64::new(0);

/// `ath11k_pcic_ext_interrupt_handler`: note the groups (cookie) and
/// wake the device owner, whose service pass is the NAPI poll. Ignored
/// while ext interrupts are disabled, as Linux. MSI is edge-triggered,
/// so there is no per-group mask to set (Linux `disable_irq_nosync` →
/// NAPI → `enable_irq`).
fn dp_msi_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    if !DP_IRQ_ENABLED.load(Ordering::Acquire) {
        return narf_interrupts::IrqStatus::Handled;
    }
    DP_MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    DP_IRQ_PENDING.fetch_or(cookie as u32, Ordering::AcqRel);
    ce::wake_waiters();
    narf_interrupts::IrqStatus::Handled
}

/// `true` while DP groups are pending (the CE wait future resolves on it).
pub(crate) fn dp_irq_pending() -> bool {
    DP_IRQ_PENDING.load(Ordering::Acquire) != 0
}

/// Hook the DP vectors (`ath11k_pcic_ext_irq_config`). Idempotent; the
/// handlers stay inert until [`set_dp_irqs_enabled`].
pub fn install_dp_irq_handlers(
    mask: &RingMask,
    config: &'static MsiConfig,
    base_irq: u8,
    n_vectors: u8,
) -> Result<(), TransportError> {
    if config.user_assignment("DP", 0).is_none() {
        return Err(TransportError::new(
            step::DP_IRQ_CONFIG,
            n_vectors as u32,
            ENOENT,
        ));
    }
    if DP_IRQS_INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    for i in 0..n_vectors {
        if let Some(cookie) = dp_vector_cookie(mask, config, i as u32) {
            narf_interrupts::install_handler_named(base_irq + i, "ath11k-dp", cookie, dp_msi_irq);
        }
    }
    Ok(())
}

/// `ath11k_pcic_ext_irq_enable` / `_disable`.
pub fn set_dp_irqs_enabled(on: bool) {
    DP_IRQ_ENABLED.store(on, Ordering::Release);
}

/// Register access the runtime can move between tasks.
pub trait RtIo: ChipIo + Send + 'static {}
impl<T: ChipIo + Send + 'static> RtIo for T {}

/// A QMI session the runtime can move between tasks.
pub trait RtQmi: QmiFw + Send + 'static {}
impl<T: QmiFw + Send + 'static> RtQmi for T {}

/// The device's interrupt + time source after bring-up: the CE side
/// ([`CeIrq`]) plus the DP ext groups. `wait` must resolve on either.
/// Cloned into [`Shared`] so tasks wait without holding the core.
pub trait DpIrq: CeIrq + Clone + Send + Sync + 'static {
    /// Take the bitmask of ext groups that interrupted.
    fn take_dp_pending(&self) -> u32;
}

impl DpIrq for MsiCeIrq {
    fn take_dp_pending(&self) -> u32 {
        DP_IRQ_PENDING.swap(0, Ordering::AcqRel)
    }
}

// ── the DP hooks of `ath11k_core_qmi_firmware_ready` ──────────────

/// [`CoreHooks`] with the real data path.
#[allow(missing_debug_implementations)]
pub struct DpHooks {
    /// `None` = the chip's DP is not ported (fails `dp_alloc`).
    pub cfg: Option<DpHwParams>,
    /// Detail for [`step::DP_UNSUPPORTED`].
    pub hw_rev: u32,
    pub sizes: DpRingSizes,
    pub msi: Option<CeMsi>,
    pub dp: Option<Dp>,
    /// `HTT_TARGET_VERSION_TIMEOUT_HZ`.
    pub htt_version_timeout_ms: u64,
    /// Ext interrupts enabled (`irq_enable` ran).
    pub irqs_enabled: bool,
}

impl DpHooks {
    pub fn new(
        cfg: Option<DpHwParams>,
        hw_rev: u32,
        sizes: DpRingSizes,
        msi: Option<CeMsi>,
    ) -> Self {
        DpHooks {
            cfg,
            hw_rev,
            sizes,
            msi,
            dp: None,
            htt_version_timeout_ms: HTT_TARGET_VERSION_TIMEOUT_MS,
            irqs_enabled: false,
        }
    }
}

fn missing(hook: u32) -> TransportError {
    TransportError::new(step::DP_MISSING, hook, ENODEV)
}

impl<Io: ChipIo, Irq: CeIrq, Q: QmiFw> CoreHooks<CeHif<Io, Irq>, Q> for DpHooks {
    fn dp_alloc(&mut self, core: &mut Ath11kCore<CeHif<Io, Irq>, Q>) -> Result<(), TransportError> {
        let Some(cfg) = self.cfg else {
            return Err(TransportError::new(
                step::DP_UNSUPPORTED,
                self.hw_rev,
                95, // -EOPNOTSUPP
            ));
        };
        let hif = &mut core.hif;
        // Dp::alloc latches + prints its own failures.
        self.dp = Some(Dp::alloc(
            &mut hif.ce.hal,
            &hif.io,
            &cfg,
            self.sizes,
            self.msi,
        )?);
        Ok(())
    }

    fn pdev_reo_setup(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(1))?;
        let hif = &mut core.hif;
        dp.pdev_reo_setup(&mut hif.ce.hal, &hif.io)
    }

    async fn htt_ver_req(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(2))?;
        // ath11k_dp_htt_connect set dp->eid.
        dp.htt.eid = core.htt_ep.map(|e| e.eid);
        // init_completion(&dp->htt_tgt_version_received)
        dp.htt = HttTarget {
            eid: dp.htt.eid,
            ..HttTarget::default()
        };
        core.htt_send(&htt::ver_req_msg())
            .map_err(|e| TransportError::new(step::HTT_VER_SEND, e.step, e.errno))?;
        let deadline = core
            .hif
            .now_ms()
            .saturating_add(self.htt_version_timeout_ms);
        loop {
            // ath11k_dp_htt_htc_t2h_msg_handler for everything queued.
            while let Some(m) = core.take_htt() {
                if dp.htt_t2h_msg_handler(&m).is_err() {
                    dp.stats.htt_unhandled += 1;
                }
            }
            if dp.htt.version_ok()? {
                log(format_args!(
                    "htt: target version {}.{}",
                    dp.htt.ver_major, dp.htt.ver_minor
                ));
                return Ok(());
            }
            let now = core.hif.now_ms();
            if now >= deadline {
                log(format_args!("htt target version request timed out"));
                return Err(HttTarget::timeout_error());
            }
            core.pump((deadline - now).min(super::core::CORE_SLICE_MS) as u32)
                .await;
        }
    }

    async fn pdev_create(
        &mut self,
        core: &mut Ath11kCore<CeHif<Io, Irq>, Q>,
    ) -> Result<(), TransportError> {
        let dp = self.dp.as_mut().ok_or(missing(3))?;
        let hif = &mut core.hif;
        // ath11k_dp_pdev_alloc (pdev 0; latches + prints its failures).
        let msgs = dp.pdev_alloc(&mut hif.ce.hal, &hif.io, 0)?;
        // ath11k_dp_tx_htt_srng_setup per ring, in Linux's order; the
        // first failure ends the pdev alloc.
        for (i, m) in msgs.iter().enumerate() {
            core.htt_send(m).map_err(|e| {
                TransportError::new(
                    step::SRING_SETUP_SEND,
                    (i as u32) << 16 | (e.step & 0xffff),
                    e.errno,
                )
            })?;
        }
        // ath11k_mac_register is the caller's (the mac layer is built on
        // the runtime once the core is ready).
        Ok(())
    }

    fn irq_enable(&mut self, _core: &mut Ath11kCore<CeHif<Io, Irq>, Q>) {
        set_dp_irqs_enabled(true);
        self.irqs_enabled = true;
        diag::set_wifi_stage(WifiStage::DataPath);
    }
}

// ── the runtime ───────────────────────────────────────────────────

/// Station data-path state (the `ath11k_vif` / `ath11k_sta` / mac80211
/// `sta_info` fields the TX and RX paths read).
#[derive(Debug, Default)]
pub struct LinkState {
    /// `vif->addr`.
    pub own: [u8; 6],
    /// `ath11k_dp_vdev_tx_attach` result (+ the BSS peer's AST).
    pub vif: Option<VifTx>,
    /// The AP (BSS peer) once HTT-mapped.
    pub bss: Option<[u8; 6]>,
    /// `WLAN_STA_AUTHORIZED` / `peer->is_authorized`.
    pub authorized: bool,
    /// `sta->sta.wme`.
    pub wme: bool,
    /// A pairwise key is installed.
    pub ptk: bool,
    pub seq: SeqState,
    /// Received EAPOL frames (802.3) for the supplicant.
    pub eapol_rx: VecDeque<Vec<u8>>,
    /// `sta->deflink.status_stats.last_ack_signal` / `last_ack` (ms).
    pub last_ack_signal: Option<i32>,
    pub last_ack_ms: Option<u64>,
    /// Received data frames (Ethernet II) for the interface, with
    /// `ath11k_dp_rx_h_csum_offload`'s verdict (`CHECKSUM_UNNECESSARY`).
    pub data_rx: VecDeque<(Vec<u8>, bool)>,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtStats {
    pub passes: u32,
    pub dp_irqs: [u32; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    /// DP work found on a group whose MSI had not fired.
    pub dp_polled_without_irq: u32,
    pub htt_rx: u32,
    pub htt_bad: u32,
    pub rx_data: u32,
    pub rx_eapol: u32,
    pub rx_dropped_unauth: u32,
    pub rx_dropped_not_ours: u32,
    pub rx_dropped_echo: u32,
    /// EAPOL to neither our address nor the PAE group address
    /// (`ieee80211_frame_allowed`).
    pub rx_dropped_eapol_da: u32,
    pub rx_dropped_short: u32,
    pub rx_queue_full: u32,
    pub tx_data: u32,
    pub tx_eapol: u32,
    pub tx_failed: u32,
    /// Frames dropped from the TX queues (`fq` overlimit, purge).
    pub tx_queue_dropped: u32,
    pub tx_completed: u32,
    /// `ieee80211_tx_status_ext` outcomes of completed MSDUs.
    pub tx_status_acked: u32,
    pub tx_status_noack: u32,
    pub tx_status_dropped: u32,
    pub mgmt_tx: u32,
    pub mgmt_tx_done: u32,
    pub mgmt_tx_unknown: u32,
    pub reo_status: u32,
}

/// `ar->txmgmt_idr` + `num_pending_mgmt_tx`.
#[derive(Debug, Default)]
pub struct MgmtTx {
    pub bufs: Idr<DmaMem>,
    pub pending: u32,
}

/// The core + DP + station state after bring-up (`struct ath11k_base` /
/// `struct ath11k` as the running driver sees them).
#[allow(missing_debug_implementations)]
pub struct Rt<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    pub core: Ath11kCore<CeHif<Io, Irq>, Q>,
    pub dp: Dp,
    pub link: LinkState,
    pub mgmt: MgmtTx,
    /// The station's per-AC TX queues + hardware queue stop reasons.
    pub txq: TxQueues,
    /// `local->ack_status_frames`: ack id → the TX descriptor's MSDU id
    /// once on TCL (WCN6855 has one TCL ring, so the MSDU id names it).
    pub ack_frames: Idr<Option<u32>>,
    /// Statuses waiting for their requester (`ieee80211_report_ack_skb`).
    pub ack_status: VecDeque<(u32, TxStatus)>,
    pub stats: RtStats,
    /// `mon_reap_timer` armed (next expiry).
    pub mon_reap_at: Option<u64>,
    qmi_service_at: u64,
}

/// A synchronous port call, applied at the next locked step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncOp {
    MgmtTxDone(u32),
    VdevTxAttach { vdev_id: u32, addr: [u8; 6] },
    PeerCleanup { vdev_id: u32, addr: [u8; 6] },
    SetAuthorized { addr: [u8; 6], on: bool },
    StaWme { addr: [u8; 6], wme: bool },
}

fn is_multicast(a: &[u8]) -> bool {
    a[0] & 1 != 0
}

/// `pae_group_addr` of `ieee80211_frame_allowed` (IEEE 802.1X PAE group
/// address 01-80-C2-00-00-03).
pub const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Rt<Io, Irq, Q> {
    /// A runtime over a ready core and its DP.
    pub fn new(core: Ath11kCore<CeHif<Io, Irq>, Q>, dp: Dp) -> Self {
        let own = core.mac_addr.unwrap_or_default();
        Rt {
            core,
            dp,
            link: LinkState {
                own,
                ..LinkState::default()
            },
            mgmt: MgmtTx::default(),
            txq: TxQueues::default(),
            ack_frames: Idr::default(),
            ack_status: VecDeque::new(),
            stats: RtStats::default(),
            mon_reap_at: None,
            qmi_service_at: 0,
        }
    }

    pub fn now_ms(&self) -> u64 {
        (self.core.hif.clock)()
    }

    /// The mac layer's view of the device (`ath11k_mac_register` inputs).
    pub fn device_caps(&self) -> Result<DeviceCaps, TransportError> {
        device_caps(&self.core)
    }

    fn apply(&mut self, op: SyncOp) {
        let now = self.now_ms();
        match op {
            SyncOp::MgmtTxDone(id) => {
                // wmi_process_mgmt_tx_comp: idr_find + idr_remove +
                // dma_unmap; num_pending_mgmt_tx--.
                if self.mgmt.bufs.remove(id).is_some() {
                    self.mgmt.pending = self.mgmt.pending.saturating_sub(1);
                    self.stats.mgmt_tx_done += 1;
                } else {
                    self.stats.mgmt_tx_unknown += 1;
                }
            }
            SyncOp::VdevTxAttach { vdev_id, addr } => {
                // ath11k_dp_vdev_tx_attach + ath11k_dp_update_vdev_search
                // (pdev 0; WCN6855 has no HTT peer map v2).
                self.link.vif = Some(VifTx::attach(vdev_id as u8, 0, self.dp.cfg.htt_peer_map_v2));
                self.link.own = addr;
            }
            SyncOp::PeerCleanup { vdev_id, addr } => {
                let hif = &mut self.core.hif;
                if let Err(e) =
                    self.dp
                        .peer_cleanup(&mut hif.ce.hal, &hif.io, vdev_id as u8, &addr, now)
                {
                    // ath11k_dp_peer_cleanup: "failed to lookup peer".
                    log(format_args!(
                        "dp peer cleanup: step {} (-{})",
                        e.step, e.errno
                    ));
                }
            }
            SyncOp::SetAuthorized { addr, on } => {
                if self.link.bss == Some(addr) {
                    self.link.authorized = on;
                }
            }
            SyncOp::StaWme { addr, wme } => {
                if self.link.bss == Some(addr) {
                    self.link.wme = wme;
                }
            }
        }
    }

    /// HTT T2H for the DP (`ath11k_dp_htt_htc_t2h_msg_handler`).
    fn route_htt(&mut self) {
        while let Some(m) = self.core.take_htt() {
            self.stats.htt_rx += 1;
            if self.dp.htt_t2h_msg_handler(&m).is_err() {
                self.stats.htt_bad += 1;
            }
        }
    }

    /// Classify one delivered MSDU (mac80211 RX for a station:
    /// `ieee80211_accept_frame`, `ieee80211_data_to_8023`'s echo check,
    /// `ieee80211_frame_allowed` — EAPOL only to our address or the PAE
    /// group address, whatever its protection; everything else through
    /// `ieee80211_802_1x_port_control` — then
    /// `ieee80211_deliver_skb_to_local_stack`: the control port protocol
    /// goes to the supplicant (`control_port_over_nl80211`), the rest to
    /// the stack). Which EAPOL source the supplicant accepts is its own
    /// rule (wpa_supplicant's `last_eapol_matches_bssid`; `mac.rs`).
    fn rx_msdu(&mut self, m: RxMsdu) {
        let csum_ok = m.csum_ok;
        let f = m.frame;
        if f.len() < ETH_HLEN {
            self.stats.rx_dropped_short += 1;
            return;
        }
        let own = self.link.own;
        let (da, sa) = (&f[0..6], &f[6..12]);
        if is_multicast(da) && sa == own {
            // Our own group frame relayed by the AP.
            self.stats.rx_dropped_echo += 1;
            return;
        }
        if !is_multicast(da) && da != own {
            self.stats.rx_dropped_not_ours += 1;
            return;
        }
        if u16::from_be_bytes([f[12], f[13]]) == ETH_P_PAE {
            if da != own && da != PAE_GROUP_ADDR {
                self.stats.rx_dropped_eapol_da += 1;
                return;
            }
            self.stats.rx_eapol += 1;
            if self.link.eapol_rx.len() >= EAPOL_QUEUE_MAX {
                self.link.eapol_rx.pop_front();
            }
            self.link.eapol_rx.push_back(f);
        } else if self.link.authorized {
            if self.link.data_rx.len() >= RX_QUEUE_MAX {
                self.stats.rx_queue_full += 1;
                return;
            }
            self.stats.rx_data += 1;
            self.link.data_rx.push_back((f, csum_ok));
        } else {
            self.stats.rx_dropped_unauth += 1;
        }
    }

    fn handle_dp_output(&mut self, out: DpServiceOutput, now: u64) {
        for m in out.rx {
            self.rx_msdu(m);
        }
        // Buffers are released inside the completion handler; each MSDU's
        // status goes to ieee80211_tx_status_ext.
        self.stats.tx_completed += out.tx_done.len() as u32;
        for c in &out.tx_done {
            self.tx_status_one(c, now);
        }
        if !out.reo_status.is_empty() {
            self.stats.reo_status += out.reo_status.len() as u32;
            let hif = &mut self.core.hif;
            self.dp
                .reo_status_handler(&mut hif.ce.hal, &hif.io, &out.reo_status, now);
        }
    }

    /// One service pass: the CE tasklet work (+ HTC / WMI / HTT
    /// routing), every DP ext group's NAPI poll (the interrupting ones
    /// first counted, all of them polled — the poll fallback), the DP
    /// shadow timers, the monitor-status reap timer, and the QMI
    /// transport. Synchronous.
    pub fn service(&mut self) {
        self.stats.passes += 1;
        let now = self.now_ms();
        let ce_pending = self.core.hif.irq.take_pending();
        {
            let hif = &mut self.core.hif;
            hif.ce.service(&hif.io, ce_pending);
        }
        self.core.drain_rx();
        self.route_htt();

        let mask = *self.dp.cfg.hw.ring_mask;
        let pending = self.core.hif.irq.take_dp_pending();
        for grp in 0..ATH11K_EXT_IRQ_GRP_NUM_MAX {
            if !group_has_rings(&mask, grp) {
                continue;
            }
            let fired = pending & (1 << grp) != 0;
            if fired {
                self.stats.dp_irqs[grp] += 1;
            }
            for _ in 0..DP_MAX_ROUNDS {
                let out = {
                    let hif = &mut self.core.hif;
                    self.dp
                        .service_srng(&mut hif.ce.hal, &hif.io, grp, NAPI_BUDGET)
                };
                let work = out.work_done as usize + out.tx_done.len() + out.reo_status.len();
                if work != 0 && !fired {
                    self.stats.dp_polled_without_irq += 1;
                }
                // napi_complete_done when under budget; else re-poll.
                let again = out.work_done >= NAPI_BUDGET;
                self.handle_dp_output(out, now);
                if !again {
                    break;
                }
            }
        }
        {
            let hif = &mut self.core.hif;
            self.dp.service_shadow_timers(&mut hif.ce.hal, &hif.io, now);
        }
        // ath11k_dp_service_mon_ring (non-full-monitor: status rings).
        if let Some(at) = self.mon_reap_at {
            if now >= at {
                for j in 0..self.dp.cfg.num_rxdma_per_pdev {
                    let mut budget = DP_MON_SERVICE_BUDGET;
                    let hif = &mut self.core.hif;
                    self.dp
                        .reap_mon_status(&mut hif.ce.hal, &hif.io, j, &mut budget);
                }
                self.mon_reap_at = Some(now + ATH11K_MON_TIMER_INTERVAL);
            }
        }
        if now >= self.qmi_service_at {
            self.core.qmi.service();
            self.qmi_service_at = now + QMI_SERVICE_MS;
        }
    }

    /// Transmit an Ethernet frame on the station vif: mac80211's
    /// Ethernet → 802.11 conversion ([`tx_hdr::build_sta_data`]) then
    /// `ath11k_dp_tx` with NATIVE_WIFI encapsulation. `csum_partial` is
    /// `skb->ip_summed == CHECKSUM_PARTIAL` (the seed is already in the
    /// frame, [`super::tx_offload::csum_partial_prepare`]). Returns the
    /// TX descriptor id.
    pub fn tx_eth(&mut self, eth: &[u8], csum_partial: bool) -> Result<u32, i32> {
        let (Some(vif), Some(bssid)) = (self.link.vif, self.link.bss) else {
            // ieee80211_build_hdr: no chanctx / not associated.
            return Err(ENOTCONN);
        };
        let sta = StaTx {
            own: self.link.own,
            bssid,
            wme: self.link.wme,
            authorized: self.link.authorized,
            protected: self.link.ptk,
        };
        let built = tx_hdr::build_sta_data(eth, &sta, &mut self.link.seq)?;
        let meta = TxMeta {
            encap: TxEncap::NativeWifi,
            priority: built.tid as u32,
            queue: built.ac,
            // hw_ops->get_ring_selector (ath11k_hw_ipq8074_get_tcl_ring_selector:
            // smp_processor_id()); WCN6855 has one TCL data ring
            // (tcl2wbm_rbm_map_ipq5018), so `% num_tx_rings` picks ring 0.
            ring_selector: narf_lib::percpu::current_cpu() as u32,
            // NETIF_F_HW_CSUM (`tx_offload::OFFLOADS`).
            csum_partial,
            pdev_idx: 0,
            lmac_id: 0,
        };
        let now = self.now_ms();
        let hif = &mut self.core.hif;
        match self
            .dp
            .tx(&mut hif.ce.hal, &hif.io, &vif, &meta, &built.frame, now)
        {
            Ok(id) => {
                if eth.len() >= ETH_HLEN && u16::from_be_bytes([eth[12], eth[13]]) == ETH_P_PAE {
                    self.stats.tx_eapol += 1;
                } else {
                    self.stats.tx_data += 1;
                }
                Ok(id)
            }
            Err(e) => {
                self.stats.tx_failed += 1;
                Err(e.errno)
            }
        }
    }

    /// One completion's status (`ath11k_dp_tx_htt_tx_complete_buf` /
    /// `ath11k_dp_tx_complete_msdu`, [`txq::tx_status`]) into mac80211's
    /// `__ieee80211_tx_status`: the station's ack statistics and, for a
    /// frame whose sender asked, `ieee80211_report_ack_skb`.
    fn tx_status_one(&mut self, c: &super::dp_ring::TxCompletion, now: u64) {
        let sta = self
            .dp
            .peer_by_id(c.peer_id)
            .is_some_and(|p| self.link.bss == Some(p.addr));
        let db2dbm = self
            .core
            .svc_map
            .test(super::wmi_ids::WMI_TLV_SERVICE_HW_DB2DBM_CONVERSION_SUPPORT);
        let st = txq::tx_status(c.acked, c.ack_rssi, db2dbm, self.link.vif.is_some(), sta);
        if st.dropped {
            self.stats.tx_status_dropped += 1;
        } else if st.acked {
            self.stats.tx_status_acked += 1;
            self.link.last_ack_ms = Some(now);
            self.link.last_ack_signal = st.ack_signal;
        } else {
            self.stats.tx_status_noack += 1;
        }
        let ack_id = self
            .ack_frames
            .ids()
            .find(|&id| self.ack_frames.find(id) == Some(&Some(c.msdu_id)));
        if let Some(id) = ack_id {
            self.ack_frames.remove(id);
            self.ack_status.push_back((id, st));
        }
    }

    /// `ieee80211_report_used_skb(.., dropped = true)` for a frame whose
    /// sender asked for the status and that never reached TCL.
    fn ack_dropped(&mut self, ack_id: Option<u32>) {
        if let Some(id) = ack_id {
            if self.ack_frames.remove(id).is_some() {
                self.ack_status.push_back((id, TxStatus::DROPPED));
            }
        }
    }

    /// `ieee80211_subif_start_xmit` up to the TXQ: drop when there is no
    /// station to send to (`ieee80211_build_hdr` without a chanctx /
    /// `sta`), else `ieee80211_select_queue` with `sta->sta.wme` and
    /// `ieee80211_queue_skb` into that AC (`fq` overlimit drops counted).
    pub fn tx_enqueue(&mut self, eth: Vec<u8>, csum_partial: bool) -> Result<(), i32> {
        self.tx_enqueue_ack(eth, csum_partial, None)
    }

    fn tx_enqueue_ack(
        &mut self,
        eth: Vec<u8>,
        csum_partial: bool,
        ack_id: Option<u32>,
    ) -> Result<(), i32> {
        if self.link.vif.is_none() || self.link.bss.is_none() {
            self.stats.tx_failed += 1;
            self.ack_dropped(ack_id);
            return Err(ENOTCONN);
        }
        let (_, ac) = tx_hdr::select_queue(&eth, self.link.wme);
        let dropped = self.txq.enqueue(
            ac,
            Queued {
                eth,
                csum_partial,
                ack_id,
            },
        );
        self.stats.tx_queue_dropped += dropped.len() as u32;
        for d in dropped {
            self.ack_dropped(d.ack_id);
        }
        Ok(())
    }

    /// As [`Self::tx_enqueue`] with `IEEE80211_TX_CTL_REQ_TX_STATUS`
    /// (`ieee80211_store_ack_skb`): returns the ack id the status is
    /// reported under ([`Self::ack_status`]).
    pub fn tx_enqueue_status(&mut self, eth: Vec<u8>) -> Result<u32, i32> {
        let id = self
            .ack_frames
            .alloc(None, txq::ACK_ID_START, txq::ACK_ID_END)
            .map_err(|_| ENOSPC)?;
        self.tx_enqueue_ack(eth, false, Some(id))?;
        Ok(id)
    }

    /// `ieee80211_handle_wake_tx_queue`: hand every frame whose hardware
    /// queue is not stopped to `ath11k_mac_op_tx` → `ath11k_dp_tx`, VO
    /// first. A frame the DP refuses (`-ENOSPC` with the TX IDR full,
    /// `-ENOMEM` with the TCL ring full) is freed, as
    /// `ath11k_mac_op_tx` does with `ieee80211_free_txskb`. Returns the
    /// frames the DP accepted.
    pub fn tx_push(&mut self) -> u32 {
        let mut sent = 0;
        while let Some((_, f)) = self.txq.dequeue() {
            match self.tx_eth(&f.eth, f.csum_partial) {
                Ok(desc_id) => {
                    sent += 1;
                    if let Some(id) = f.ack_id {
                        let msdu =
                            super::hal::field_get(super::dp_ring::DP_TX_DESC_ID_MSDU_ID, desc_id);
                        if let Some(slot) = self.ack_frames.find_mut(id) {
                            *slot = Some(msdu);
                        }
                    }
                }
                Err(_) => self.ack_dropped(f.ack_id),
            }
        }
        sent
    }

    /// `ieee80211_stop_queues_by_reason(hw, queues, reason, false)`.
    pub fn stop_queues(&mut self, queues: u32, reason: u32) {
        self.txq.stop(queues, reason);
    }

    /// `ieee80211_wake_queues_by_reason`: clear the reason and drain what
    /// the queues now allow (`_ieee80211_wake_txqs`, AC order).
    pub fn wake_queues(&mut self, queues: u32, reason: u32) -> u32 {
        self.txq.wake(queues, reason);
        self.tx_push()
    }

    /// `ieee80211_purge_sta_txqs` (each purged frame freed:
    /// `ieee80211_free_txskb`).
    pub fn purge_txqs(&mut self) -> u32 {
        let mut n = 0;
        while let Some(f) = self.txq.take_any() {
            self.ack_dropped(f.ack_id);
            n += 1;
        }
        self.stats.tx_queue_dropped += n;
        n
    }

    /// `ath11k_mac_mgmt_tx` + the first half of `ath11k_mac_mgmt_tx_wmi`:
    /// a TX buffer id and DMA copy of `frame`, and the
    /// `WMI_MGMT_TX_SEND_CMDID` to send. The frame first gets the
    /// sequence number mac80211's TX path gives it
    /// ([`tx_hdr::tx_h_sequence`]: the vif counter non-QoS data uses).
    pub fn mgmt_tx_prepare(&mut self, vdev_id: u32, frame: &[u8]) -> Result<(u32, WmiCmd), i32> {
        if self.mgmt.pending >= ATH11K_TX_MGMT_NUM_PENDING_MAX {
            // "mgmt tx queue is full"
            return Err(ENOSPC);
        }
        let mut frame = frame.to_vec();
        tx_hdr::tx_h_sequence(&mut frame, &mut self.link.seq);
        let frame = &frame[..];
        let mut mem = DmaMem::alloc(frame.len().max(4), 4).map_err(|_| EIO)?;
        mem.write_bytes(0, frame);
        let paddr = mem.paddr();
        let id = self
            .mgmt
            .bufs
            .alloc(mem, 0, ATH11K_TX_MGMT_NUM_PENDING_MAX)
            .map_err(|_| ENOSPC)?;
        // ath11k_wmi_mgmt_send: no CFR capture on a station
        // (tx_params_valid 0), chanfreq 0 (not off-channel).
        Ok((id, wmi::mgmt_send_cmd(vdev_id, id, frame, paddr, 0, false)))
    }
}

/// [`DeviceCaps`] from the core's bring-up events.
pub fn device_caps<H: Hif, Q: QmiFw>(
    core: &Ath11kCore<H, Q>,
) -> Result<DeviceCaps, TransportError> {
    let mut missing = 0;
    if core.svc_ext.is_none() {
        missing |= 1;
    }
    if core.ready.is_none() {
        missing |= 2;
    }
    if missing != 0 {
        return Err(TransportError::new(step::MAC_CAPS, missing, ENODEV));
    }
    let sr = ServiceReady {
        caps: Some(core.target_caps),
        fw_build_vers: core.fw_build_vers,
        svc_map: core.svc_map,
        bitmap_seen: true,
    };
    DeviceCaps::from_events(
        &sr,
        core.svc_ext.as_ref().unwrap(),
        core.ready.as_ref().unwrap(),
        &core.svc_map,
    )
    .ok_or(TransportError::new(step::MAC_CAPS, 4, ENODEV))
}

/// The runtime as tasks share it.
#[allow(missing_debug_implementations)]
pub struct Shared<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    pub rt: Mutex<Rt<Io, Irq, Q>>,
    /// The interrupt source, outside the lock (waits never hold it).
    pub irq: Irq,
    pub clock: fn() -> u64,
    /// `get_random_bytes`.
    pub rng: fn(&mut [u8]),
    /// WMI endpoint `max_msg_len`.
    pub max_msg_len: u32,
    /// `WMI_SEND_TIMEOUT_HZ`.
    pub wmi_send_ms: u64,
    pub slice_ms: u32,
    ops: IrqSafeSpinLock<VecDeque<SyncOp>>,
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Shared<Io, Irq, Q> {
    pub fn new(rt: Rt<Io, Irq, Q>, rng: fn(&mut [u8])) -> Arc<Self> {
        let irq = rt.core.hif.irq.clone();
        let clock = rt.core.hif.clock;
        let max_msg_len = rt.core.wmi_ep.map_or(0, |e| e.max_msg_len);
        let wmi_send_ms = rt.core.cfg.wmi_send_ms;
        Arc::new(Shared {
            rt: Mutex::new(rt),
            irq,
            clock,
            rng,
            max_msg_len,
            wmi_send_ms,
            slice_ms: SERVICE_SLICE_MS,
            ops: IrqSafeSpinLock::new(VecDeque::new()),
        })
    }

    pub fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    /// Queue a synchronous port call.
    pub fn push_op(&self, op: SyncOp) {
        self.ops.lock().push_back(op);
    }

    fn take_ops(&self) -> VecDeque<SyncOp> {
        core::mem::take(&mut *self.ops.lock())
    }

    /// Lock the runtime and apply the queued synchronous calls.
    pub async fn lock(&self) -> MutexGuard<'_, Rt<Io, Irq, Q>> {
        let mut g = self.rt.lock().await;
        for op in self.take_ops() {
            g.apply(op);
        }
        g
    }

    /// [`Self::lock`] without waiting (sync callers: the netdev drain hook).
    pub fn try_lock(&self) -> Option<MutexGuard<'_, Rt<Io, Irq, Q>>> {
        let mut g = self.rt.try_lock()?;
        for op in self.take_ops() {
            g.apply(op);
        }
        Some(g)
    }

    /// Service the device until `f` yields or `timeout_ms` passes (0 =
    /// one pass), sleeping on the interrupt source between passes.
    pub async fn wait_until<T: Send>(
        &self,
        timeout_ms: u32,
        mut f: impl FnMut(&mut Rt<Io, Irq, Q>) -> Option<T> + Send,
    ) -> Option<T> {
        let deadline = self.now_ms().saturating_add(timeout_ms as u64);
        loop {
            let r = {
                let mut g = self.lock().await;
                g.service();
                f(&mut g)
            };
            if r.is_some() {
                return r;
            }
            let now = self.now_ms();
            if now >= deadline {
                return None;
            }
            self.irq
                .wait(((deadline - now) as u32).min(self.slice_ms))
                .await;
        }
    }

    /// `ath11k_wmi_cmd_send`: retry while HTC lacks credits (or the CE
    /// ring is full without credit flow) for `WMI_SEND_TIMEOUT_HZ`.
    pub async fn wmi_send(&self, cmd: &WmiCmd) -> Result<(), i32> {
        enum Try {
            Done,
            Retry(i32),
            Fail(i32),
        }
        let deadline = self.now_ms().saturating_add(self.wmi_send_ms);
        loop {
            let t = {
                let mut g = self.lock().await;
                g.service();
                match g.core.wmi_cmd_try_send(cmd) {
                    Ok(()) => Try::Done,
                    Err(e) if g.core.wmi_send_retryable(e) => Try::Retry(e),
                    Err(e) => Try::Fail(e),
                }
            };
            match t {
                Try::Done => return Ok(()),
                Try::Fail(e) => return Err(e),
                Try::Retry(e) => {
                    let now = self.now_ms();
                    if now >= deadline {
                        log(format_args!(
                            "wmi command {:#x} timeout (-{})",
                            cmd.cmd_id, e
                        ));
                        return Err(e);
                    }
                    self.irq
                        .wait(((deadline - now) as u32).min(self.slice_ms))
                        .await;
                }
            }
        }
    }

    /// Send HTT messages in order (no credit flow on HTT); the first
    /// failure is returned.
    async fn htt_send_all(&self, msgs: &[Vec<u8>]) -> Result<(), i32> {
        let mut g = self.lock().await;
        for m in msgs {
            g.core.htt_send(m).map_err(|e| e.errno)?;
        }
        Ok(())
    }

    /// Received data frames waiting for the interface (Ethernet II +
    /// the hardware checksum verdict).
    pub async fn take_rx(&self) -> Vec<(Vec<u8>, bool)> {
        let mut g = self.lock().await;
        g.service();
        g.link.data_rx.drain(..).collect()
    }

    /// Frames from the interface (`(Ethernet, CHECKSUM_PARTIAL)`): queue
    /// each on its AC, push what the hardware queues allow, service.
    /// Returns each frame's enqueue result.
    pub async fn tx_frames(&self, frames: Vec<(Vec<u8>, bool)>) -> Vec<Result<(), i32>> {
        let mut g = self.lock().await;
        let r = frames
            .into_iter()
            .map(|(eth, csum)| g.tx_enqueue(eth, csum))
            .collect();
        g.tx_push();
        g.service();
        r
    }

    /// Send an Ethernet frame asking for its TX status and wait ≤
    /// `timeout_ms` for it (`ieee80211_tx_control_port` with a cookie →
    /// `cfg80211_control_port_tx_status`, the mlme probe's
    /// `ieee80211_sta_tx_notify`). `Err(ETIMEDOUT)` frees the ack id.
    pub async fn send_eth_tx_status(&self, eth: &[u8], timeout_ms: u32) -> Result<TxStatus, i32> {
        let id = {
            let mut g = self.lock().await;
            let id = g.tx_enqueue_status(eth.to_vec())?;
            g.tx_push();
            g.service();
            id
        };
        let r = self
            .wait_until(timeout_ms, |rt| {
                let i = rt.ack_status.iter().position(|(a, _)| *a == id)?;
                rt.ack_status.remove(i).map(|(_, s)| s)
            })
            .await;
        match r {
            Some(s) => Ok(s),
            None => {
                self.lock().await.ack_frames.remove(id);
                Err(ETIMEDOUT)
            }
        }
    }

    /// `ieee80211_flush_queues(local, sdata, drop)` for the station vif:
    /// stop the vif's hardware queues (`QUEUE_STOP_REASON_FLUSH`), purge
    /// the TXQs when `drop`, `drv_flush` (`ath11k_mac_op_flush`: nothing
    /// when `drop`, else `ath11k_mac_flush_tx_complete` — wait ≤ 5 s each
    /// for no pending data and no pending management frame), wake.
    pub async fn flush_queues(&self, drop: bool) {
        let q = TxQueues::vif_queues();
        {
            let mut g = self.lock().await;
            g.stop_queues(q, txq::reason::FLUSH);
            if drop {
                g.purge_txqs();
            }
        }
        if !drop {
            let data = self
                .wait_until(ATH11K_FLUSH_TIMEOUT_MS, |rt| {
                    (rt.dp.pdev.as_ref().map_or(0, |p| p.num_tx_pending) == 0).then_some(())
                })
                .await;
            if data.is_none() {
                log(format_args!("failed to flush transmit queue"));
            }
            let mgmt = self
                .wait_until(ATH11K_FLUSH_TIMEOUT_MS, |rt| {
                    (rt.mgmt.pending == 0).then_some(())
                })
                .await;
            if mgmt.is_none() {
                log(format_args!("failed to flush mgmt transmit queue"));
            }
        }
        let mut g = self.lock().await;
        g.wake_queues(q, txq::reason::FLUSH);
        g.service();
    }
}

/// The ports the mac layer drives (`Mac<Port, Port>`).
#[allow(missing_debug_implementations)]
pub struct Port<Io: RtIo, Irq: DpIrq, Q: RtQmi>(pub Arc<Shared<Io, Irq, Q>>);

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Clone for Port<Io, Irq, Q> {
    fn clone(&self) -> Self {
        Port(self.0.clone())
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> WmiPort for Port<Io, Irq, Q> {
    async fn send(&self, cmd: WmiCmd) -> Result<(), i32> {
        self.0.wmi_send(&cmd).await
    }

    async fn next_event(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        self.0
            .wait_until(timeout_ms, |rt| rt.core.take_event().map(|e| e.frame))
            .await
    }

    async fn mgmt_tx(&self, vdev_id: u32, frame: &[u8]) -> Result<u32, i32> {
        let (id, cmd) = {
            let mut g = self.0.lock().await;
            g.mgmt_tx_prepare(vdev_id, frame)?
        };
        match self.0.wmi_send(&cmd).await {
            Ok(()) => {
                let mut g = self.0.lock().await;
                g.mgmt.pending += 1;
                g.stats.mgmt_tx += 1;
                Ok(id)
            }
            Err(e) => {
                // err_unmap_buf / err_free_idr.
                let mut g = self.0.lock().await;
                g.mgmt.bufs.remove(id);
                Err(e)
            }
        }
    }

    fn mgmt_tx_done(&self, desc_id: u32) {
        self.0.push_op(SyncOp::MgmtTxDone(desc_id));
    }

    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    fn max_msg_len(&self) -> u32 {
        self.0.max_msg_len
    }

    fn random_bytes(&self, out: &mut [u8]) {
        (self.0.rng)(out)
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> DataPort for Port<Io, Irq, Q> {
    async fn ppdu_stats_req(&self) -> Result<(), i32> {
        // ath11k_dp_tx_htt_h2t_ppdu_stats_req(ar, HTT_PPDU_STATS_TAG_DEFAULT)
        let msgs: Vec<Vec<u8>> = {
            let g = self.0.lock().await;
            htt::ppdu_stats_cfg_msgs(
                0,
                g.dp.cfg.num_rxdma_per_pdev,
                htt::HTT_PPDU_STATS_TAG_DEFAULT,
            )
            .iter()
            .map(|m| m.to_vec())
            .collect()
        };
        self.0.htt_send_all(&msgs).await
    }

    async fn mon_status_default(&self, enable: bool) -> Result<(), i32> {
        let mut g = self.0.lock().await;
        let msgs = {
            let rt = &mut *g;
            rt.dp
                .mon_status_default_msgs(&rt.core.hif.ce.hal, enable)
                .map_err(|e| e.errno)?
        };
        // Linux keeps going and returns the last ring's result.
        let mut ret = Ok(());
        for m in &msgs {
            ret = g.core.htt_send(m).map_err(|e| e.errno);
        }
        if enable && !g.dp.cfg.rxdma1_enable {
            // mod_timer(&ab->mon_reap_timer, …) (deleted only by
            // ath11k_mac_op_stop / ath11k_dp_free).
            let now = g.now_ms();
            g.mon_reap_at = Some(now + ATH11K_MON_TIMER_INTERVAL);
        }
        ret
    }

    fn vdev_tx_attach(&self, vdev_id: u32, addr: [u8; 6]) {
        self.0.push_op(SyncOp::VdevTxAttach { vdev_id, addr });
    }

    async fn wait_peer_mapped(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        mapped: bool,
        timeout_ms: u32,
    ) -> Result<(), i32> {
        self.0
            .wait_until(timeout_ms, |rt| {
                let peer = rt
                    .dp
                    .peers
                    .iter()
                    .find(|p| p.vdev_id as u32 == vdev_id && p.addr == addr)
                    .copied();
                match (peer, mapped) {
                    (Some(p), true) => {
                        // ath11k_peer_create (STA vif): arvif->ast_hash /
                        // ast_idx from the BSS peer.
                        if let Some(v) = rt.link.vif.as_mut() {
                            v.ast_hash = p.ast_hash;
                            v.ast_idx = p.hw_peer_id;
                        }
                        rt.link.bss = Some(addr);
                        Some(())
                    }
                    (None, false) => {
                        if rt.link.bss == Some(addr) {
                            rt.link.bss = None;
                            rt.link.authorized = false;
                            rt.link.ptk = false;
                            rt.link.wme = false;
                            rt.link.seq.sta_destroyed();
                        }
                        Some(())
                    }
                    _ => None,
                }
            })
            .await
            .ok_or(ETIMEDOUT)
    }

    async fn peer_setup(&self, vdev_id: u32, addr: [u8; 6]) -> Result<(), i32> {
        // ath11k_dp_peer_setup(ar, vdev_id, addr): reo_dest = mac_id + 1.
        let (mut op, cmd) = {
            let g = self.0.lock().await;
            g.dp.peer_setup_begin(vdev_id as u8, addr, 0)
        };
        // WMI_PEER_SET_DEFAULT_ROUTING: "failed to set default routing".
        self.0.wmi_send(&cmd).await?;
        loop {
            let next = {
                let mut g = self.0.lock().await;
                let now = g.now_ms();
                let rt = &mut *g;
                let hif = &mut rt.core.hif;
                rt.dp
                    .peer_setup_next(&mut hif.ce.hal, &hif.io, &mut op, now)
            };
            match next {
                Ok(Some(cmd)) => {
                    if let Err(e) = self.0.wmi_send(&cmd).await {
                        let mut g = self.0.lock().await;
                        let now = g.now_ms();
                        let rt = &mut *g;
                        let hif = &mut rt.core.hif;
                        let te = rt
                            .dp
                            .peer_setup_wmi_failed(&mut hif.ce.hal, &hif.io, &op, e, now);
                        return Err(te.errno);
                    }
                }
                Ok(None) => return Ok(()),
                Err(te) => return Err(te.errno),
            }
        }
    }

    fn peer_cleanup(&self, vdev_id: u32, addr: [u8; 6]) {
        self.0.push_op(SyncOp::PeerCleanup { vdev_id, addr });
    }

    async fn rx_pn_replay_config(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        cipher: u32,
        pairwise: bool,
        install: bool,
    ) -> Result<(), i32> {
        let mut g = self.0.lock().await;
        let now = g.now_ms();
        let rsn = matches!(
            cipher,
            wmi::cipher::AES_CCM | wmi::cipher::TKIP | wmi::cipher::AES_GCM
        );
        let r = {
            let rt = &mut *g;
            let hif = &mut rt.core.hif;
            rt.dp.pn_replay_config(
                &mut hif.ce.hal,
                &hif.io,
                vdev_id as u8,
                &addr,
                rsn,
                pairwise,
                install,
                now,
            )
        };
        r.map_err(|e| e.errno)?;
        // ath11k_mac_op_set_key: peer->sec_type / sec_type_grp
        // (ath11k_dp_tx_get_encrypt_type), and mac80211's PTK slot that
        // makes data Protected.
        let sec = match cipher {
            wmi::cipher::AES_CCM => enc::CCMP_128,
            wmi::cipher::TKIP => enc::TKIP_MIC,
            wmi::cipher::AES_GCM => enc::GCMP_128,
            _ => enc::OPEN,
        };
        if let Some(p) =
            g.dp.peers
                .iter()
                .find(|p| p.vdev_id as u32 == vdev_id && p.addr == addr)
                .copied()
        {
            if install {
                let (u, m) = if pairwise {
                    (sec, p.sec_type_grp)
                } else {
                    (p.sec_type, sec)
                };
                g.dp.set_peer_sec_type(p.peer_id, u, m);
            }
        }
        if pairwise && g.link.bss == Some(addr) {
            g.link.ptk = install;
        }
        Ok(())
    }

    async fn send_eth(&self, frame: &[u8]) -> Result<(), i32> {
        // ieee80211_tx_control_port → the TXQ like any data frame.
        self.0
            .tx_frames(alloc::vec![(frame.to_vec(), false)])
            .await
            .pop()
            .unwrap_or(Err(EIO))
    }

    async fn recv_eapol(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        self.0
            .wait_until(timeout_ms, |rt| rt.link.eapol_rx.pop_front())
            .await
    }

    fn set_authorized(&self, addr: [u8; 6], authorized: bool) {
        self.0.push_op(SyncOp::SetAuthorized {
            addr,
            on: authorized,
        });
    }

    fn set_sta_wme(&self, addr: [u8; 6], wme: bool) {
        self.0.push_op(SyncOp::StaWme { addr, wme });
    }
}

// ── PCI: from a ready core to `wlan%d` ────────────────────────────

/// The hardware runtime.
pub type PciShared = Shared<super::core::Bar0, MsiCeIrq, super::pci::Wlfw>;

/// A runtime whose mac layer failed to come up (kept: the firmware owns
/// memory and rings it was given).
static STRANDED_RT: IrqSafeSpinLock<Option<Arc<PciShared>>> = IrqSafeSpinLock::new(None);

/// After `ath11k_core_qmi_firmware_ready`: `ath11k_mac_register` (the
/// mac layer from the bring-up events), then the netdev and its tasks.
/// The hardware starts when the interface goes up (`ieee80211_do_open`
/// → `ath11k_mac_op_start` + `ath11k_mac_op_add_interface`, in
/// [`super::iface`]). Failures are latched by the layer that failed;
/// nothing here panics or blocks the caller (it runs in the
/// probe-spawned MHI task).
pub async fn start_pci(core: super::core::PciCore, dp: Dp) {
    let rt = Rt::new(core, dp);
    let caps = match rt.device_caps() {
        Ok(c) => c,
        Err(e) => {
            e.report("ath11k mac register");
            *STRANDED_RT.lock() = Some(Shared::new(rt, narf_crypto::fill_random_bytes));
            return;
        }
    };
    let initial_reg = rt.core.reg_info.clone();
    let shared = Shared::new(rt, narf_crypto::fill_random_bytes);
    let mac = super::mac::Mac::new(
        Port(shared.clone()),
        Port(shared.clone()),
        caps.clone(),
        super::mac::MacConfig::wcn6855(),
        initial_reg.as_deref(),
    );
    let m = caps.mac_addr;
    let name = super::iface::register_pci(shared, mac, m);
    log(format_args!(
        "{}: registered, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (data path up; starts on IFF_UP)",
        name, m[0], m[1], m[2], m[3], m[4], m[5]
    ));
}

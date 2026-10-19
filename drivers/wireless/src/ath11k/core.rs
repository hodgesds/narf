//! Core bring-up after FW_READY: QMI firmware start, Copy Engines, HTC
//! and WMI to WMI READY — Linux `core.c::ath11k_core_qmi_firmware_ready`
//! and `ath11k_core_start`.
//!
//! Linux order (`drivers/net/wireless/ath/ath11k/core.c`), reproduced
//! step for step by [`Ath11kCore::qmi_firmware_ready`]:
//!
//! 1. `ath11k_core_start_firmware`: `ath11k_ce_get_shadow_config`, then
//!    `ath11k_qmi_firmware_start` (wlan_ini → wlan_cfg with the shadow
//!    list → wlan_mode NORMAL).
//! 2. `ath11k_ce_init_pipes`.
//! 3. `ath11k_dp_alloc` — [`CoreHooks::dp_alloc`] (DP phase).
//! 4. `ath11k_core_start`:
//!    `ath11k_wmi_attach` (preferred hw mode SINGLE on WCN6855) →
//!    `ath11k_htc_init` → `ath11k_hif_start` (`ath11k_pci_start`: ASPM
//!    restore, `ath11k_pcic_start`: CE IRQs on + RX buffers posted) →
//!    `ath11k_htc_wait_target` (1 s, poll every CE, 1 s more) →
//!    `ath11k_dp_htt_connect` (HTT_DATA_MSG) → `ath11k_wmi_connect`
//!    (WMI_CONTROL × `wmi_ep_count`) → `ath11k_htc_start`
//!    (SETUP_COMPLETE_EX) → `ath11k_wmi_wait_for_service_ready` (5 s;
//!    completed by SERVICE_READY_EXT, or EXT2 when the firmware
//!    advertises `WMI_TLV_SERVICE_EXT2_MSG`) → (`ath11k_mac_allocate`:
//!    mac80211, not ported — the caps it reads are kept here) →
//!    `ath11k_dp_pdev_reo_setup` ([`CoreHooks::pdev_reo_setup`]) →
//!    `ath11k_wmi_cmd_init` (WMI INIT) →
//!    `ath11k_wmi_wait_for_unified_ready` (5 s; WMI READY → MAC) →
//!    `ath11k_wmi_set_hw_mode(DBS)` (`single_pdev_only &&
//!    num_rxdma_per_pdev > 1`, i.e. WCN6855) →
//!    `ath11k_dp_tx_htt_h2t_ver_req_msg` ([`CoreHooks::htt_ver_req`]).
//! 5. `ath11k_core_pdev_create` ([`CoreHooks::pdev_create`]: DP pdev +
//!    mac registration) → `ath11k_hif_irq_enable`
//!    ([`CoreHooks::irq_enable`]: DP ext interrupts).
//!
//! Failures unwind like Linux: anything after the firmware started
//! stops the HIF (once started) and sends QMI `wlan_mode OFF`
//! (`ath11k_qmi_firmware_stop`).
//!
//! Transport is behind [`Hif`] (CE send / RX / service; [`CeHif`] is
//! the real one) and the QMI session behind [`QmiFw`] (implemented by
//! [`wlfw::Wlfw`]), so `core_tests.rs` drives the whole sequence with a
//! scripted firmware.
//!
//! WMI events are processed as they arrive, like
//! `ath11k_wmi_tlv_op_rx`: SERVICE_READY / AVAILABLE / EXT / EXT2 /
//! READY / REG_CHAN_LIST update [`Ath11kCore`]; every other event (and
//! REG_CHAN_LIST too) is queued for [`Ath11kCore::wait_event`] /
//! [`Ath11kCore::next_event`]. HTT target→host messages are queued for
//! the DP layer ([`Ath11kCore::take_htt`]).

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::diag::{self, WifiStage};

use super::ce::{self, Ce, CeIrq, CeMsi, CeRecv, MsiCeIrq};
use super::hal::TransportError;
use super::htc::{
    self, svc_id, Htc, HtcConfig, HtcConnected, HtcError, HtcReady, HtcRxKind, HtcTx,
};
use super::hw::{HwParams, HwRev};
use super::mhi_host::MhiNotify;
use super::power::ChipIo;
use super::qmi_wlfw::{ATH11K_FIRMWARE_MODE_NORMAL, ATH11K_FIRMWARE_MODE_OFF};
use super::wlfw::{self, CoherentMem, WlfwError};
use super::wmi::{
    self, hw_mode, DmaRingCap, InitCmdParam, Ready, RegInfo, ServiceMap, ServiceReadyExt,
    TargetCaps, TargetResourceConfig, WmiCmd, WmiError,
};

/// Failing-step codes (`diag::latch_wifi_error`). 120–139; the detail
/// word is documented per step.
pub mod step {
    /// No core configuration for this chip (detail = hw_rev index).
    pub const UNSUPPORTED: u32 = 120;
    /// No probed device / MSI state to start the core on.
    pub const NO_DEVICE: u32 = 121;
    /// `ath11k_htc_init` failed (detail = HTC error code).
    pub const HTC_INIT: u32 = 122;
    /// No HTC READY within 1 s + poll + 1 s (`-ETIMEDOUT`).
    pub const HTC_READY_TIMEOUT: u32 = 123;
    /// HTC READY malformed / zero credits (`-ECOMM`).
    pub const HTC_BAD_READY: u32 = 124;
    /// HTT_DATA_MSG connect failed (detail = HTC error code).
    pub const HTT_CONNECT: u32 = 125;
    /// No CONNECT_SERVICE_RESP for HTT within 1 s.
    pub const HTT_CONNECT_TIMEOUT: u32 = 126;
    /// WMI_CONTROL connect failed (detail = HTC error code).
    pub const WMI_CONNECT: u32 = 127;
    /// No CONNECT_SERVICE_RESP for WMI within 1 s.
    pub const WMI_CONNECT_TIMEOUT: u32 = 128;
    /// SETUP_COMPLETE_EX could not be sent.
    pub const HTC_START: u32 = 129;
    /// Service ready not completed within 5 s (detail = `seen::*` bits).
    pub const SERVICE_READY_TIMEOUT: u32 = 130;
    /// A service-ready event failed to decode (detail = event id << 16
    /// | errno).
    pub const SERVICE_READY_DECODE: u32 = 131;
    /// WMI INIT could not be built.
    pub const WMI_INIT: u32 = 132;
    /// A WMI command waited 3 s for TX credits (`-EAGAIN`; detail =
    /// command id).
    pub const WMI_SEND_CREDITS: u32 = 133;
    /// A WMI command was refused by HTC / the CE (detail = command id).
    pub const WMI_SEND: u32 = 134;
    /// No WMI READY within 5 s of INIT (detail = `seen::*` bits).
    pub const READY_TIMEOUT: u32 = 135;
    /// WMI READY failed to decode (detail = errno).
    pub const READY_DECODE: u32 = 136;
    /// WMI command with no connected WMI endpoint.
    pub const NO_WMI_EP: u32 = 137;
    /// [`super::Ath11kCore::wait_event`] timed out (API only, never
    /// latched by the core; detail = event id).
    pub const EVENT_TIMEOUT: u32 = 138;
    /// HTT send with no connected HTT endpoint, or refused.
    pub const HTT_SEND: u32 = 139;
}

/// Which bring-up events have been processed (`SERVICE_READY_TIMEOUT` /
/// `READY_TIMEOUT` detail).
pub mod seen {
    pub const SERVICE_READY: u32 = 1 << 0;
    pub const SERVICE_AVAILABLE: u32 = 1 << 1;
    pub const SERVICE_READY_EXT: u32 = 1 << 2;
    pub const SERVICE_READY_EXT2: u32 = 1 << 3;
    /// `WMI_TLV_SERVICE_EXT2_MSG` advertised (EXT2 awaited).
    pub const EXT2_EXPECTED: u32 = 1 << 4;
    pub const READY: u32 = 1 << 5;
    pub const REG_CHAN_LIST: u32 = 1 << 6;
}

const ETIMEDOUT: i32 = 110;
const EAGAIN: i32 = 11;
const ENOBUFS: i32 = 105;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;
const ENODEV: i32 = 19;

/// Service slice for every wait (the CE wait returns early on an IRQ).
pub const CORE_SLICE_MS: u64 = 25;
/// Bound on queued unsolicited WMI events / HTT messages.
pub const EVENT_QUEUE_MAX: usize = 512;

// ── transport / QMI seams ─────────────────────────────────────────

/// The host interface the core runs on (Linux `ath11k_hif_ops` + the CE
/// calls HTC makes).
pub trait Hif {
    /// `ath11k_ce_get_shadow_config`: the QMI `WLAN_CFG` shadow list.
    fn shadow_reg_v2(&self) -> Vec<u32>;
    /// `ath11k_ce_init_pipes`.
    fn init_pipes(&mut self) -> Result<(), TransportError>;
    /// `ath11k_hif_start` (PCI: ASPM restore, CE IRQs on, RX posted).
    fn start(&mut self);
    /// `ath11k_hif_stop`.
    fn stop(&mut self);
    /// `ath11k_ce_send(skb, pipe, transfer_id)`.
    fn send(&mut self, pipe: u8, frame: &[u8], transfer_id: u16) -> Result<(), TransportError>;
    /// Next received buffer `(pipe, bytes)`.
    fn take_rx(&mut self) -> Option<(u32, Vec<u8>)>;
    /// The pipe's `recv_cb`.
    fn recv_kind(&self, pipe: u32) -> Option<CeRecv>;
    /// `ath11k_ce_per_engine_service` on every CE
    /// (`ath11k_htc_wait_target`'s fallback).
    fn poll_all(&mut self);
    /// Wait up to `ms` for a CE interrupt, then service the CEs.
    fn wait(&mut self, ms: u32) -> impl Future<Output = ()>;
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
}

/// What the firmware transport reported after bring-up
/// ([`QmiFw::service`]), in Linux's terms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwNotice {
    /// `ath11k_mhi_op_status_cb` queued `reset_work` (MHI_CB_EE_RDDM, or
    /// MHI_CB_SYS_ERROR, spec §8): `ath11k_core_reset`.
    Reset(MhiNotify),
    /// `ATH11K_QMI_EVENT_SERVER_EXIT`: CRASH_FLUSH + RECOVERY and
    /// `ath11k_core_pre_reconfigure_recovery`; the firmware announces
    /// itself again and the handshake reruns.
    ServerExit,
    /// FW_INIT_DONE (or FW_READY) with `ATH11K_FLAG_REGISTERED` set:
    /// `queue_work(restart_work)`.
    Restart,
}

/// A completed firmware crash dump made available to the driver diagnostic
/// surface. This is NARF's ownership-safe analogue of Linux's
/// `dev_coredumpv`: MHI RDDM, FBC paging and dump-eligible QMI target memory
/// are copied before recovery can recycle their DMA owners, then held until a
/// diagnostic consumer takes the dump from [`super::runtime::Shared`].
#[derive(Debug)]
pub struct FirmwareCrashDump {
    /// Monotonic capture time supplied by the transport.
    pub captured_at_ms: u64,
    /// PCI device id (`ath11k_dump_file_data::chip_id`).
    pub chip_id: u32,
    /// Remote WLFW service instance (`ath11k_dump_file_data::qrtr_id`).
    pub qrtr_instance: u32,
    /// Contiguous BHIe firmware image: Linux's `FW_CRASH_DUMP_PAGING_DATA`.
    pub paging: Vec<u8>,
    /// Contiguous ath11k BHIe RDDM payload: `FW_CRASH_DUMP_RDDM_DATA`.
    pub rddm: Vec<u8>,
    /// QMI host-DDR target memory: `FW_CRASH_DUMP_REMOTE_MEM_DATA`.
    pub remote_mem: Vec<u8>,
    /// QMI pageable target memory: `FW_CRASH_DUMP_PAGEABLE_DATA`.
    pub pageable: Vec<u8>,
    /// QMI M3 dump target memory: `FW_CRASH_DUMP_M3_DUMP`.
    pub m3: Vec<u8>,
}

impl FirmwareCrashDump {
    /// Serialize the compatible `ATH11K-FW-DUMP` v2 header plus its TLVs.
    /// NARF has a monotonic capture clock rather than Linux's real-time
    /// `timespec64` and no PCI-domain concept, so those header fields are
    /// zero. The payload types, ordering and little-endian layout match
    /// Linux's `ath11k_pci_coredump_download`.
    pub fn into_linux_v2(self) -> Vec<u8> {
        const HEADER_LEN: usize = 196;
        const VERSION: u32 = 2;
        const PAGING: u32 = 0;
        const RDDM: u32 = 1;
        const REMOTE: u32 = 2;
        const PAGEABLE: u32 = 3;
        const M3: u32 = 4;
        let sections = [
            (PAGING, self.paging),
            (RDDM, self.rddm),
            (REMOTE, self.remote_mem),
            (PAGEABLE, self.pageable),
            (M3, self.m3),
        ];
        let align4 = |len: usize| (len + 3) & !3;
        let data_len = sections
            .iter()
            .filter(|(_, bytes)| !bytes.is_empty())
            .map(|(_, bytes)| 8 + align4(bytes.len()))
            .sum::<usize>();
        let total = HEADER_LEN.saturating_add(data_len);
        let mut out = Vec::with_capacity(total);
        out.resize(HEADER_LEN, 0);
        out[..14].copy_from_slice(b"ATH11K-FW-DUMP");
        out[16..20].copy_from_slice(&(total as u32).to_le_bytes());
        out[20..24].copy_from_slice(&VERSION.to_le_bytes());
        out[24..28].copy_from_slice(&self.chip_id.to_le_bytes());
        out[28..32].copy_from_slice(&self.qrtr_instance.to_le_bytes());
        for (kind, bytes) in sections {
            if bytes.is_empty() {
                continue;
            }
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
            let padded = align4(out.len() - HEADER_LEN);
            out.resize(HEADER_LEN + padded, 0);
        }
        out
    }
}

/// The QMI half of firmware start/stop.
pub trait QmiFw {
    /// `ath11k_qmi_firmware_start(ab, mode)`.
    fn firmware_start(
        &mut self,
        mode: u32,
        shadow_reg_v2: &[u32],
    ) -> impl Future<Output = Result<(), WlfwError>>;
    /// `ath11k_qmi_firmware_stop`: `wlan_mode OFF`, errors only logged.
    fn firmware_stop(&mut self) -> impl Future<Output = ()>;
    /// Service the transport after bring-up (Linux keeps the MHI
    /// controller's interrupts, the QMI handle and its QRTR socket alive):
    /// MHI state changes / SYS_ERR / RDDM, QMI indications. Returns a
    /// crash or restart the runtime must act on. Sync and cheap; the
    /// default reports nothing.
    fn service(&mut self) -> Option<FwNotice> {
        None
    }
    /// The transport has an interrupt waiting (service it now rather than
    /// at the next periodic pass).
    fn irq_pending(&self) -> bool {
        false
    }
    /// Preserve a transport-owned firmware crash dump, if one exists, before
    /// the radio reset destroys the source buffers. The default transport has
    /// no such dump and is deliberately a no-op.
    fn collect_crash_dump(&mut self) -> impl Future<Output = ()> {
        async {}
    }
    /// Transfer a completed transport dump to the physical-radio diagnostic
    /// owner. The default transport owns no such dump.
    fn take_crash_dump(&mut self) -> Option<FirmwareCrashDump> {
        None
    }
    /// The firmware half of a recovery, up to the point Linux queues
    /// `restart_work`: with `power_cycle` (`ath11k_core_reset`)
    /// `ath11k_hif_power_down` + `ath11k_hif_power_up` first; then the QMI
    /// event work until FW_INIT_DONE / FW_READY. The default cannot
    /// recover.
    fn recover(&mut self, _power_cycle: bool) -> impl Future<Output = Result<(), WlfwError>> {
        async { Err(WlfwError::new(wlfw::step::UNSUPPORTED, 1, EOPNOTSUPP)) }
    }
}

impl<P, F, A> QmiFw for wlfw::Wlfw<P, F, A>
where
    P: super::qmi_client::QrtrPipe,
    F: wlfw::FirmwareLoader,
    A: wlfw::DmaAllocator,
{
    async fn firmware_start(&mut self, mode: u32, shadow_reg_v2: &[u32]) -> Result<(), WlfwError> {
        wlfw::Wlfw::firmware_start(self, mode, shadow_reg_v2).await
    }
    async fn firmware_stop(&mut self) {
        if let Err(e) = self
            .mode_send(ATH11K_FIRMWARE_MODE_OFF, wlfw::step::WLAN_MODE)
            .await
        {
            log(format_args!(
                "qmi failed to send wlan mode off: step {} (-{})",
                e.step, e.errno
            ));
        }
    }
    fn service(&mut self) -> Option<FwNotice> {
        // The MHI interrupt work (mhi_intvec_threaded_handler, the event
        // ring tasklets: M0 / M1 / M3, SYS_ERR, RDDM), then the QRTR link
        // so the IPCR DL buffers are recycled.
        self.client.pipe.service();
        self.client.pump();
        // ath11k_mhi_op_status_cb → queue_work(reset_work).
        if let Some(cb) = self.client.pipe.take_reset_request() {
            return Some(FwNotice::Reset(cb));
        }
        // Late indications (`ath11k_qmi_msg_handlers`, then
        // `ath11k_qmi_driver_event_work` on a registered device).
        self.late_event().map(|e| match e {
            wlfw::LateEvent::ServerExit => FwNotice::ServerExit,
            wlfw::LateEvent::Restart => FwNotice::Restart,
        })
    }
    fn irq_pending(&self) -> bool {
        self.client.pipe.irqs_pending()
    }
    async fn collect_crash_dump(&mut self) {
        if let Err(e) = self.client.pipe.collect_crash_dump().await {
            log(format_args!(
                "mhi RDDM collection failed: step {} detail {:#x} (-{})",
                e.step, e.detail, e.errno
            ));
        }
    }
    fn take_crash_dump(&mut self) -> Option<FirmwareCrashDump> {
        let snapshot = self.client.pipe.take_rddm_snapshot()?;
        let mut remote_mem = Vec::new();
        let mut pageable = Vec::new();
        let mut m3 = Vec::new();
        for chunk in self.target_mem.iter().take(self.mem_seg_count) {
            let Some(mem) = chunk.mem.as_ref() else {
                continue;
            };
            let bytes = &mem.bytes()[..(chunk.size as usize).min(mem.bytes().len())];
            match chunk.mem_type {
                // `ath11k_coredump_get_dump_type`.
                super::qmi_wlfw::QMI_WLANFW_MEM_TYPE_DDR_V01 => remote_mem.extend_from_slice(bytes),
                // `M3_DUMP_REGION_TYPE` / `QMI_WLANFW_MEM_M3_V01`.
                super::qmi_wlfw::QMI_WLANFW_MEM_M3_V01 => m3.extend_from_slice(bytes),
                super::qmi_wlfw::QMI_WLANFW_MEM_PAGEABLE_V01 => pageable.extend_from_slice(bytes),
                // BDF / CALDB (and unknown types) never enter Linux's dump.
                _ => {}
            }
        }
        Some(FirmwareCrashDump {
            captured_at_ms: snapshot.captured_at_ms,
            chip_id: self.cfg.board.device as u32,
            qrtr_instance: self
                .client
                .server()
                .map_or(0, |server| server.qmi_instance()),
            paging: self.client.pipe.firmware_paging_snapshot(),
            rddm: snapshot.bytes,
            remote_mem,
            pageable,
            m3,
        })
    }
    async fn recover(&mut self, power_cycle: bool) -> Result<(), WlfwError> {
        if power_cycle {
            self.client
                .pipe
                .power_cycle()
                .await
                .map_err(|e| WlfwError::new(e.step, e.detail, e.errno))?;
            // qcom_mhi_qrtr_remove + qcom_mhi_qrtr_probe.
            self.endpoint_reset();
        }
        self.run_to_fw_restart().await
    }
}

/// The DP phase's insertion points in Linux's order. Every default is a
/// no-op, which is what runs until the DP ring runtime lands.
pub trait CoreHooks<H: Hif, Q: QmiFw> {
    /// `ath11k_dp_alloc` — after `ath11k_ce_init_pipes`, before
    /// `ath11k_core_start`.
    fn dp_alloc(&mut self, _core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        Ok(())
    }
    /// `ath11k_dp_pdev_pre_alloc` + `ath11k_dp_pdev_reo_setup` — after
    /// service ready, before WMI INIT.
    fn pdev_reo_setup(&mut self, _core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        Ok(())
    }
    /// `ath11k_dp_tx_htt_h2t_ver_req_msg` — the last step of
    /// `ath11k_core_start` (send with [`Ath11kCore::htt_send`], await
    /// the reply with [`Ath11kCore::wait_htt`]).
    fn htt_ver_req(
        &mut self,
        _core: &mut Ath11kCore<H, Q>,
    ) -> impl Future<Output = Result<(), TransportError>> {
        async { Ok(()) }
    }
    /// `ath11k_core_pdev_create` (DP pdev alloc; mac registration).
    fn pdev_create(
        &mut self,
        _core: &mut Ath11kCore<H, Q>,
    ) -> impl Future<Output = Result<(), TransportError>> {
        async { Ok(()) }
    }
    /// `ath11k_hif_irq_enable` (DP ext interrupt groups).
    fn irq_enable(&mut self, _core: &mut Ath11kCore<H, Q>) {}
}

/// No DP yet: every hook is the default no-op.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoDp;

impl<H: Hif, Q: QmiFw> CoreHooks<H, Q> for NoDp {}

// ── configuration ─────────────────────────────────────────────────

/// The `hw_params` fields and timeouts the core reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreConfig {
    /// `ab->fw_mode` (`ATH11K_FIRMWARE_MODE_NORMAL`).
    pub fw_mode: u32,
    pub credit_flow: bool,
    pub supports_shadow_regs: bool,
    pub single_pdev_only: bool,
    pub num_rxdma_per_pdev: u32,
    pub max_radios: u8,
    /// `hw_params.num_vdevs` (resource config).
    pub num_vdevs: u32,
    pub svc_to_ce_map: &'static [htc::ServiceToPipe],
    /// `ATH11K_HTC_WAIT_TIMEOUT_HZ`.
    pub htc_wait_ms: u64,
    /// `ATH11K_HTC_CONN_SVC_TIMEOUT_HZ`.
    pub htc_conn_ms: u64,
    /// `WMI_SERVICE_READY_TIMEOUT_HZ` (service ready and unified ready).
    pub service_ready_ms: u64,
    /// `WMI_SEND_TIMEOUT_HZ`.
    pub wmi_send_ms: u64,
}

impl CoreConfig {
    /// `ath11k_hw_params[]` for the PCI parts the core supports:
    /// QCA6390 and the WCN6855 family (all `single_pdev_only`,
    /// `num_rxdma_per_pdev = 2`, `max_radios = 3`, `num_vdevs = 2 + 1`,
    /// credit flow, shadow registers, the QCA6390 service map).
    /// QCN9074 (multi-pdev, no shadow registers) is not supported.
    pub fn for_hw(params: &HwParams) -> Option<Self> {
        match params.hw_rev {
            HwRev::Qca6390Hw20
            | HwRev::Wcn6855Hw20
            | HwRev::Wcn6855Hw21
            | HwRev::Qca2066Hw21
            | HwRev::Qca6698aqHw21 => Some(CoreConfig {
                fw_mode: ATH11K_FIRMWARE_MODE_NORMAL,
                credit_flow: params.credit_flow,
                supports_shadow_regs: params.supports_shadow_regs,
                single_pdev_only: true,
                num_rxdma_per_pdev: 2,
                max_radios: 3,
                num_vdevs: 2 + 1,
                svc_to_ce_map: &htc::TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
                htc_wait_ms: 1000,
                htc_conn_ms: 1000,
                service_ready_ms: 5000,
                wmi_send_ms: 3000,
            }),
            _ => None,
        }
    }

    /// `ath11k_wmi_attach`'s initial `preferred_hw_mode`.
    pub fn initial_hw_mode(&self) -> u32 {
        if self.single_pdev_only && self.num_rxdma_per_pdev > 1 {
            hw_mode::SINGLE
        } else {
            hw_mode::MAX
        }
    }

    /// The HTC knobs `ath11k_htc_init` reads (`wmi_ep_count` from the
    /// attach-time preferred hw mode).
    pub fn htc(&self) -> HtcConfig {
        HtcConfig {
            credit_flow: self.credit_flow,
            supports_shadow_regs: self.supports_shadow_regs,
            wmi_ep_count: htc::wmi_ep_count(self.initial_hw_mode(), self.max_radios),
            svc_to_ce_map: self.svc_to_ce_map,
        }
    }
}

// ── state ─────────────────────────────────────────────────────────

/// One queued WMI event: its id and the whole frame (`wmi_cmd_hdr`
/// included, so [`wmi::decode_event`] takes it as is).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WmiRx {
    pub id: u32,
    pub frame: Vec<u8>,
}

/// Where the core is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreState {
    /// Constructed; `qmi_firmware_ready` not run.
    Idle,
    /// WMI READY seen and every hook ran.
    Ready,
    /// Bring-up failed with this error (the session is kept: firmware
    /// may still own the target memory).
    Failed(TransportError),
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    pub rx_frames: u32,
    pub htc_rx_errors: u32,
    pub htc_unsolicited: u32,
    /// Frames for an endpoint nobody owns.
    pub rx_unrouted: u32,
    pub credit_reports: u32,
    pub wmi_events: u32,
    pub wmi_bad_events: u32,
    pub wmi_cmds: u32,
    pub credit_waits: u32,
    pub events_dropped: u32,
    pub htt_rx: u32,
    pub htt_dropped: u32,
}

/// `struct ath11k_base` as far as the core bring-up goes: the transport,
/// the QMI session, HTC, the WMI endpoint and what the firmware told us.
#[allow(missing_debug_implementations)]
pub struct Ath11kCore<H: Hif, Q: QmiFw> {
    pub hif: H,
    pub qmi: Q,
    pub cfg: CoreConfig,
    pub htc: Htc,
    pub state: CoreState,
    pub hif_started: bool,
    pub htc_ready: Option<HtcReady>,
    /// `dp->eid`.
    pub htt_ep: Option<HtcConnected>,
    /// `wmi_ab.wmi[0]` endpoint (`eid`, `max_msg_len`).
    pub wmi_ep: Option<HtcConnected>,
    /// `wmi_ab.preferred_hw_mode`.
    pub preferred_hw_mode: u32,
    /// `ab->target_caps`.
    pub target_caps: TargetCaps,
    pub fw_build_vers: u32,
    /// `wmi_ab.svc_map`.
    pub svc_map: ServiceMap,
    /// SERVICE_READY_EXT: hw modes, MAC/PHY caps, per-pdev band /
    /// HT / VHT / HE caps (`ab->pdevs[].cap`), HAL reg caps.
    pub svc_ext: Option<ServiceReadyExt>,
    /// `ab->db_caps` (from EXT, else EXT2).
    pub dma_ring_caps: Vec<DmaRingCap>,
    /// WMI READY.
    pub ready: Option<Ready>,
    /// `ab->mac_addr`.
    pub mac_addr: Option<[u8; 6]>,
    /// Latest REG_CHAN_LIST_CC[_EXT] (`ab->default_regd` source).
    pub reg_info: Option<Box<RegInfo>>,
    /// `seen::*`.
    pub seen: u32,
    service_ready_done: bool,
    unified_ready_done: bool,
    /// A bring-up event failed to decode (ends the wait it occurs in).
    fatal: Option<TransportError>,
    /// HTC endpoint-zero `SEND_SUSPEND_COMPLETE` / `NACK_SUSPEND`, consumed
    /// by the WoWLAN owner after `WMI_WOW_ENABLE_CMDID`.
    htc_suspend_complete: Option<bool>,
    /// `WMI_WOW_WAKEUP_HOST_EVENTID`, the completion Linux waits for after
    /// `WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID`.  HTC's similarly named EP0
    /// message is diagnostic-only and must not satisfy this wait.
    wow_wakeup: Option<wmi::WowWakeup>,
    events: VecDeque<WmiRx>,
    htt: VecDeque<Vec<u8>>,
    pub stats: CoreStats,
}

fn log(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "  ath11k: {}", args);
}

/// HTC error → detail word: kind << 16 | value.
pub fn htc_err_detail(e: &HtcError) -> u32 {
    let (k, v): (u32, u32) = match *e {
        HtcError::InvalidEndpoint(x) => (1, x as u32),
        HtcError::NoCredits { needed, .. } => (2, needed as u32 & 0xffff),
        HtcError::PayloadTooLarge(n) => (3, n as u32 & 0xffff),
        HtcError::ShortFrame => (4, 0),
        HtcError::FrameTooLong(n) => (5, n as u32 & 0xffff),
        HtcError::InsufficientLength { got, .. } => (6, got as u32 & 0xffff),
        HtcError::InvalidTrailerLen(x) => (7, x as u32),
        HtcError::InvalidRecord => (8, 0),
        HtcError::NotConnected(x) => (9, x as u32),
        HtcError::NoControlResponse => (10, 0),
        HtcError::BadReady => (11, 0),
        HtcError::BadConnectResp => (12, 0),
        HtcError::ConnectRefused(s) => (13, s as u32),
        HtcError::BadAssignment => (14, 0),
        HtcError::NoPipe(s) => (15, s as u32),
        HtcError::OutOfOrder => (16, 0),
    };
    k << 16 | v
}

fn htc_error(step: u32, e: HtcError) -> TransportError {
    TransportError::new(step, htc_err_detail(&e), e.errno())
}

fn wmi_decode_error(id: u32, e: WmiError) -> TransportError {
    TransportError::new(
        step::SERVICE_READY_DECODE,
        (id & 0xffff) << 16 | e.errno() as u32,
        e.errno(),
    )
}

impl<H: Hif, Q: QmiFw> Ath11kCore<H, Q> {
    /// A core over `hif` and the FW_READY session `qmi`.
    /// `ath11k_wmi_attach` + `ath11k_htc_init` run here (no I/O). On
    /// failure `hif` and `qmi` come back (the session must outlive the
    /// firmware's use of its target memory).
    #[allow(clippy::result_large_err)]
    pub fn new(hif: H, qmi: Q, cfg: CoreConfig) -> Result<Self, (TransportError, H, Q)> {
        let htc = match Htc::init(cfg.htc()) {
            Ok(h) => h,
            Err(e) => return Err((htc_error(step::HTC_INIT, e), hif, qmi)),
        };
        Ok(Ath11kCore {
            hif,
            qmi,
            cfg,
            htc,
            state: CoreState::Idle,
            hif_started: false,
            htc_ready: None,
            htt_ep: None,
            wmi_ep: None,
            preferred_hw_mode: cfg.initial_hw_mode(),
            target_caps: TargetCaps::default(),
            fw_build_vers: 0,
            svc_map: ServiceMap::default(),
            svc_ext: None,
            dma_ring_caps: Vec::new(),
            ready: None,
            mac_addr: None,
            reg_info: None,
            seen: 0,
            service_ready_done: false,
            unified_ready_done: false,
            fatal: None,
            htc_suspend_complete: None,
            wow_wakeup: None,
            events: VecDeque::new(),
            htt: VecDeque::new(),
            stats: CoreStats::default(),
        })
    }

    /// `true` once WMI READY arrived and every hook ran.
    pub fn is_ready(&self) -> bool {
        self.state == CoreState::Ready
    }

    /// The transport, the QMI session and the configuration back, for a
    /// restart (`ath11k_core_reconfigure_on_crash`): everything else —
    /// HTC and its endpoints, WMI (`ath11k_wmi_detach`), the service maps
    /// and capabilities, queued events — is dropped. The next
    /// [`Self::new`] runs `ath11k_wmi_attach` + `ath11k_htc_init` again,
    /// as `ath11k_core_start` does.
    pub fn into_parts(self) -> (H, Q, CoreConfig) {
        (self.hif, self.qmi, self.cfg)
    }

    // ── RX dispatch ───────────────────────────────────────────────

    /// Process everything the HIF has received (the CE `recv_cb`s).
    pub fn drain_rx(&mut self) {
        while let Some((pipe, buf)) = self.hif.take_rx() {
            self.stats.rx_frames += 1;
            match self.hif.recv_kind(pipe) {
                // CE5: ath11k_dp_htt_htc_t2h_msg_handler directly.
                Some(CeRecv::HttT2h) => self.push_htt(buf),
                _ => self.htc_rx(&buf),
            }
        }
    }

    /// `ath11k_htc_rx_completion_handler` → `ep_rx_complete`.
    fn htc_rx(&mut self, buf: &[u8]) {
        let rx = match self.htc.rx(buf) {
            Ok(rx) => rx,
            Err(e) => {
                // Linux warns and drops the frame.
                self.stats.htc_rx_errors += 1;
                log(format_args!("htc: rx dropped: {:?} (len {})", e, buf.len()));
                return;
            }
        };
        if !rx.credited.is_empty() {
            // ep_tx_credits → wake_up(tx_credits_wq): the WMI send
            // loop re-tries on its next pass.
            self.stats.credit_reports += 1;
        }
        match rx.kind {
            HtcRxKind::SuspendComplete(ack) => {
                // `ath11k_htc_suspend_complete`: an ACK is the terminal
                // WoW-enable response; NACK is retained too so the caller
                // can perform Linux's bounded retry sequence.
                self.htc_suspend_complete = Some(ack);
            }
            // `ath11k_htc_wakeup_from_suspend` only logs this endpoint-zero
            // indication.  The WMI WoW wakeup-host event below is the real
            // `ath11k_wow_wakeup` completion.
            HtcRxKind::WakeupFromSuspend => {}
            HtcRxKind::Deliver { eid, range } => {
                if self.wmi_ep.map(|e| e.eid) == Some(eid) {
                    self.wmi_rx(&buf[range]);
                } else if self.htt_ep.map(|e| e.eid) == Some(eid) {
                    self.push_htt(buf[range].to_vec());
                } else {
                    self.stats.rx_unrouted += 1;
                }
            }
            HtcRxKind::UnsolicitedControl(id) => {
                self.stats.htc_unsolicited += 1;
                log(format_args!("htc: unsolicited control message {}", id));
            }
            _ => {}
        }
    }

    fn push_htt(&mut self, b: Vec<u8>) {
        self.stats.htt_rx += 1;
        if self.htt.len() >= EVENT_QUEUE_MAX {
            self.htt.pop_front();
            self.stats.htt_dropped += 1;
        }
        self.htt.push_back(b);
    }

    fn push_event(&mut self, id: u32, frame: &[u8]) {
        if self.events.len() >= EVENT_QUEUE_MAX {
            self.events.pop_front();
            self.stats.events_dropped += 1;
        }
        self.events.push_back(WmiRx {
            id,
            frame: frame.to_vec(),
        });
    }

    fn fail_decode(&mut self, e: TransportError) {
        self.stats.wmi_bad_events += 1;
        if self.fatal.is_none() {
            self.fatal = Some(e);
        }
    }

    /// `ath11k_wmi_tlv_op_rx`.
    fn wmi_rx(&mut self, frame: &[u8]) {
        let (id, p) = match wmi::split_event(frame) {
            Ok(v) => v,
            Err(_) => {
                self.stats.wmi_bad_events += 1;
                return;
            }
        };
        self.stats.wmi_events += 1;
        match id {
            wmi::WMI_SERVICE_READY_EVENTID => match wmi::decode_service_ready(p) {
                Ok(sr) => {
                    if let Some(c) = sr.caps {
                        self.target_caps = c;
                    }
                    self.fw_build_vers = sr.fw_build_vers;
                    // ath11k_wmi_service_bitmap_copy: set_bit into svc_map.
                    for s in 0..wmi::WMI_MAX_SERVICE {
                        if sr.svc_map.test(s) {
                            self.svc_map.set(s);
                        }
                    }
                    self.seen |= seen::SERVICE_READY;
                }
                // NARF-stricter: Linux warns and goes on without the
                // caps / bitmap.
                Err(e) => self.fail_decode(wmi_decode_error(id, e)),
            },
            wmi::WMI_SERVICE_AVAILABLE_EVENTID => {
                // Linux warns on a parse error; segments already
                // applied stay applied.
                if let Err(e) = wmi::apply_service_available(&mut self.svc_map, p) {
                    self.stats.wmi_bad_events += 1;
                    log(format_args!(
                        "wmi: failed to parse services available tlv: {:?}",
                        e
                    ));
                }
                self.seen |= seen::SERVICE_AVAILABLE;
            }
            wmi::WMI_SERVICE_READY_EXT_EVENTID => {
                match wmi::decode_service_ready_ext(
                    p,
                    self.preferred_hw_mode,
                    self.cfg.single_pdev_only,
                ) {
                    Ok(ext) => {
                        self.preferred_hw_mode = ext.preferred_hw_mode;
                        if !ext.dma_ring_caps.is_empty() {
                            self.dma_ring_caps = ext.dma_ring_caps.clone();
                        }
                        self.svc_ext = Some(ext);
                        self.seen |= seen::SERVICE_READY_EXT;
                        if self.svc_map.test(wmi::WMI_TLV_SERVICE_EXT2_MSG) {
                            self.seen |= seen::EXT2_EXPECTED;
                        } else {
                            self.service_ready_done = true;
                        }
                    }
                    // Linux: no completion → the 5 s wait times out.
                    Err(e) => self.fail_decode(wmi_decode_error(id, e)),
                }
            }
            wmi::WMI_SERVICE_READY_EXT2_EVENTID => match wmi::decode_service_ready_ext2(p) {
                Ok(caps) => {
                    // ath11k_wmi_tlv_dma_ring_caps: "Already processed,
                    // so ignoring dma ring caps".
                    if self.dma_ring_caps.is_empty() {
                        self.dma_ring_caps = caps;
                    }
                    self.seen |= seen::SERVICE_READY_EXT2;
                    self.service_ready_done = true;
                }
                Err(e) => self.fail_decode(wmi_decode_error(id, e)),
            },
            wmi::WMI_READY_EVENTID => match wmi::decode_ready(p) {
                Ok(r) => {
                    self.mac_addr = Some(r.mac_addr);
                    self.ready = Some(r);
                    self.seen |= seen::READY;
                    self.unified_ready_done = true;
                }
                Err(e) => self.fail_decode(TransportError::new(
                    step::READY_DECODE,
                    e.errno() as u32,
                    e.errno(),
                )),
            },
            wmi::WMI_REG_CHAN_LIST_CC_EVENTID | wmi::WMI_REG_CHAN_LIST_CC_EXT_EVENTID => {
                let r = if id == wmi::WMI_REG_CHAN_LIST_CC_EVENTID {
                    wmi::decode_reg_chan_list(p)
                } else {
                    wmi::decode_reg_chan_list_ext(p)
                };
                match r {
                    Ok(info) => {
                        self.reg_info = Some(Box::new(info));
                        self.seen |= seen::REG_CHAN_LIST;
                    }
                    Err(e) => {
                        self.stats.wmi_bad_events += 1;
                        log(format_args!("wmi: reg chan list event: {:?}", e));
                    }
                }
                self.push_event(id, frame);
            }
            wmi::WMI_WOW_WAKEUP_HOST_EVENTID => match wmi::decode_wow_wakeup(p) {
                Ok(wakeup) => self.wow_wakeup = Some(wakeup),
                Err(e) => self.fail_decode(wmi_decode_error(id, e)),
            },
            _ => self.push_event(id, frame),
        }
    }

    // ── waiting ───────────────────────────────────────────────────

    /// One service pass: wait up to `ms`, then process what arrived.
    pub async fn pump(&mut self, ms: u32) {
        self.hif.wait(ms).await;
        self.drain_rx();
    }

    /// Process RX until `done` or `timeout_ms` (HIF clock). `Err` only
    /// for a bring-up event that failed to decode.
    async fn wait_until(
        &mut self,
        timeout_ms: u64,
        done: impl Fn(&Self) -> bool,
    ) -> Result<bool, TransportError> {
        let deadline = self.hif.now_ms().saturating_add(timeout_ms);
        loop {
            self.drain_rx();
            if let Some(e) = self.fatal.take() {
                return Err(e);
            }
            if done(self) {
                return Ok(true);
            }
            let now = self.hif.now_ms();
            if now >= deadline {
                return Ok(false);
            }
            self.hif
                .wait((deadline - now).min(CORE_SLICE_MS) as u32)
                .await;
        }
    }

    // ── HTC ───────────────────────────────────────────────────────

    /// `ath11k_htc_send`'s CE half: post, give the credits back on a CE
    /// refusal (`err_credits`).
    fn htc_tx(&mut self, tx: HtcTx) -> Result<(), TransportError> {
        match self.hif.send(tx.pipe, &tx.frame, tx.eid as u16) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.htc.revert_credits(&tx);
                Err(e)
            }
        }
    }

    /// `ath11k_htc_wait_target`.
    pub async fn htc_wait_target(&mut self) -> Result<HtcReady, TransportError> {
        let ms = self.cfg.htc_wait_ms;
        let mut ok = self.wait_until(ms, |c| c.htc.control_pending()).await?;
        if !ok {
            log(format_args!(
                "failed to receive control response completion, polling.."
            ));
            self.hif.poll_all();
            ok = self.wait_until(ms, |c| c.htc.control_pending()).await?;
        }
        if !ok {
            return Err(TransportError::new(step::HTC_READY_TIMEOUT, 0, ETIMEDOUT));
        }
        let r = self
            .htc
            .wait_target()
            .map_err(|e| htc_error(step::HTC_BAD_READY, e))?;
        log(format_args!(
            "htc: target ready credits {} x {} bytes (using {}), max endpoints {}",
            r.credit_count, r.credit_size, self.htc.total_transmit_credits, r.max_endpoints
        ));
        self.htc_ready = Some(r);
        Ok(r)
    }

    /// `ath11k_htc_connect_service` for a real service.
    async fn connect_service(
        &mut self,
        service_id: u16,
        fail: u32,
        timeout: u32,
    ) -> Result<HtcConnected, TransportError> {
        let tx = self
            .htc
            .connect_service_request(service_id, 0)
            .map_err(|e| htc_error(fail, e))?;
        self.htc_tx(tx)
            .map_err(|e| TransportError::new(fail, (service_id as u32) << 16 | e.step, e.errno))?;
        let ms = self.cfg.htc_conn_ms;
        if !self.wait_until(ms, |c| c.htc.control_pending()).await? {
            return Err(TransportError::new(timeout, service_id as u32, ETIMEDOUT));
        }
        let c = self
            .htc
            .connect_service_complete()
            .map_err(|e| htc_error(fail, e))?;
        log(format_args!(
            "htc: service {:#06x} → eid {} (ul {} dl {}) max_msg {} credits {} flow {}",
            c.service_id, c.eid, c.ul_pipe, c.dl_pipe, c.max_msg_len, c.tx_credits, c.credit_flow
        ));
        Ok(c)
    }

    /// `ath11k_dp_htt_connect`.
    pub async fn htt_connect(&mut self) -> Result<(), TransportError> {
        let c = self
            .connect_service(
                svc_id::HTT_DATA_MSG,
                step::HTT_CONNECT,
                step::HTT_CONNECT_TIMEOUT,
            )
            .await?;
        self.htt_ep = Some(c);
        Ok(())
    }

    /// `ath11k_wmi_connect` → `ath11k_connect_pdev_htc_service` per WMI
    /// endpoint. NARF-stricter: Linux only warns when a WMI connect
    /// fails (and then times out waiting for service ready); here it
    /// fails with its own step.
    pub async fn wmi_connect(&mut self) -> Result<(), TransportError> {
        const SVC: [u16; 3] = [
            svc_id::WMI_CONTROL,
            svc_id::WMI_CONTROL_MAC1,
            svc_id::WMI_CONTROL_MAC2,
        ];
        let n = self.htc.cfg.wmi_ep_count;
        if n > self.cfg.max_radios {
            return Err(TransportError::new(step::WMI_CONNECT, n as u32, EINVAL));
        }
        for &s in SVC.iter().take(n as usize) {
            let c = self
                .connect_service(s, step::WMI_CONNECT, step::WMI_CONNECT_TIMEOUT)
                .await?;
            // wmi_ab.wmi[0] is the only pdev handle used on
            // single-pdev parts.
            if self.wmi_ep.is_none() {
                self.wmi_ep = Some(c);
            }
        }
        Ok(())
    }

    /// `ath11k_htc_start`: SETUP_COMPLETE_EX.
    pub fn htc_start(&mut self) -> Result<(), TransportError> {
        let tx = self
            .htc
            .start()
            .map_err(|e| htc_error(step::HTC_START, e))?;
        self.htc_tx(tx)
            .map_err(|e| TransportError::new(step::HTC_START, e.step, e.errno))
    }

    // ── WMI ───────────────────────────────────────────────────────

    /// One `ath11k_wmi_cmd_send_nowait` attempt on `wmi_ab.wmi[0]`:
    /// `Err(errno)` — `-EAGAIN` while HTC has no credits, the CE's errno
    /// when it refuses ([`Self::wmi_send_retryable`] tells whether
    /// `ath11k_wmi_cmd_send` would retry), `-ENODEV` without a WMI
    /// endpoint. The runtime's [`super::runtime`] ports use this to wait
    /// without holding the core.
    pub fn wmi_cmd_try_send(&mut self, cmd: &WmiCmd) -> Result<(), i32> {
        let Some(ep) = self.wmi_ep else {
            return Err(ENODEV);
        };
        let payload = cmd.frame();
        let ret = match self.htc.send(ep.eid, &payload) {
            Ok(tx) => match self.htc_tx(tx) {
                Ok(()) => {
                    self.stats.wmi_cmds += 1;
                    return Ok(());
                }
                Err(e) => e.errno,
            },
            Err(HtcError::NoCredits { .. }) => EAGAIN,
            Err(e) => e.errno(),
        };
        Err(ret)
    }

    /// `ath11k_wmi_cmd_send`'s `wait_event_timeout` condition: with credit
    /// flow it retries `-EAGAIN`, without it `-ENOBUFS`.
    pub fn wmi_send_retryable(&self, errno: i32) -> bool {
        if self.cfg.credit_flow {
            errno == EAGAIN
        } else {
            errno == ENOBUFS
        }
    }

    /// `ath11k_wmi_cmd_send` on `wmi_ab.wmi[0]`: with credit flow, retry
    /// while HTC has no credits (`-EAGAIN`) for up to 3 s; without it,
    /// retry while the CE ring is full (`-ENOBUFS`).
    pub async fn wmi_cmd_send(&mut self, cmd: &WmiCmd) -> Result<(), TransportError> {
        if self.wmi_ep.is_none() {
            return Err(TransportError::new(step::NO_WMI_EP, cmd.cmd_id, ENODEV));
        }
        let deadline = self.hif.now_ms().saturating_add(self.cfg.wmi_send_ms);
        loop {
            let ret = match self.wmi_cmd_try_send(cmd) {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            let retry = self.wmi_send_retryable(ret);
            let now = self.hif.now_ms();
            if !retry || now >= deadline {
                let st = if ret == EAGAIN {
                    log(format_args!("wmi command {:#x} timeout", cmd.cmd_id));
                    step::WMI_SEND_CREDITS
                } else {
                    if ret == ENOBUFS {
                        log(format_args!(
                            "ce desc not available for wmi command {:#x}",
                            cmd.cmd_id
                        ));
                    }
                    step::WMI_SEND
                };
                return Err(TransportError::new(st, cmd.cmd_id, ret));
            }
            self.stats.credit_waits += 1;
            self.hif
                .wait((deadline - now).min(CORE_SLICE_MS) as u32)
                .await;
            self.drain_rx();
        }
    }

    /// Next queued WMI event, if any.
    pub fn take_event(&mut self) -> Option<WmiRx> {
        self.events.pop_front()
    }

    /// Take an endpoint-zero WoW suspend response.  This is separate from
    /// the WMI event queue because HTC control frames are not WMI events.
    pub fn take_htc_suspend_complete(&mut self) -> Option<bool> {
        self.htc_suspend_complete.take()
    }

    /// Take WMI's WoW wakeup-host completion and its firmware reason.
    pub fn take_wow_wakeup(&mut self) -> Option<wmi::WowWakeup> {
        self.wow_wakeup.take()
    }

    /// Queued WMI events.
    pub fn events_pending(&self) -> usize {
        self.events.len()
    }

    /// Ids of the queued WMI events, oldest first.
    pub fn queued_event_ids(&self) -> Vec<u32> {
        self.events.iter().map(|e| e.id).collect()
    }

    /// Next WMI event (any id), waiting up to `timeout_ms`.
    pub async fn next_event(&mut self, timeout_ms: u64) -> Option<WmiRx> {
        let deadline = self.hif.now_ms().saturating_add(timeout_ms);
        loop {
            self.drain_rx();
            if let Some(e) = self.events.pop_front() {
                return Some(e);
            }
            let now = self.hif.now_ms();
            if now >= deadline {
                return None;
            }
            self.hif
                .wait((deadline - now).min(CORE_SLICE_MS) as u32)
                .await;
        }
    }

    /// The first queued event with `id`, waiting up to `timeout_ms`;
    /// other events stay queued in order. Times out with
    /// `step::EVENT_TIMEOUT` (not latched).
    pub async fn wait_event(&mut self, id: u32, timeout_ms: u64) -> Result<WmiRx, TransportError> {
        let deadline = self.hif.now_ms().saturating_add(timeout_ms);
        loop {
            self.drain_rx();
            if let Some(i) = self.events.iter().position(|e| e.id == id) {
                if let Some(e) = self.events.remove(i) {
                    return Ok(e);
                }
            }
            let now = self.hif.now_ms();
            if now >= deadline {
                return Err(TransportError::new(step::EVENT_TIMEOUT, id, ETIMEDOUT));
            }
            self.hif
                .wait((deadline - now).min(CORE_SLICE_MS) as u32)
                .await;
        }
    }

    /// Send `cmd`, then await event `event_id`.
    pub async fn wmi_cmd_wait(
        &mut self,
        cmd: &WmiCmd,
        event_id: u32,
        timeout_ms: u64,
    ) -> Result<WmiRx, TransportError> {
        self.wmi_cmd_send(cmd).await?;
        self.wait_event(event_id, timeout_ms).await
    }

    // ── HTT (for the DP layer) ────────────────────────────────────

    /// `ath11k_htc_send(&ab->htc, dp->eid, skb)` — no credit flow on HTT.
    pub fn htt_send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let Some(ep) = self.htt_ep else {
            return Err(TransportError::new(step::HTT_SEND, 0, ENODEV));
        };
        let tx = self
            .htc
            .send(ep.eid, payload)
            .map_err(|e| htc_error(step::HTT_SEND, e))?;
        self.htc_tx(tx)
    }

    /// Next HTT target→host message (HTC header stripped; raw on CE5).
    pub fn take_htt(&mut self) -> Option<Vec<u8>> {
        self.htt.pop_front()
    }

    /// Next HTT message, waiting up to `timeout_ms`.
    pub async fn wait_htt(&mut self, timeout_ms: u64) -> Option<Vec<u8>> {
        let deadline = self.hif.now_ms().saturating_add(timeout_ms);
        loop {
            self.drain_rx();
            if let Some(m) = self.htt.pop_front() {
                return Some(m);
            }
            let now = self.hif.now_ms();
            if now >= deadline {
                return None;
            }
            self.hif
                .wait((deadline - now).min(CORE_SLICE_MS) as u32)
                .await;
        }
    }

    // ── bring-up ──────────────────────────────────────────────────

    /// `ath11k_wmi_wait_for_service_ready`.
    pub async fn wait_for_service_ready(&mut self) -> Result<(), TransportError> {
        let ms = self.cfg.service_ready_ms;
        if !self.wait_until(ms, |c| c.service_ready_done).await? {
            return Err(TransportError::new(
                step::SERVICE_READY_TIMEOUT,
                self.seen,
                ETIMEDOUT,
            ));
        }
        let ext = self.svc_ext.as_ref();
        log(format_args!(
            "wmi: service ready: fw {:#x} rf_chains {} ht_cap {:#x} vht_cap {:#x} \
             preferred_hw_mode {} radios {} ext2 {} reg_cc_ext {}",
            self.fw_build_vers,
            self.target_caps.num_rf_chains,
            self.target_caps.ht_cap_info,
            self.target_caps.vht_cap_info,
            self.preferred_hw_mode,
            ext.map_or(0, |e| e.num_radios),
            self.seen & seen::SERVICE_READY_EXT2 != 0,
            self.svc_map
                .test(wmi::WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT)
        ));
        Ok(())
    }

    /// `ath11k_wmi_cmd_init` for a `single_pdev_only` chip:
    /// `ath11k_init_wmi_config_qca6390` with `num_rf_chains` from
    /// SERVICE_READY, `is_reg_cc_ext_event_supported` from the service
    /// map, no host memory chunks, `hw_mode_id = WMI_HOST_HW_MODE_MAX`.
    pub fn init_cmd(&self) -> Result<WmiCmd, TransportError> {
        if !self.cfg.single_pdev_only {
            return Err(TransportError::new(step::WMI_INIT, 1, EOPNOTSUPP));
        }
        let res = TargetResourceConfig::qca6390(
            self.cfg.num_vdevs,
            self.target_caps.num_rf_chains,
            self.svc_map
                .test(wmi::WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT),
        );
        wmi::init_cmd(&InitCmdParam::single_pdev(res))
            .map_err(|e| TransportError::new(step::WMI_INIT, 2, e.errno()))
    }

    /// `ath11k_wmi_wait_for_unified_ready`.
    pub async fn wait_for_unified_ready(&mut self) -> Result<(), TransportError> {
        let ms = self.cfg.service_ready_ms;
        if !self.wait_until(ms, |c| c.unified_ready_done).await? {
            return Err(TransportError::new(
                step::READY_TIMEOUT,
                self.seen,
                ETIMEDOUT,
            ));
        }
        Ok(())
    }

    /// `ath11k_core_start` (see the module docs for the order).
    async fn core_start<D: CoreHooks<H, Q>>(
        &mut self,
        hooks: &mut D,
    ) -> Result<(), TransportError> {
        // ath11k_wmi_attach + ath11k_htc_init happened in `new`.
        self.hif.start();
        self.hif_started = true;
        self.htc_wait_target().await?;
        self.htt_connect().await?;
        self.wmi_connect().await?;
        self.htc_start()?;
        self.wait_for_service_ready().await?;
        // ath11k_mac_allocate: mac80211 — the caps it consumes stay in
        // `target_caps` / `svc_ext`.
        hooks.pdev_reo_setup(self)?;
        let init = self.init_cmd()?;
        self.wmi_cmd_send(&init).await?;
        self.wait_for_unified_ready().await?;
        if let Some(mac) = self.mac_addr {
            log(format_args!(
                "wmi: ready: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ));
        }
        diag::set_wifi_stage(WifiStage::Commands);
        // "put hardware to DBS mode"
        if self.cfg.single_pdev_only && self.cfg.num_rxdma_per_pdev > 1 {
            let cmd = wmi::set_hw_mode_cmd(hw_mode::DBS);
            self.wmi_cmd_send(&cmd).await?;
        }
        hooks.htt_ver_req(self).await
    }

    /// `ath11k_core_qmi_firmware_ready`. On failure the error is
    /// latched + printed, the HIF stopped and the firmware told
    /// `wlan_mode OFF` where Linux does; the core keeps its state
    /// ([`CoreState::Failed`]).
    pub async fn qmi_firmware_ready<D: CoreHooks<H, Q>>(
        &mut self,
        hooks: &mut D,
    ) -> Result<(), TransportError> {
        let r = self.firmware_ready_inner(hooks).await;
        match r {
            Ok(()) => {
                self.state = CoreState::Ready;
                Ok(())
            }
            Err(e) => {
                self.state = CoreState::Failed(e);
                Err(e)
            }
        }
    }

    async fn firmware_ready_inner<D: CoreHooks<H, Q>>(
        &mut self,
        hooks: &mut D,
    ) -> Result<(), TransportError> {
        // ath11k_core_start_firmware.
        let shadow = self.hif.shadow_reg_v2();
        if let Err(e) = self.qmi.firmware_start(self.cfg.fw_mode, &shadow).await {
            let e = TransportError::new(e.step, e.detail, e.errno);
            e.report("firmware start");
            return Err(e);
        }
        let r = self.after_firmware_start(hooks).await;
        if let Err(e) = r {
            e.report("ath11k core start");
            if self.hif_started {
                self.hif.stop();
                self.hif_started = false;
            }
            self.qmi.firmware_stop().await;
        }
        r
    }

    async fn after_firmware_start<D: CoreHooks<H, Q>>(
        &mut self,
        hooks: &mut D,
    ) -> Result<(), TransportError> {
        self.hif.init_pipes()?;
        hooks.dp_alloc(self)?;
        self.core_start(hooks).await?;
        hooks.pdev_create(self).await?;
        hooks.irq_enable(self);
        Ok(())
    }
}

// ── the real HIF: CE over PCI ─────────────────────────────────────

/// [`Hif`] over the Copy Engines.
#[allow(missing_debug_implementations)]
pub struct CeHif<Io: ChipIo, Irq: CeIrq> {
    pub ce: Ce,
    pub io: Io,
    pub irq: Irq,
    /// Runs first in `start` (`ath11k_pci_start`: ASPM restore).
    pub on_start: fn(),
    pub clock: fn() -> u64,
}

impl<Io: ChipIo, Irq: CeIrq> Hif for CeHif<Io, Irq> {
    fn shadow_reg_v2(&self) -> Vec<u32> {
        self.ce.shadow_reg_v2().to_vec()
    }
    fn init_pipes(&mut self) -> Result<(), TransportError> {
        self.ce.init_pipes(&self.io)
    }
    fn start(&mut self) {
        (self.on_start)();
        self.ce.start(&self.io);
    }
    fn stop(&mut self) {
        self.ce.stop();
    }
    fn send(&mut self, pipe: u8, frame: &[u8], transfer_id: u16) -> Result<(), TransportError> {
        self.ce.send(&self.io, pipe as u32, frame, transfer_id)
    }
    fn take_rx(&mut self) -> Option<(u32, Vec<u8>)> {
        self.ce.take_rx_any()
    }
    fn recv_kind(&self, pipe: u32) -> Option<CeRecv> {
        self.ce.pipe(pipe).and_then(|p| p.recv_cb)
    }
    fn poll_all(&mut self) {
        for i in 0..self.ce.ce_count() as u32 {
            self.ce.per_engine_service(&self.io, i);
        }
    }
    async fn wait(&mut self, ms: u32) {
        self.ce.wait_and_service(&self.io, &self.irq, ms).await;
    }
    fn now_ms(&self) -> u64 {
        (self.clock)()
    }
}

/// BAR0 by value (the PCI glue's [`ChipIo`]).
#[derive(Copy, Clone, Debug)]
pub struct Bar0(pub narf_bus::MmioRegion);

impl ChipIo for Bar0 {
    fn read32(&self, offset: u32) -> u32 {
        super::pci::Bar0Io(&self.0).read32(offset)
    }
    fn write32(&self, offset: u32, value: u32) {
        super::pci::Bar0Io(&self.0).write32(offset, value)
    }
    fn delay_ms(&self, ms: u32) {
        super::pci::Bar0Io(&self.0).delay_ms(ms)
    }
    fn restore_window(&self) {
        super::pci::Bar0Io(&self.0).restore_window()
    }
}

pub type PciHif = CeHif<Bar0, MsiCeIrq>;
pub type PciCore = Ath11kCore<PciHif, super::pci::Wlfw>;

/// The core after bring-up (ready or failed — a failed core is kept so
/// the target memory the firmware was given is never freed). Never hold
/// this lock across an `.await`.
static CORE: IrqSafeSpinLock<Option<PciCore>> = IrqSafeSpinLock::new(None);
/// A FW_READY session the core could not start on (CE allocation
/// failed); parked for the same reason.
static STRANDED: IrqSafeSpinLock<Option<super::pci::Wlfw>> = IrqSafeSpinLock::new(None);
/// The DP of a failed bring-up (its rings were programmed into the
/// hardware; never freed).
static STRANDED_DP: IrqSafeSpinLock<Option<super::dp_ring::Dp>> = IrqSafeSpinLock::new(None);

/// Take a ready core parked with [`park_core`]. Bring-up hands a ready
/// core straight to the runtime ([`super::runtime::start_pci`]), so the
/// slot normally holds only a failed core, which stays parked.
pub fn take_core() -> Option<PciCore> {
    let mut g = CORE.lock();
    if g.as_ref().is_some_and(|c| c.is_ready()) {
        g.take()
    } else {
        None
    }
}

/// Return a core taken with [`take_core`].
pub fn park_core(c: PciCore) {
    *CORE.lock() = Some(c);
}

/// `true` once a ready core is parked.
pub fn core_ready() -> bool {
    CORE.lock().as_ref().is_some_and(|c| c.is_ready())
}

/// The failure a parked core ended with.
pub fn core_failure() -> Option<TransportError> {
    match CORE.lock().as_ref().map(|c| c.state) {
        Some(CoreState::Failed(e)) => Some(e),
        _ => None,
    }
}

/// The PCI side of `ath11k_core_qmi_firmware_ready`, run by the MHI task
/// after FW_READY: the probe-time CE setup Linux does in
/// `ath11k_pci_probe` (`ath11k_hal_srng_init`, `ath11k_ce_alloc_pipes`,
/// `ath11k_pcic_config_irq`), then the core bring-up.
pub async fn pci_start(w: super::pci::Wlfw) {
    let dev = super::pci::with_controller(|d| {
        (
            d.params,
            CeMsi {
                addr: d.msi.addr,
                ep_base_data: d.msi.ep_base_data,
                config: d.msi.config,
            },
            d.msi.base_irq,
            d.msi.n_vectors,
        )
    });
    let Some((params, msi, base_irq, n_vectors)) = dev else {
        TransportError::new(step::NO_DEVICE, 0, ENODEV).report("ath11k core");
        *STRANDED.lock() = Some(w);
        return;
    };
    let Some(cfg) = CoreConfig::for_hw(&params) else {
        TransportError::new(step::UNSUPPORTED, params.hw_rev as u32, EOPNOTSUPP)
            .report("ath11k core");
        *STRANDED.lock() = Some(w);
        return;
    };
    let ce = match Ce::alloc(&params, msi, ce::monotonic_ms) {
        Ok(c) => c,
        Err(_) => {
            // Ce::alloc latched + printed.
            *STRANDED.lock() = Some(w);
            return;
        }
    };
    ce::install_ce_irq_handlers(params.host_ce_config, msi.config, base_irq, n_vectors);
    // ath11k_pcic_config_irq's ext part (ath11k_pcic_ext_irq_config).
    if let Err(e) =
        super::runtime::install_dp_irq_handlers(params.ring_mask, msi.config, base_irq, n_vectors)
    {
        e.report("ath11k DP irq config");
        *STRANDED.lock() = Some(w);
        return;
    }
    let mmio = super::pci::with_controller(|d| d.mmio_bar0);
    let Some(mmio) = mmio else {
        TransportError::new(step::NO_DEVICE, 1, ENODEV).report("ath11k core");
        *STRANDED.lock() = Some(w);
        return;
    };
    let hif = CeHif {
        ce,
        io: Bar0(mmio),
        irq: MsiCeIrq,
        on_start: super::pci::aspm_restore,
        clock: ce::monotonic_ms,
    };
    let mut core = match Ath11kCore::new(hif, w, cfg) {
        Ok(c) => c,
        Err((e, _hif, w)) => {
            e.report("ath11k core");
            *STRANDED.lock() = Some(w);
            return;
        }
    };
    let mut hooks = super::runtime::DpHooks::new(
        super::dp_ring::DpHwParams::for_rev(params.hw_rev),
        params.hw_rev as u32,
        super::dp_ring::DpRingSizes::LINUX,
        Some(msi),
    );
    let r = core.qmi_firmware_ready(&mut hooks).await;
    let st = core.hif.ce.stats;
    log(format_args!(
        "core: {:?} ce irqs {:?} polled-without-irq {} wmi events {} cmds {} credit waits {}",
        core.state,
        st.irqs,
        st.polled_without_irq,
        core.stats.wmi_events,
        core.stats.wmi_cmds,
        core.stats.credit_waits
    ));
    match (r, hooks.dp.take()) {
        // ath11k_core_qmi_firmware_ready succeeded: the runtime takes
        // the core + DP (ath11k_mac_register → wlan%d).
        (Ok(()), Some(dp)) => super::runtime::start_pci(core, dp).await,
        (_, dp) => {
            // The unwind stopped the firmware (wlan_mode OFF); keep
            // everything it was given (target memory, programmed rings).
            *STRANDED_DP.lock() = dp;
            *CORE.lock() = Some(core);
        }
    }
}

//! The WLFW bring-up state machine: from MHI mission mode to
//! FW_READY over QRTR/QMI, then `firmware_start` (wlan_ini →
//! wlan_cfg → wlan_mode).
//!
//! A port of Linux `drivers/net/wireless/ath/ath11k/qmi.c`'s event
//! machinery as it runs on WCN6855 (PCIe, `fixed_fw_mem = false`,
//! `fixed_mem_region = false`, `fixed_bdf_addr = false`, no cold-boot
//! calibration), driven against three traits so a scripted fake
//! firmware runs the whole handshake offline:
//! [`QrtrPipe`] (the IPCR channels), [`FirmwareLoader`]
//! (`firmware_request_nowarn`) and [`DmaAllocator`]
//! (`dma_alloc_coherent` under the 32-bit coherent mask).
//!
//! Ported (Linux → here):
//! - `ath11k_qmi_init_service` → [`Wlfw::new`] + the lookup in
//!   [`Wlfw::run_to_fw_ready`];
//! - `ath11k_qmi_driver_event_work` → [`Wlfw::run_to_fw_ready`]'s
//!   event loop; `ath11k_qmi_ops_new_server` / `_del_server` and the
//!   `ath11k_qmi_msg_*_cb` handlers → [`Wlfw::drain_inbound`];
//! - `ath11k_qmi_event_server_arrive`, `ath11k_qmi_fw_ind_register_send`,
//!   `ath11k_qmi_host_cap_send`, `ath11k_qmi_alloc_target_mem_chunk`,
//!   `ath11k_qmi_free_target_mem_chunk`, `ath11k_qmi_event_mem_request`
//!   / `ath11k_qmi_respond_fw_mem_request`, `ath11k_qmi_event_load_bdf`,
//!   `ath11k_qmi_request_target_cap`, `ath11k_qmi_load_bdf_qmi`,
//!   `ath11k_qmi_load_file_target_mem`, `ath11k_qmi_m3_load`,
//!   `ath11k_qmi_wlanfw_m3_info_send` (M3 from `firmware-N.bin` when it
//!   carries one, [`super::fw`]), `ath11k_qmi_process_coldboot_calibration`,
//!   `ath11k_qmi_firmware_start`, `ath11k_qmi_wlanfw_wlan_ini_send`,
//!   `ath11k_qmi_wlanfw_wlan_cfg_send`, `ath11k_qmi_wlanfw_mode_send`;
//! - `core.c`: `ath11k_core_fetch_bdf`, `ath11k_core_fetch_regdb`,
//!   `ath11k_core_fetch_board_data_api_1`, `ath11k_core_firmware_request`,
//!   `ath11k_core_create_firmware_path` (via [`super::board`]).
//!
//! After FW_READY the same machine keeps running on a registered device
//! ([`Wlfw::late_event`], [`Wlfw::run_to_fw_restart`]): SERVER_EXIT,
//! a second FW_INIT_DONE / FW_READY, COLD_BOOT_CAL_DONE and a restarted
//! firmware's handshake are handled as `ath11k_qmi_driver_event_work`
//! does once `ATH11K_FLAG_REGISTERED` is set.
//!
//! Not ported (not reached on PCIe WCN6855): `ath11k_qmi_assign_target_mem_chunk`
//! (`fixed_mem_region`), `ath11k_qmi_request_device_info`
//! (`hybrid_bus_type`), the `fixed_bdf_addr` ioremap path of
//! `load_file_target_mem`, `ath11k_qmi_fwreset_from_cold_boot`, FTM
//! mode. During the first bring-up a SERVER_EXIT ends the handshake with
//! an error (Linux waits for the server to return).
//!
//! Where Linux waits for an indication with no timeout (server
//! arrival, REQUEST_MEM, FW_MEM_READY, FW_READY) or stalls silently
//! (a memory-request callback that cannot allocate), NARF bounds the
//! wait and fails with a distinct [`step`] code: there is no serial
//! console on the target, so a hang must show on the panel.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::board::{
    self, bdf_search, fetch_board_data_api_n, regdb_search, BoardError, BoardId, BoardSearch,
    ATH11K_BD_IE_BOARD_DATA, ATH11K_BD_IE_BOARD_NAME, ATH11K_BOARD_API2_FILE,
    ATH11K_DEFAULT_CAL_FILE, ATH11K_M3_FILE,
};
use super::fw::FwApi;
use super::hw::HwRev;
use super::qmi::{QmiResponse, QMI_RESULT_SUCCESS_V01};
use super::qmi_client::{Inbound, QmiClient, QrtrPipe, TxnError};
use super::qmi_wlfw::*;

/// Failing-step codes latched into `narf_memory::diag` while the QMI
/// handshake runs (`WifiStage::Control`). Continues `mhi_host::step`
/// (10–35). Request failures carry `detail = kind << 16 | value`:
/// kind 1 timeout, 2 QMI result failure (value = QMI error code),
/// 3 decode, 4 encode, 5 UL send (value = errno), 6 not connected,
/// 7 QRTR flow-control timeout, 8 frame too large.
pub mod step {
    /// No firmware authority / loader (detail 0).
    pub const NO_FW_AUTHORITY: u32 = 40;
    /// The WLFW service never appeared (detail = QRTR HELLO seen).
    pub const SERVER_TIMEOUT: u32 = 41;
    /// The WLFW server left (DEL_SERVER / BYE) mid-handshake.
    pub const SERVER_EXIT: u32 = 42;
    pub const IND_REGISTER: u32 = 43;
    pub const HOST_CAP: u32 = 44;
    /// No REQUEST_MEM indication after host_cap (detail = rounds).
    pub const MEM_REQUEST_TIMEOUT: u32 = 45;
    /// `dma_alloc_coherent` failed with > 5 segments requested
    /// (detail = chunk size). Linux logs and stalls here.
    pub const TARGET_MEM_ALLOC: u32 = 46;
    pub const RESPOND_MEM: u32 = 47;
    /// No FW_MEM_READY after respond_mem.
    pub const MEM_READY_TIMEOUT: u32 = 48;
    pub const TARGET_CAP: u32 = 49;
    /// No board data found (detail = errno).
    pub const BDF_FETCH: u32 = 50;
    pub const BDF_DOWNLOAD: u32 = 51;
    /// No caldata (`cal-pci-<dev>.bin` / `caldata.bin`) for a BIN BDF.
    pub const CALDATA_FETCH: u32 = 52;
    pub const CALDATA_DOWNLOAD: u32 = 53;
    /// `m3.bin` missing (detail = errno).
    pub const M3_LOAD: u32 = 54;
    /// No DMA32 memory for the M3 image (detail = size).
    pub const M3_ALLOC: u32 = 55;
    pub const M3_INFO: u32 = 56;
    /// No FW_READY / FW_INIT_DONE after m3_info.
    pub const FW_READY_TIMEOUT: u32 = 57;
    pub const WLAN_INI: u32 = 58;
    pub const WLAN_CFG: u32 = 59;
    pub const WLAN_MODE: u32 = 60;
    /// Cold-boot calibration mode request failed.
    pub const COLDBOOT_MODE: u32 = 61;
    /// FW_INIT_DONE after registration outside a recovery (Linux queues
    /// `restart_work`; the runtime's recovery takes that path).
    pub const FW_RESTART: u32 = 62;
    /// `fixed_mem_region` / `hybrid_bus_type` part (not ported).
    pub const UNSUPPORTED: u32 = 63;
}

/// A bring-up failure: diag step + detail, and the Linux errno.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WlfwError {
    pub step: u32,
    pub detail: u32,
    pub errno: i32,
}

impl WlfwError {
    pub const fn new(step: u32, detail: u32, errno: i32) -> Self {
        Self {
            step,
            detail,
            errno,
        }
    }

    fn txn(step: u32, e: TxnError) -> Self {
        let value = match e {
            TxnError::Send(errno) => errno as u32 & 0xffff,
            _ => 0,
        };
        Self::new(step, e.kind() << 16 | value, e.errno())
    }

    /// `resp.result != QMI_RESULT_SUCCESS_V01` → `-EINVAL`.
    fn result(step: u32, r: QmiResponse) -> Self {
        Self::new(step, 2 << 16 | r.error as u32, 22)
    }
}

/// `-ENOENT`, `-ENOMEM`, `-ETIMEDOUT`, `-EINVAL`, `-EOPNOTSUPP`.
pub const ENOENT: i32 = 2;
pub const ENOMEM: i32 = 12;
pub const EINVAL: i32 = 22;
pub const ETIMEDOUT: i32 = 110;
pub const EOPNOTSUPP: i32 = 95;

/// `firmware_request_nowarn` for `ath11k/<dir>/<file>` paths.
pub trait FirmwareLoader {
    type Blob: AsRef<[u8]>;
    /// The file's bytes, or a positive errno (`ENOENT` when absent).
    fn request(&mut self, path: &str) -> Result<Self::Blob, i32>;
}

/// One `dma_alloc_coherent` allocation.
pub trait CoherentMem {
    /// The bus address handed to firmware.
    fn dma_addr(&self) -> u64;
    /// Bytes actually allocated (≥ the request).
    fn size(&self) -> usize;
    /// `memcpy(vaddr + off, data, len)`.
    fn write(&mut self, off: usize, data: &[u8]);
    /// CPU view of the coherent allocation. Crash collection uses this only
    /// after firmware has entered RDDM and before the reset can recycle the
    /// target-memory buffer.
    fn bytes(&self) -> &[u8];
}

/// `dma_alloc_coherent` on the device (coherent mask 32 bits).
pub trait DmaAllocator {
    type Mem: CoherentMem;
    /// `None` = allocation failure.
    fn alloc_coherent(&mut self, size: usize) -> Option<Self::Mem>;
}

/// The ath11k fields the handshake needs beyond [`WlfwHwParams`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WlfwConfig {
    pub hw_rev: HwRev,
    pub hw: WlfwHwParams,
    /// `hw_params.fw.dir`.
    pub fw_dir: &'static str,
    /// `ab->id` (+ variant); `chip_id` / `board_id` are filled from
    /// target_cap.
    pub board: BoardId,
    /// `dev_name(ab->dev)` — `"%04x:%02x:%02x.%d"` for PCI; names the
    /// `cal-pci-<dev>.bin` caldata file.
    pub dev_name: String,
    /// `ath11k_cold_boot_cal` module parameter (default 1).
    pub cold_boot_cal: bool,
    /// `ATH11K_QMI_WLANFW_TIMEOUT_MS` per transaction.
    pub txn_timeout_ms: u32,
    /// NARF-only bound on each indication / server wait.
    pub ind_timeout_ms: u32,
    /// `ATH11K_COLD_BOOT_FW_RESET_DELAY` (60 s).
    pub coldboot_timeout_ms: u32,
    /// `ATH11K_FLAG_FIXED_MEM_RGN`: the PCI function's Devicetree node has
    /// `memory-region` (`ath11k_pci_probe`); `Some(region)` carries the
    /// resolved `/reserved-memory` (base, size), `Some(None)` an
    /// unresolvable one (Linux then fails the assignment).
    pub fixed_mem_rgn: Option<Option<(u64, u64)>>,
}

/// `ATH11K_QMI_CALDB_ADDRESS`.
pub const ATH11K_QMI_CALDB_ADDRESS: u64 = 0x4BA0_0000;
/// `ATH11K_QMI_CALDB_SIZE`.
pub const ATH11K_QMI_CALDB_SIZE: u32 = 0x48_0000;

/// `ath11k_qmi_assign_target_mem_chunk` over the firmware's requested
/// `(type, size)` segments: HOST_DDR takes the reserved region (which
/// must hold it), BDF the hardware `bdf_addr`, CALDB the bytes after
/// HOST_DDR (or the fixed CALDB address without a region) when cold-boot
/// calibration is supported, else 0; other types are dropped ("qmi ignore
/// invalid mem req type"). Returns the compacted `(paddr, size, type)`
/// list; `Err` = the HOST_DDR region is missing or too small, or CALDB is
/// larger than `ATH11K_QMI_CALDB_SIZE`.
pub fn assign_fixed_target_mem(
    segments: &[(i32, u32)],
    region: Option<(u64, u64)>,
    bdf_addr: u64,
    coldboot_cal: bool,
) -> Result<Vec<(u64, u32, i32)>, i32> {
    let mut out = Vec::with_capacity(segments.len());
    let mut res: Option<(u64, u64)> = None;
    let mut host_ddr_sz = 0u64;
    for &(mem_type, size) in segments {
        match mem_type as u32 {
            HOST_DDR_REGION_TYPE => {
                // of_reserved_mem_region_to_resource / size check.
                let (start, len) = region.ok_or(ENOENT)?;
                if len < u64::from(size) {
                    return Err(EINVAL);
                }
                res = Some((start, len));
                host_ddr_sz = u64::from(size);
                out.push((start, size, mem_type));
            }
            BDF_MEM_REGION_TYPE => out.push((bdf_addr, size, mem_type)),
            CALDB_MEM_REGION_TYPE => {
                if size > ATH11K_QMI_CALDB_SIZE {
                    return Err(EINVAL);
                }
                let paddr = match (coldboot_cal, res) {
                    (true, Some((start, _))) => start + host_ddr_sz,
                    (true, None) => ATH11K_QMI_CALDB_ADDRESS,
                    (false, _) => 0,
                };
                out.push((paddr, size, mem_type));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// NARF-only: how long to wait for the server or an indication.
pub const ATH11K_NARF_IND_TIMEOUT_MS: u32 = 30_000;
/// `ATH11K_COLD_BOOT_FW_RESET_DELAY` = 60 * HZ.
pub const ATH11K_COLD_BOOT_FW_RESET_DELAY_MS: u32 = 60_000;

impl WlfwConfig {
    /// The values `ath11k_pci_probe` / `ath11k_core_init` give a PCI
    /// part: `bdf_search = ATH11K_BDF_SEARCH_BUS_AND_BOARD` only for
    /// WCN6855 (`17cb:1103`, incl. QCA2066 / QCA6698AQ).
    pub fn pci(
        hw_rev: HwRev,
        vendor: u16,
        device: u16,
        subsystem_vendor: u16,
        subsystem_device: u16,
        dev_name: String,
        bdf_ext: Vec<u8>,
    ) -> Option<Self> {
        Some(Self {
            hw_rev,
            hw: wlfw_hw_params(hw_rev)?,
            fw_dir: hw_rev.fw_dir()?,
            board: BoardId {
                search_bus_and_board: device == super::hw::ATH11K_DEV_WCN6855,
                vendor,
                device,
                subsystem_vendor,
                subsystem_device,
                chip_id: 0,
                board_id: 0,
                bdf_ext,
            },
            dev_name,
            cold_boot_cal: true,
            txn_timeout_ms: ATH11K_QMI_WLANFW_TIMEOUT_MS,
            ind_timeout_ms: ATH11K_NARF_IND_TIMEOUT_MS,
            coldboot_timeout_ms: ATH11K_COLD_BOOT_FW_RESET_DELAY_MS,
            fixed_mem_rgn: None,
        })
    }

    /// Apply the PCI function's Devicetree `memory-region` facts
    /// (`ATH11K_FLAG_FIXED_MEM_RGN`).
    pub fn with_fixed_mem_region(mut self, region: Option<(u64, u64)>) -> Self {
        self.fixed_mem_rgn = Some(region);
        self
    }

    /// `hw_params.fixed_mem_region || ATH11K_FLAG_FIXED_MEM_RGN`.
    pub fn fixed_mem(&self) -> bool {
        self.hw.fixed_mem_region || self.fixed_mem_rgn.is_some()
    }

    /// `ath11k_core_coldboot_cal_support` (FTM mode off).
    pub fn coldboot_cal_support(&self) -> bool {
        self.cold_boot_cal && self.hw.coldboot_cal_mm
    }
}

/// `enum ath11k_qmi_event_type` (the ones a PCIe part sees).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WlfwEvent {
    ServerArrive,
    ServerExit,
    RequestMem,
    FwMemReady,
    FwReady,
    FwInitDone,
}

/// What `ath11k_qmi_driver_event_work` does with events that arrive
/// after FW_READY on a registered device ([`Wlfw::late_event`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LateEvent {
    /// `ATH11K_QMI_EVENT_SERVER_EXIT`: CRASH_FLUSH + RECOVERY and
    /// `ath11k_core_pre_reconfigure_recovery`; the restarted firmware's
    /// handshake follows ([`Wlfw::run_to_fw_restart`]). Also reported for
    /// handshake events (SERVER_ARRIVE, REQUEST_MEM, FW_MEM_READY) that
    /// arrive with no SERVER_EXIT before them: the firmware restarted.
    ServerExit,
    /// FW_INIT_DONE, or FW_READY on a part without `cbcal_restart_fw`,
    /// with REGISTERED set: `queue_work(restart_work)`.
    Restart,
}

/// What the event loop is waiting for — names the timeout step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Server,
    MemRequest,
    MemReady,
    FwReady,
}

/// `struct target_mem_chunk`.
#[derive(Debug)]
pub struct TargetMemChunk<M> {
    pub size: u32,
    pub mem_type: i32,
    pub prev_size: u32,
    pub prev_type: i32,
    pub mem: Option<M>,
    /// The physical address of a fixed-memory assignment (no DMA buffer).
    pub fixed_paddr: Option<u64>,
}

impl<M> Default for TargetMemChunk<M> {
    fn default() -> Self {
        Self {
            size: 0,
            mem_type: 0,
            prev_size: 0,
            prev_type: 0,
            mem: None,
            fixed_paddr: None,
        }
    }
}

/// The board data `ath11k_core_fetch_bdf` settled on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardChoice {
    /// The board name matched in `board-2.bin`, or the API-1 file.
    pub name: String,
    /// 2 = `board-2.bin`, 1 = `board.bin`.
    pub api: u8,
    pub bdf_type: u8,
    /// Bytes sent (`min(board_size, len)`).
    pub sent: usize,
}

/// FW_READY reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwReadyInfo {
    pub target: TargetInfo,
    pub board: Option<BoardChoice>,
    pub regdb_sent: Option<usize>,
    pub m3_addr: u64,
    pub m3_size: u32,
    /// Target memory as handed to firmware: `(addr, size, type)`.
    pub target_mem: Vec<(u64, u32, i32)>,
    /// Number of delayed (empty) memory responses.
    pub mem_delayed_rounds: u32,
}

/// The handshake owner (Linux `struct ath11k_qmi` + the `ab` fields
/// it touches).
#[allow(missing_debug_implementations)]
pub struct Wlfw<P: QrtrPipe, F: FirmwareLoader, A: DmaAllocator> {
    pub client: QmiClient<P>,
    pub fw: F,
    pub dma: A,
    pub cfg: WlfwConfig,
    events: VecDeque<WlfwEvent>,
    /// A handler failed where Linux would only log and stall.
    fatal: Option<WlfwError>,
    pub target: TargetInfo,
    pub target_mem: Vec<TargetMemChunk<A::Mem>>,
    pub mem_seg_count: usize,
    pub target_mem_delayed: bool,
    pub mem_delayed_rounds: u32,
    pub m3: Option<A::Mem>,
    pub m3_size: u32,
    pub cal_done: u8,
    pub registered: bool,
    pub board_choice: Option<BoardChoice>,
    pub regdb_sent: Option<usize>,
    /// `ab->fw` (`ath11k_fw_pre_init`): the M3 IE of `firmware-N.bin`.
    pub fw_api: FwApi,
    phase: Phase,
    /// The event work is running for a crash recovery
    /// ([`Self::run_to_fw_restart`]).
    recovering: bool,
}

impl<P: QrtrPipe, F: FirmwareLoader, A: DmaAllocator> Wlfw<P, F, A> {
    /// `ath11k_qmi_init_service`: zeroed target info / memory,
    /// `target_mem_mode = fw_mem_mode` (carried in `cfg.hw`).
    pub fn new(pipe: P, fw: F, dma: A, cfg: WlfwConfig) -> Result<Self, WlfwError> {
        if cfg.hw.fixed_mem_region || cfg.hw.hybrid_bus_type || cfg.hw.fixed_bdf_addr {
            return Err(WlfwError::new(step::UNSUPPORTED, 0, EOPNOTSUPP));
        }
        let mut target_mem = Vec::with_capacity(ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01);
        target_mem.resize_with(
            ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
            TargetMemChunk::default,
        );
        Ok(Self {
            client: QmiClient::new(pipe),
            fw,
            dma,
            cfg,
            events: VecDeque::new(),
            fatal: None,
            target: TargetInfo::default(),
            target_mem,
            mem_seg_count: 0,
            target_mem_delayed: false,
            mem_delayed_rounds: 0,
            m3: None,
            m3_size: 0,
            cal_done: 0,
            registered: false,
            board_choice: None,
            regdb_sent: None,
            fw_api: FwApi::api1(),
            phase: Phase::Server,
            recovering: false,
        })
    }

    fn log(&self, args: core::fmt::Arguments<'_>) {
        self.client.pipe.log(args);
    }

    /// `ath11k_core_create_firmware_path` (no `firmware-name` DT
    /// property and no use-case firmware on PCI x86).
    pub fn fw_path(&self, file: &str) -> String {
        format!("ath11k/{}/{}", self.cfg.fw_dir, file)
    }

    // ── Indication handlers (qmi rx context in Linux) ─────────────

    /// Run the `ops` / `ath11k_qmi_msg_*_cb` handlers for everything
    /// received so far, posting driver events in order.
    pub fn drain_inbound(&mut self) {
        while let Some(ib) = self.client.take_inbound() {
            match ib {
                Inbound::ServerArrive(s) => {
                    self.log(format_args!(
                        "qmi: wifi fw qmi service connected (node {:#x} port {:#x})",
                        s.node, s.port
                    ));
                    self.events.push_back(WlfwEvent::ServerArrive);
                }
                Inbound::ServerExit(_) => {
                    self.log(format_args!("qmi: wifi fw del server"));
                    self.events.push_back(WlfwEvent::ServerExit);
                }
                Inbound::Message(raw) => match decode_indication(&raw) {
                    Ok(Some(WlfwIndication::RequestMem(m))) => self.mem_request_cb(&m),
                    Ok(Some(WlfwIndication::FwMemReady)) => {
                        self.events.push_back(WlfwEvent::FwMemReady)
                    }
                    Ok(Some(WlfwIndication::FwReady)) => {
                        if self.cal_done == 0 {
                            self.cal_done = 1;
                        }
                        self.events.push_back(WlfwEvent::FwReady);
                    }
                    Ok(Some(WlfwIndication::ColdBootCalDone)) => self.cal_done = 1,
                    Ok(Some(WlfwIndication::FwInitDone)) => {
                        self.events.push_back(WlfwEvent::FwInitDone)
                    }
                    Ok(None) => {}
                    Err(e) => self.log(format_args!(
                        "qmi: failed to decode incoming message: {:?}",
                        e
                    )),
                },
            }
        }
    }

    /// `ath11k_qmi_msg_mem_request_cb`.
    fn mem_request_cb(&mut self, msg: &RequestMemInd) {
        let n = msg.mem_seg.len();
        if n == 0 || n > ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01 {
            self.log(format_args!("qmi: invalid memory segment length: {}", n));
        }
        self.mem_seg_count = n;
        for (i, seg) in msg.mem_seg.iter().enumerate() {
            self.target_mem[i].mem_type = seg.mem_type;
            self.target_mem[i].size = seg.size;
            self.log(format_args!(
                "qmi: mem seg type {} size {}",
                seg.mem_type, seg.size
            ));
        }
        if self.cfg.fixed_mem() {
            // ath11k_qmi_assign_target_mem_chunk.
            let segments: Vec<(i32, u32)> = self
                .target_mem
                .iter()
                .take(self.mem_seg_count)
                .map(|c| (c.mem_type, c.size))
                .collect();
            let region = self.cfg.fixed_mem_rgn.flatten();
            match assign_fixed_target_mem(&segments, region, 0, self.cfg.coldboot_cal_support()) {
                Ok(list) => {
                    for (chunk, (paddr, size, mem_type)) in self.target_mem.iter_mut().zip(&list) {
                        chunk.mem = None;
                        chunk.fixed_paddr = Some(*paddr);
                        chunk.size = *size;
                        chunk.mem_type = *mem_type;
                    }
                    self.mem_seg_count = list.len();
                }
                Err(errno) => {
                    // "failed to assign qmi target memory", no event.
                    self.log(format_args!(
                        "qmi: failed to assign qmi target memory: -{}",
                        errno
                    ));
                    self.fatal
                        .get_or_insert(WlfwError::new(step::TARGET_MEM_ALLOC, 0, errno));
                    return;
                }
            }
            self.events.push_back(WlfwEvent::RequestMem);
            return;
        }
        if let Err(e) = self.alloc_target_mem_chunk() {
            // Linux: "failed to allocate qmi target memory", no event.
            self.log(format_args!(
                "qmi: failed to allocate qmi target memory: -{}",
                e.errno
            ));
            self.fatal.get_or_insert(e);
            return;
        }
        self.events.push_back(WlfwEvent::RequestMem);
    }

    /// `ath11k_qmi_free_target_mem_chunk`.
    fn free_target_mem_chunk(&mut self) {
        for chunk in self.target_mem.iter_mut().take(self.mem_seg_count) {
            chunk.mem = None;
        }
    }

    /// `ath11k_qmi_alloc_target_mem_chunk`.
    pub fn alloc_target_mem_chunk(&mut self) -> Result<(), WlfwError> {
        self.target_mem_delayed = false;
        let count = self.mem_seg_count;
        for i in 0..count {
            let chunk = &mut self.target_mem[i];
            if chunk.mem.is_some() {
                if chunk.prev_type == chunk.mem_type && chunk.prev_size == chunk.size {
                    continue;
                }
                if count <= ATH11K_QMI_FW_MEM_REQ_SEGMENT_CNT {
                    // "size/type mismatch ..., try later with small size"
                    self.target_mem_delayed = true;
                    return Ok(());
                }
                // cannot reuse the existing chunk
                chunk.mem = None;
            }
            let size = chunk.size;
            match self.dma.alloc_coherent(size as usize) {
                Some(m) => {
                    let chunk = &mut self.target_mem[i];
                    chunk.mem = Some(m);
                    chunk.prev_type = chunk.mem_type;
                    chunk.prev_size = chunk.size;
                }
                None => {
                    if count <= ATH11K_QMI_FW_MEM_REQ_SEGMENT_CNT {
                        self.log(format_args!(
                            "qmi: dma allocation failed ({} B type {}), will try later \
                             with small size",
                            size, self.target_mem[i].mem_type
                        ));
                        self.free_target_mem_chunk();
                        self.target_mem_delayed = true;
                        return Ok(());
                    }
                    self.log(format_args!(
                        "qmi: failed to allocate dma memory for qmi ({} B type {})",
                        size, self.target_mem[i].mem_type
                    ));
                    return Err(WlfwError::new(step::TARGET_MEM_ALLOC, size, EINVAL));
                }
            }
        }
        Ok(())
    }

    /// The memory list respond_mem would send now.
    pub fn target_mem_list(&self) -> Vec<(u64, u32, i32)> {
        self.target_mem
            .iter()
            .take(self.mem_seg_count)
            .map(|c| {
                (
                    c.fixed_paddr
                        .unwrap_or_else(|| c.mem.as_ref().map_or(0, |m| m.dma_addr())),
                    c.size,
                    c.mem_type,
                )
            })
            .collect()
    }

    // ── Requests ──────────────────────────────────────────────────

    async fn txn<Q: WlfwRequest, M: WlfwMessage>(
        &mut self,
        req: &Q,
        step: u32,
        what: &str,
    ) -> Result<M, WlfwError> {
        let t = self.cfg.txn_timeout_ms;
        let r = self.client.request::<Q, M>(req, t).await;
        // Handlers ran in Linux while the event work waited.
        self.drain_inbound();
        r.map_err(|e| {
            self.log(format_args!("qmi: failed to send/wait {}: {:?}", what, e));
            WlfwError::txn(step, e)
        })
    }

    fn check(&self, r: QmiResponse, step: u32, what: &str) -> Result<(), WlfwError> {
        if r.result != QMI_RESULT_SUCCESS_V01 {
            self.log(format_args!(
                "qmi: {} request failed: {} {}",
                what, r.result, r.error
            ));
            return Err(WlfwError::result(step, r));
        }
        Ok(())
    }

    /// `ath11k_qmi_fw_ind_register_send`.
    pub async fn fw_ind_register_send(&mut self) -> Result<(), WlfwError> {
        let req = IndRegisterReq::ath11k(&self.cfg.hw);
        let resp: IndRegisterResp = self
            .txn(&req, step::IND_REGISTER, "indication register")
            .await?;
        self.check(
            resp.resp,
            step::IND_REGISTER,
            "firmware indication register",
        )
    }

    /// `ath11k_qmi_host_cap_send`.
    pub async fn host_cap_send(&mut self) -> Result<(), WlfwError> {
        let req = HostCapReq::ath11k(&self.cfg.hw, self.cal_done);
        let resp: HostCapResp = self.txn(&req, step::HOST_CAP, "host capability").await?;
        self.check(resp.resp, step::HOST_CAP, "host capability")
    }

    /// `ath11k_qmi_respond_fw_mem_request`.
    pub async fn respond_fw_mem_request(&mut self) -> Result<(), WlfwError> {
        let delayed = !self.cfg.fixed_mem() && self.target_mem_delayed;
        let req = if delayed {
            self.log(format_args!(
                "qmi: delays mem_request {}",
                self.mem_seg_count
            ));
            RespondMemReq::default()
        } else {
            RespondMemReq {
                mem_seg: self
                    .target_mem_list()
                    .into_iter()
                    .map(|(addr, size, mem_type)| MemSegResp {
                        addr,
                        size,
                        mem_type,
                        restore: 0,
                    })
                    .collect(),
            }
        };
        let resp: RespondMemResp = self
            .txn(&req, step::RESPOND_MEM, "qmi memory request")
            .await?;
        if resp.resp.result != QMI_RESULT_SUCCESS_V01 {
            // the error response is expected when target_mem_delayed
            if delayed && resp.resp.error == 0 {
                self.mem_delayed_rounds += 1;
                return Ok(());
            }
            return self.check(resp.resp, step::RESPOND_MEM, "qmi respond memory");
        }
        if delayed {
            self.mem_delayed_rounds += 1;
        }
        Ok(())
    }

    /// `ath11k_qmi_request_target_cap` (+ the SMBIOS / DT variant
    /// checks, whose result `cfg.board.bdf_ext` already holds).
    pub async fn request_target_cap(&mut self) -> Result<(), WlfwError> {
        let resp: CapResp = self.txn(&CapReq, step::TARGET_CAP, "qmi cap").await?;
        self.check(resp.resp, step::TARGET_CAP, "qmi cap")?;
        self.target = TargetInfo::from_cap(&resp);
        let t = &self.target;
        self.log(format_args!(
            "chip_id {:#x} chip_family {:#x} board_id {:#x} soc_id {:#x}",
            t.chip_id, t.chip_family, t.board_id, t.soc_id
        ));
        self.log(format_args!(
            "fw_version {:#x} fw_build_timestamp {} fw_build_id {}",
            t.fw_version,
            Lossy(&t.fw_build_timestamp),
            Lossy(t.fw_build_id_display())
        ));
        if t.eeprom_caldata != 0 {
            self.log(format_args!("qmi: cal data supported from eeprom"));
        }
        self.cfg.board.chip_id = self.target.chip_id;
        self.cfg.board.board_id = self.target.board_id;
        Ok(())
    }

    /// `ath11k_qmi_load_file_target_mem` (no `fixed_bdf_addr`).
    pub async fn load_file_target_mem(
        &mut self,
        data: &[u8],
        file_type: u8,
        step: u32,
    ) -> Result<(), WlfwError> {
        let board_id = self.target.board_id;
        if file_type == ATH11K_QMI_FILE_TYPE_EEPROM {
            let req = bdf_eeprom_request(board_id);
            let resp: BdfDownloadResp = self.txn(&req, step, "board file download").await?;
            return self.check(resp.resp, step, "board file download");
        }
        for req in bdf_segments(data, board_id, file_type) {
            let resp: BdfDownloadResp = self.txn(&req, step, "board file download").await?;
            self.check(resp.resp, step, "board file download")?;
        }
        Ok(())
    }

    /// Run one board-data search (`ath11k_core_fetch_bdf` /
    /// `ath11k_core_fetch_regdb`): `(blob, offset, len, name, api)`.
    fn fetch_board(
        &mut self,
        search: &[BoardSearch],
        name_id: u32,
        data_id: u32,
    ) -> Result<(F::Blob, usize, usize, String, u8), i32> {
        let mut ret = ENOENT;
        for s in search {
            match s {
                BoardSearch::Api2 { name, ie_id } => {
                    let path = self.fw_path(ATH11K_BOARD_API2_FILE);
                    let blob = match self.fw.request(&path) {
                        Ok(b) => b,
                        Err(e) => {
                            ret = e;
                            continue;
                        }
                    };
                    match fetch_board_data_api_n(
                        blob.as_ref(),
                        name.as_bytes(),
                        *ie_id,
                        name_id,
                        data_id,
                    ) {
                        Ok((off, len)) => return Ok((blob, off, len, name.clone(), 2)),
                        Err(e) => {
                            if !matches!(e, BoardError::NoData) {
                                self.log(format_args!("{}: {:?}", path, e));
                            }
                            ret = e.errno();
                        }
                    }
                }
                BoardSearch::Api1 { file } => {
                    let path = self.fw_path(file);
                    match self.fw.request(&path) {
                        Ok(b) => {
                            let len = b.as_ref().len();
                            return Ok((b, 0, len, String::from(*file), 1));
                        }
                        Err(e) => ret = e,
                    }
                }
            }
        }
        Err(ret)
    }

    /// `ath11k_qmi_load_bdf_qmi(ab, regdb)`.
    pub async fn load_bdf_qmi(&mut self, regdb: bool) -> Result<(), WlfwError> {
        let id = self.cfg.board.clone();
        let fetched = if regdb {
            self.fetch_board(
                &regdb_search(&id),
                board::ATH11K_BD_IE_REGDB_NAME,
                board::ATH11K_BD_IE_REGDB_DATA,
            )
        } else {
            self.fetch_board(
                &bdf_search(&id),
                ATH11K_BD_IE_BOARD_NAME,
                ATH11K_BD_IE_BOARD_DATA,
            )
        };
        let (blob, off, len, name, api) = match fetched {
            Ok(f) => f,
            Err(e) => {
                if !regdb {
                    let path = self.fw_path(ATH11K_BOARD_API2_FILE);
                    for s in bdf_search(&id).iter() {
                        if let BoardSearch::Api2 { name, .. } = s {
                            self.log(format_args!(
                                "failed to fetch board data for {} from {}",
                                name, path
                            ));
                        }
                    }
                    self.log(format_args!(
                        "failed to fetch board.bin from {}",
                        self.cfg.fw_dir
                    ));
                    self.log(format_args!("qmi failed to fetch board file: -{}", e));
                }
                return Err(WlfwError::new(step::BDF_FETCH, e as u32, e));
            }
        };
        // One current owned snapshot for this operation. Source revocation
        // after the name parser ran may make a later AsRef empty; never trust
        // the old extent across that boundary or let it become a slice panic.
        let snapshot = blob.as_ref();
        let data = off
            .checked_add(len)
            .and_then(|end| snapshot.get(off..end))
            .filter(|data| !data.is_empty())
            .ok_or(WlfwError::new(step::BDF_FETCH, EINVAL as u32, EINVAL))?;
        let bdf_type = bdf_type_for(data, regdb);
        let fw_size = data.len().min(self.cfg.hw.board_size);
        self.log(format_args!(
            "qmi: {} '{}' (api {}) {} bytes, bdf_type {}",
            if regdb { "regdb" } else { "board" },
            name,
            api,
            len,
            bdf_type
        ));
        // (A regdb failure is logged and ignored by the caller.)
        if let Err(e) = self
            .load_file_target_mem(&data[..fw_size], bdf_type, step::BDF_DOWNLOAD)
            .await
        {
            self.log(format_args!("qmi failed to load bdf file"));
            return Err(e);
        }
        if regdb {
            self.regdb_sent = Some(fw_size);
        } else {
            self.board_choice = Some(BoardChoice {
                name,
                api,
                bdf_type,
                sent: fw_size,
            });
        }
        drop(blob);

        // QCA6390/WCN6855 does not support cal data, skip it
        if bdf_type == ATH11K_QMI_BDF_TYPE_ELF || bdf_type == ATH11K_QMI_BDF_TYPE_REGDB {
            return Ok(());
        }

        if self.target.eeprom_caldata != 0 {
            return self
                .load_file_target_mem(&[], ATH11K_QMI_FILE_TYPE_EEPROM, step::CALDATA_DOWNLOAD)
                .await
                .inspect_err(|_| self.log(format_args!("qmi failed to load caldata")));
        }
        // cal-<bus>-<id>.bin, then caldata.bin.
        let cal_name = format!("cal-{}-{}.bin", board::BUS_PCI, self.cfg.dev_name);
        let blob = match self.fw.request(&self.fw_path(&cal_name)) {
            Ok(b) => b,
            Err(_) => match self.fw.request(&self.fw_path(ATH11K_DEFAULT_CAL_FILE)) {
                Ok(b) => b,
                Err(e) => {
                    self.log(format_args!(
                        "qmi failed to load CAL data file:{}",
                        cal_name
                    ));
                    return Err(WlfwError::new(step::CALDATA_FETCH, e as u32, e));
                }
            },
        };
        let data = blob.as_ref();
        if data.is_empty() {
            return Err(WlfwError::new(step::CALDATA_FETCH, EINVAL as u32, EINVAL));
        }
        let fw_size = data.len().min(self.cfg.hw.board_size);
        self.load_file_target_mem(
            &data[..fw_size],
            ATH11K_QMI_FILE_TYPE_CALDATA,
            step::CALDATA_DOWNLOAD,
        )
        .await
        .inspect_err(|_| self.log(format_args!("qmi failed to load caldata")))
    }

    /// `ath11k_qmi_event_load_bdf`.
    pub async fn event_load_bdf(&mut self) -> Result<(), WlfwError> {
        self.request_target_cap().await?;
        // ath11k_qmi_request_device_info: hybrid-bus parts only.
        if self.cfg.hw.supports_regdb {
            // The result is ignored, as in Linux.
            let _ = self.load_bdf_qmi(true).await;
        }
        self.load_bdf_qmi(false).await
    }

    /// `ath11k_qmi_m3_load`: the DMA copy is made once ("m3 firmware
    /// buffer is already available"), from the `firmware-N.bin` M3 IE
    /// when it is non-empty, else from `m3.bin`.
    fn m3_load(&mut self) -> Result<(), WlfwError> {
        if self.m3.is_some() {
            return Ok(());
        }
        let blob;
        let data: &[u8] = match self.fw_api.m3() {
            // "firmware-N.bin had a m3 firmware file so use that"
            Some(m3) => m3,
            None => {
                let path = self.fw_path(ATH11K_M3_FILE);
                blob = self.fw.request(&path).map_err(|e| {
                    self.client
                        .pipe
                        .log(format_args!("failed to load {}: -{}", path, e));
                    WlfwError::new(step::M3_LOAD, e as u32, e)
                })?;
                blob.as_ref()
            }
        };
        if data.is_empty() {
            return Err(WlfwError::new(step::M3_LOAD, EINVAL as u32, EINVAL));
        }
        let Some(mut mem) = self.dma.alloc_coherent(data.len()) else {
            self.client.pipe.log(format_args!(
                "failed to allocate memory for M3 with size {}",
                data.len()
            ));
            return Err(WlfwError::new(step::M3_ALLOC, data.len() as u32, ENOMEM));
        };
        mem.write(0, data);
        self.m3_size = data.len() as u32;
        self.m3 = Some(mem);
        Ok(())
    }

    /// `ath11k_qmi_wlanfw_m3_info_send`.
    pub async fn m3_info_send(&mut self) -> Result<(), WlfwError> {
        let req = if self.cfg.hw.m3_fw_support {
            self.m3_load()?;
            M3InfoReq {
                addr: self.m3.as_ref().map_or(0, |m| m.dma_addr()),
                size: self.m3_size,
            }
        } else {
            M3InfoReq { addr: 0, size: 0 }
        };
        let resp: M3InfoResp = self.txn(&req, step::M3_INFO, "m3 information").await?;
        self.check(resp.resp, step::M3_INFO, "m3 info")
    }

    /// `ath11k_qmi_wlanfw_mode_send`.
    pub async fn mode_send(&mut self, mode: u32, step: u32) -> Result<(), WlfwError> {
        let req = WlanModeReq::ath11k(mode);
        let resp: WlanModeResp = self.txn(&req, step, "wlan mode").await?;
        self.check(resp.resp, step, "wlan mode")
    }

    /// `ath11k_qmi_wlanfw_wlan_ini_send(ab, enable)`.
    pub async fn wlan_ini_send(&mut self, enable: bool) -> Result<(), WlfwError> {
        let req = WlanIniReq::ath11k(enable);
        let resp: WlanIniResp = self.txn(&req, step::WLAN_INI, "wlan ini").await?;
        self.check(resp.resp, step::WLAN_INI, "qmi wlan ini")
    }

    /// `ath11k_qmi_wlanfw_wlan_cfg_send` with the CE / service maps of
    /// `hw_params` and the shadow-register v2 list the CE layer built
    /// (`ath11k_ce_get_shadow_config`).
    pub async fn wlan_cfg_send(&mut self, shadow_reg_v2: &[u32]) -> Result<(), WlfwError> {
        let req = WlanCfgReq::ath11k(
            &self.cfg.hw,
            &TARGET_CE_CONFIG_WLAN_QCA6390,
            &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
            shadow_reg_v2,
        );
        let resp: WlanCfgResp = self.txn(&req, step::WLAN_CFG, "wlan config").await?;
        self.check(resp.resp, step::WLAN_CFG, "wlan config")
    }

    /// `ath11k_qmi_firmware_start(ab, mode)` — what
    /// `ath11k_core_start_firmware` sends once the shadow config exists.
    pub async fn firmware_start(
        &mut self,
        mode: u32,
        shadow_reg_v2: &[u32],
    ) -> Result<(), WlfwError> {
        if self.cfg.hw.fw_wmi_diag_event {
            self.wlan_ini_send(true).await?;
        }
        self.wlan_cfg_send(shadow_reg_v2).await?;
        self.mode_send(mode, step::WLAN_MODE).await
    }

    /// `ath11k_qmi_event_server_arrive`.
    async fn event_server_arrive(&mut self) -> Result<(), WlfwError> {
        self.fw_ind_register_send().await?;
        self.host_cap_send().await?;
        self.phase = Phase::MemRequest;
        if !self.cfg.hw.fixed_fw_mem {
            return Ok(());
        }
        self.event_load_bdf().await
    }

    /// `ath11k_qmi_process_coldboot_calibration`.
    async fn process_coldboot_calibration(&mut self) -> Result<(), WlfwError> {
        self.mode_send(ATH11K_FIRMWARE_MODE_COLD_BOOT, step::COLDBOOT_MODE)
            .await?;
        let deadline = self.client.pipe.now_ms() + self.cfg.coldboot_timeout_ms as u64;
        while self.cal_done != 1 {
            let now = self.client.pipe.now_ms();
            if now >= deadline {
                // Linux warns and returns 0.
                self.log(format_args!("qmi: coldboot calibration timed out"));
                return Ok(());
            }
            self.client.wait_inbound((deadline - now) as u32).await;
            self.drain_inbound();
        }
        Ok(())
    }

    /// The bring-up half of `ath11k_qmi_driver_event_work`: lookup,
    /// then process events until FW_READY (or FW_INIT_DONE) — the
    /// point where Linux calls `ath11k_core_qmi_firmware_ready`.
    pub async fn run_to_fw_ready(&mut self) -> Result<FwReadyInfo, WlfwError> {
        self.client.add_lookup(
            ATH11K_QMI_WLFW_SERVICE_ID_V01,
            ATH11K_QMI_WLFW_SERVICE_VERS_V01,
            self.cfg.hw.qmi_service_ins_id,
        );
        self.phase = Phase::Server;
        self.event_loop().await?;
        Ok(self.ready_info())
    }

    /// Process events until one of them is the firmware-ready point.
    async fn event_loop(&mut self) -> Result<(), WlfwError> {
        loop {
            self.drain_inbound();
            if let Some(e) = self.fatal {
                return Err(e);
            }
            while let Some(ev) = self.events.pop_front() {
                if self.handle_event(ev).await? {
                    return Ok(());
                }
                if let Some(e) = self.fatal {
                    return Err(e);
                }
            }
            let t = self.cfg.ind_timeout_ms;
            if !self.client.wait_inbound(t).await {
                return Err(self.phase_timeout());
            }
        }
    }

    /// `ath11k_qmi_driver_event_work` for what arrived after FW_READY
    /// (the link is pumped and the QMI handlers run first: COLD_BOOT_CAL_DONE / FW_READY set
    /// `cal_done`, REQUEST_MEM allocated its chunks). Events that need
    /// the event work stay queued for [`Self::run_to_fw_restart`]; the
    /// returned [`LateEvent`] says how the device must recover. `None`:
    /// nothing to do.
    pub fn late_event(&mut self) -> Option<LateEvent> {
        self.client.pump();
        self.drain_inbound();
        // "For targets requiring a FW restart upon cold boot completion,
        // there is no need to process FW ready".
        if self.cfg.hw.cbcal_restart_fw {
            self.events.retain(|e| *e != WlfwEvent::FwReady);
        }
        if self.events.contains(&WlfwEvent::ServerExit) {
            return Some(LateEvent::ServerExit);
        }
        if self
            .events
            .iter()
            .any(|e| matches!(e, WlfwEvent::FwInitDone | WlfwEvent::FwReady))
        {
            return Some(LateEvent::Restart);
        }
        if !self.events.is_empty() || self.fatal.is_some() {
            self.log(format_args!(
                "qmi: firmware restarted without SERVER_EXIT ({:?})",
                self.events.front()
            ));
            return Some(LateEvent::ServerExit);
        }
        None
    }

    /// The MHI endpoint went away and came back (`ath11k_core_reset`'s
    /// power cycle): the QRTR node is gone (its server is reported
    /// exited), queued events belong to the dead firmware.
    pub fn endpoint_reset(&mut self) {
        self.events.clear();
        self.fatal = None;
        self.client.endpoint_reset();
    }

    /// The event work on a registered device after a crash: queued and
    /// arriving events run as in [`Self::run_to_fw_ready`] (SERVER_EXIT
    /// waits for the server; SERVER_ARRIVE → ind_register + host_cap with
    /// the current `cal_done`; REQUEST_MEM reuses chunks of the same size
    /// and type; the M3 copy is reused) until FW_INIT_DONE (or FW_READY)
    /// queues `restart_work`.
    pub async fn run_to_fw_restart(&mut self) -> Result<(), WlfwError> {
        self.recovering = true;
        self.fatal = None;
        self.phase = Phase::Server;
        let r = self.event_loop().await;
        self.recovering = false;
        if r.is_ok() {
            self.log(format_args!("qmi: firmware restarted, queueing restart"));
        }
        r
    }

    fn phase_timeout(&self) -> WlfwError {
        let (s, d) = match self.phase {
            Phase::Server => (step::SERVER_TIMEOUT, self.client.link().hello_seen() as u32),
            Phase::MemRequest => (step::MEM_REQUEST_TIMEOUT, self.mem_delayed_rounds),
            Phase::MemReady => (step::MEM_READY_TIMEOUT, 0),
            Phase::FwReady => (step::FW_READY_TIMEOUT, 0),
        };
        self.log(format_args!(
            "qmi: timed out waiting in phase {:?} ({} ms)",
            self.phase, self.cfg.ind_timeout_ms
        ));
        WlfwError::new(s, d, ETIMEDOUT)
    }

    /// One `switch (event->type)` arm; `Ok(true)` = firmware ready.
    async fn handle_event(&mut self, ev: WlfwEvent) -> Result<bool, WlfwError> {
        match ev {
            WlfwEvent::ServerArrive => {
                self.event_server_arrive().await?;
            }
            WlfwEvent::ServerExit => {
                // Linux sets CRASH_FLUSH | RECOVERY; in a recovery the
                // event work then waits for the server to come back.
                if self.recovering {
                    self.phase = Phase::Server;
                    return Ok(false);
                }
                return Err(WlfwError::new(step::SERVER_EXIT, self.phase as u32, 104));
            }
            WlfwEvent::RequestMem => {
                self.respond_fw_mem_request().await?;
                self.phase = if self.target_mem_delayed {
                    Phase::MemRequest
                } else {
                    Phase::MemReady
                };
            }
            WlfwEvent::FwMemReady => {
                self.event_load_bdf().await?;
                self.m3_info_send().await?;
                self.phase = Phase::FwReady;
            }
            WlfwEvent::FwInitDone => {
                if self.registered {
                    // queue_work(ab->workqueue, &ab->restart_work)
                    if self.recovering {
                        return Ok(true);
                    }
                    return Err(WlfwError::new(step::FW_RESTART, 0, EOPNOTSUPP));
                }
                if self.cal_done == 0 && self.cfg.coldboot_cal_support() {
                    self.process_coldboot_calibration().await?;
                } else {
                    self.registered = true;
                    return Ok(true);
                }
            }
            WlfwEvent::FwReady => {
                // Targets that restart after cold-boot calibration get
                // FW_INIT_DONE instead.
                if self.cfg.hw.cbcal_restart_fw {
                    return Ok(false);
                }
                // Registered (a recovery): Linux calls
                // ath11k_core_qmi_firmware_ready again; NARF takes the
                // restart path (spec §8).
                self.registered = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn ready_info(&self) -> FwReadyInfo {
        FwReadyInfo {
            target: self.target.clone(),
            board: self.board_choice.clone(),
            regdb_sent: self.regdb_sent,
            m3_addr: self.m3.as_ref().map_or(0, |m| m.dma_addr()),
            m3_size: self.m3_size,
            target_mem: self.target_mem_list(),
            mem_delayed_rounds: self.mem_delayed_rounds,
        }
    }
}

/// Bytes as text for the console (`%s` of a firmware string).
#[derive(Debug)]
pub struct Lossy<'a>(pub &'a [u8]);

impl core::fmt::Display for Lossy<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0 {
            if b == 0 {
                break;
            }
            let c = if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '?'
            };
            core::fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

// ── Kernel implementations ─────────────────────────────────────────

/// `dma_alloc_coherent` under `ATH11K_PCI_COHERENT_DMA_MASK`.
#[derive(Debug, Default)]
pub struct Dma32;

impl CoherentMem for narf_io::DmaBuffer {
    fn dma_addr(&self) -> u64 {
        narf_io::DmaBuffer::dma_addr(self).raw()
    }
    fn size(&self) -> usize {
        narf_io::DmaBuffer::len(self)
    }
    fn write(&mut self, off: usize, data: &[u8]) {
        self.as_mut_slice()[off..off + data.len()].copy_from_slice(data);
    }
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DmaAllocator for Dma32 {
    type Mem = narf_io::DmaBuffer;
    fn alloc_coherent(&mut self, size: usize) -> Option<narf_io::DmaBuffer> {
        if size == 0 {
            return None;
        }
        narf_io::alloc_coherent_masked(
            size,
            narf_lib::id::DomainId::DRIVER_0,
            super::mhi::ATH11K_PCI_COHERENT_DMA_MASK,
        )
        .ok()
    }
}

/// A firmware blob held open by its read cap.
#[derive(Debug)]
pub struct FwBlob(crate::firmware_asset::Asset);

impl AsRef<[u8]> for FwBlob {
    fn as_ref(&self) -> &[u8] {
        if self.0.current() {
            &self.0.bytes
        } else {
            &[]
        }
    }
}

/// `firmware_request_nowarn` against the NARF firmware registry.
#[derive(Debug)]
pub struct NarfFirmware {
    auth: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
}

impl NarfFirmware {
    /// `None` when no trusted loader authority exists yet.
    pub fn new() -> Option<Self> {
        let auth = narf_firmware::trusted_loader_authority()?.derive().ok()?;
        Some(Self { auth })
    }
}

impl FirmwareLoader for NarfFirmware {
    type Blob = FwBlob;
    fn request(&mut self, path: &str) -> Result<FwBlob, i32> {
        let file = path.rsplit('/').next().ok_or(EINVAL)?;
        let board = matches!(
            file,
            "board.bin" | "board-2.bin" | "regdb.bin" | "caldata.bin"
        ) || file.starts_with("cal-") && file.ends_with(".bin");
        crate::firmware_asset::load(&self.auth, path, 16 * 1024 * 1024, board)
            .map(FwBlob)
            .map_err(|error| match error {
                narf_firmware::FirmwareError::NotFound => ENOENT,
                narf_firmware::FirmwareError::OutOfMemory => ENOMEM,
                _ => EINVAL,
            })
    }
}

#[cfg(feature = "kernel-test")]
mod asset_authority_tests {
    use super::*;
    use crate::firmware_asset::tests::install;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_ath11k_board_calibration_regdb_require_signer_and_owned_blob_honors_epoch(
    ) -> TestResult {
        let (write, read) = narf_firmware::bootstrap_authority();
        let mut files = NarfFirmware { auth: read };
        for name in [
            "ath11k/narf-test/board-2.bin",
            "ath11k/narf-test/board.bin",
            "ath11k/narf-test/caldata.bin",
            "ath11k/narf-test/cal-pci-fffe:fc:1b.0.bin",
            "ath11k/narf-test/regdb.bin",
        ] {
            match install(&write, name, b"inert-board-policy", false) {
                Ok(()) => {
                    if files.request(name).is_ok() {
                        return TestResult::Fail(
                            "developer unsigned Qualcomm board/cal/regdb was admitted",
                        );
                    }
                }
                Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
                Err(_) => return TestResult::Fail("unexpected board fixture installation failure"),
            }
            install(&write, name, b"inert-board-policy", true).unwrap();
            let blob = files.request(name).unwrap();
            if blob.as_ref() != b"inert-board-policy" {
                return TestResult::Fail("signed board bytes changed during owned current copy");
            }
            blob.0.cap.revoke();
            if !blob.as_ref().is_empty() {
                return TestResult::Fail("revoked board cap still exposed active request bytes");
            }
        }
        let executable = "ath11k/narf-test/amss.bin";
        match install(&write, executable, b"inert-executable", false) {
            Ok(()) => {
                if files.request(executable).unwrap().as_ref() != b"inert-executable" {
                    return TestResult::Fail("explicit developer executable policy changed");
                }
            }
            Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
            Err(_) => {
                return TestResult::Fail("unexpected executable fixture installation failure")
            }
        }
        read.revoke();
        if files.request("ath11k/narf-test/board-2.bin").is_ok() {
            return TestResult::Fail("revoked ath11k registry read bypassed current invocation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath11k/wlfw",
        smoke_ath11k_board_calibration_regdb_require_signer_and_owned_blob_honors_epoch
    );
    // Revoke an actual installed blob cap precisely between board-offset
    // parsing and the operation's second snapshot. No borrowed registry view
    // or fabricated signer metadata participates in this fixture.
    struct RevokingBlob {
        blob: FwBlob,
        reads: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
        revoke_on: usize,
    }
    impl AsRef<[u8]> for RevokingBlob {
        fn as_ref(&self) -> &[u8] {
            let read = self
                .reads
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
                + 1;
            if read == self.revoke_on {
                self.blob.0.cap.revoke();
            }
            self.blob.as_ref()
        }
    }
    struct RevokingFiles {
        registry: NarfFirmware,
        reads: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
        revoke_on: usize,
        issued:
            Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
    }
    impl FirmwareLoader for RevokingFiles {
        type Blob = RevokingBlob;
        fn request(&mut self, path: &str) -> Result<Self::Blob, i32> {
            let blob = self.registry.request(path)?;
            self.issued = Some(blob.0.cap);
            Ok(RevokingBlob {
                blob,
                reads: self.reads.clone(),
                revoke_on: self.revoke_on,
            })
        }
    }
    struct NoTargetTraffic(alloc::sync::Arc<core::sync::atomic::AtomicUsize>);
    impl QrtrPipe for NoTargetTraffic {
        fn send(&mut self, _: &[u8]) -> Result<(), i32> {
            self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Err(EINVAL)
        }
        fn poll(&mut self) {}
        fn recv(&mut self) -> Option<Vec<u8>> {
            None
        }
        fn wait(&mut self, _: u32) -> impl core::future::Future<Output = ()> + Send {
            core::future::ready(())
        }
        fn now_ms(&self) -> u64 {
            0
        }
    }
    struct NoTargetDma(alloc::sync::Arc<core::sync::atomic::AtomicUsize>);
    impl DmaAllocator for NoTargetDma {
        type Mem = narf_io::DmaBuffer;
        fn alloc_coherent(&mut self, _: usize) -> Option<Self::Mem> {
            self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            None
        }
    }
    fn smoke_ath11k_actual_board_epoch_between_parse_and_snapshot_fails_before_target_io(
    ) -> TestResult {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let (write, read) = narf_firmware::bootstrap_authority();
        install(
            &write,
            "ath11k/narf-epoch-boundary/board.bin",
            b"inert-board-policy",
            true,
        )
        .unwrap();
        install(
            &write,
            "ath11k/narf-epoch-boundary/m3.bin",
            b"inert-m3",
            true,
        )
        .unwrap();
        for (file, revoke_on) in [("board", 2), ("m3", 1)] {
            let calls = alloc::sync::Arc::new(AtomicUsize::new(0));
            let reads = alloc::sync::Arc::new(AtomicUsize::new(0));
            let files = RevokingFiles {
                registry: NarfFirmware { auth: read },
                reads: reads.clone(),
                revoke_on,
                issued: None,
            };
            let mut cfg = WlfwConfig::pci(
                HwRev::Wcn6855Hw21,
                0x17cb,
                0x1103,
                0x17aa,
                0xffff,
                String::from("fffe:fc:1b.0"),
                Vec::new(),
            )
            .unwrap();
            cfg.fw_dir = "narf-epoch-boundary";
            let mut owner = Wlfw::new(
                NoTargetTraffic(calls.clone()),
                files,
                NoTargetDma(calls.clone()),
                cfg,
            )
            .unwrap();
            let (result, expected) = if file == "board" {
                let mut future = core::pin::pin!(owner.load_bdf_qmi(false));
                let result = match future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(value) => value,
                    Poll::Pending => return TestResult::Fail("revoked board reached target wait"),
                };
                (result, step::BDF_FETCH)
            } else {
                (owner.m3_load(), step::M3_LOAD)
            };
            if !matches!(result,Err(WlfwError {step,errno:EINVAL,..}) if step==expected)
                || reads.load(Ordering::Acquire) != revoke_on
                || owner
                    .fw
                    .issued
                    .is_none_or(|cap| cap.invoke(narf_capabilities::NoopOp).is_ok())
                || calls.load(Ordering::Acquire) != 0
                || owner.board_choice.is_some()
                || owner.m3.is_some()
                || owner.m3_size != 0
            {
                return TestResult::Fail(
                    "revoked owned blob panicked, published readiness, or reached target DMA/QMI",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath11k/wlfw",
        smoke_ath11k_actual_board_epoch_between_parse_and_snapshot_fails_before_target_io
    );
}

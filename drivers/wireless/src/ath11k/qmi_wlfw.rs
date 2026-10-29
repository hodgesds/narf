//! WLFW — the "WLAN firmware" QMI service ath11k talks to during
//! firmware bring-up.
//!
//! One codec per message ath11k sends or handles, built on
//! [`super::qmi`] and byte-identical to the `*_ei[]` tables in Linux
//! `drivers/net/wireless/ath/ath11k/qmi.c`: TLVs are emitted in ei
//! order, each with the `tlv_type`, width and count encoding its ei
//! entry names. Each struct's doc names the ei table it mirrors.
//!
//! Bring-up order (`ath11k_qmi_driver_event_work`), WCN6855:
//!
//! 1. QRTR `NEW_SERVER` for service `0x45` → [`IndRegisterReq`]
//!    then [`HostCapReq`].
//! 2. Firmware sends [`RequestMemInd`]; host answers
//!    [`RespondMemReq`] with the allocated chunks — or an empty list
//!    (`target_mem_delayed`) when a request of at most 5 segments
//!    could not be allocated, after which firmware asks again in
//!    smaller chunks.
//! 3. `FW_MEM_READY` indication → [`CapReq`] / [`CapResp`], regdb then
//!    board data via [`BdfDownloadReq`] segments, then
//!    [`M3InfoReq`].
//! 4. `FW_READY` / `FW_INIT_DONE` → [`WlanIniReq`] (if
//!    `fw_wmi_diag_event`), [`WlanCfgReq`], [`WlanModeReq`].
//!
//! Linux references (BSD-3-Clause-Clear, citation + adaptation
//! permitted):
//! - `drivers/net/wireless/ath/ath11k/qmi.{c,h}` — message structs,
//!   ei tables, ids, max lengths, and the `ath11k_qmi_*_send`
//!   functions whose field choices the `ath11k()` constructors copy.
//! - `drivers/net/wireless/ath/ath11k/core.c::ath11k_hw_params` —
//!   the per-chip flags in [`WlfwHwParams`].
//! - `drivers/net/wireless/ath/ath11k/hw.c` —
//!   `ath11k_target_ce_config_wlan_qca6390`,
//!   `ath11k_target_service_to_ce_map_wlan_qca6390`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::hw::HwRev;
use super::qmi::{
    decode_tlvs, encode_message, nested_var_struct_array, split_message, tlv_string, tlv_struct,
    tlv_u32, tlv_u64, tlv_u8, tlv_var_struct_array, LenSize, QmiError, QmiHeader, QmiResponse,
    StructReader, TlvWriter, QMI_INDICATION, QMI_REQUEST, QMI_RESPONSE, QMI_RESPONSE_TLV,
};

// ── Service ────────────────────────────────────────────────────────

/// `ATH11K_QMI_WLFW_SERVICE_ID_V01` — QRTR service number.
pub const ATH11K_QMI_WLFW_SERVICE_ID_V01: u32 = 0x45;
/// `ATH11K_QMI_WLFW_SERVICE_VERS_V01`.
pub const ATH11K_QMI_WLFW_SERVICE_VERS_V01: u32 = 0x01;
/// `ATH11K_QMI_WLFW_SERVICE_INS_ID_V01` (generic).
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01: u32 = 0x02;
/// Instance used by QCA6390 and the whole WCN6855 family.
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCA6390: u32 = 0x01;
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_IPQ8074: u32 = 0x02;
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCN9074: u32 = 0x07;
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750: u32 = 0x03;

/// `ATH11K_QMI_WLANFW_TIMEOUT_MS` — per-transaction wait.
pub const ATH11K_QMI_WLANFW_TIMEOUT_MS: u32 = 10_000;
/// `ATH11K_QMI_RESP_LEN_MAX` — the QMI handle's receive buffer.
pub const ATH11K_QMI_RESP_LEN_MAX: usize = 8192;
/// `QMI_WLANFW_CLIENT_ID` — `"LENK"` as a LE u32.
pub const QMI_WLANFW_CLIENT_ID: u32 = 0x4b4e_454c;
/// `ATH11K_HOST_VERSION_STRING`.
pub const ATH11K_HOST_VERSION_STRING: &[u8] = b"WIN";
/// `FW_BUILD_ID_MASK` — prefix stripped from `fw_build_id` for logs.
pub const FW_BUILD_ID_MASK: &[u8] = b"QC_IMAGE_VERSION_STRING=";

// ── Message ids (qmi.h) ────────────────────────────────────────────

pub const QMI_WLANFW_IND_REGISTER_REQ_V01: u16 = 0x0020;
pub const QMI_WLANFW_IND_REGISTER_RESP_V01: u16 = 0x0020;
pub const QMI_WLFW_FW_READY_IND_V01: u16 = 0x0021;
pub const QMI_WLANFW_WLAN_MODE_REQ_V01: u16 = 0x0022;
pub const QMI_WLANFW_WLAN_MODE_RESP_V01: u16 = 0x0022;
pub const QMI_WLANFW_WLAN_CFG_REQ_V01: u16 = 0x0023;
pub const QMI_WLANFW_WLAN_CFG_RESP_V01: u16 = 0x0023;
pub const QMI_WLANFW_CAP_REQ_V01: u16 = 0x0024;
pub const QMI_WLANFW_CAP_RESP_V01: u16 = 0x0024;
/// `ATH11K_QMI_DEVICE_BAR_SIZE`.
pub const ATH11K_QMI_DEVICE_BAR_SIZE: u32 = 0x20_0000;
pub const QMI_WLANFW_BDF_DOWNLOAD_REQ_V01: u16 = 0x0025;
pub const QMI_WLANFW_BDF_DOWNLOAD_RESP_V01: u16 = 0x0025;
pub const QMI_WLANFW_WLAN_INI_REQ_V01: u16 = 0x002F;
pub const QMI_WLANFW_WLAN_INI_RESP_V01: u16 = 0x002F;
pub const QMI_WLANFW_HOST_CAP_REQ_V01: u16 = 0x0034;
pub const QMI_WLFW_HOST_CAP_RESP_V01: u16 = 0x0034;
pub const QMI_WLFW_REQUEST_MEM_IND_V01: u16 = 0x0035;
pub const QMI_WLANFW_RESPOND_MEM_REQ_V01: u16 = 0x0036;
pub const QMI_WLANFW_RESPOND_MEM_RESP_V01: u16 = 0x0036;
pub const QMI_WLFW_FW_MEM_READY_IND_V01: u16 = 0x0037;
pub const QMI_WLFW_FW_INIT_DONE_IND_V01: u16 = 0x0038;
pub const QMI_WLANFW_M3_INFO_REQ_V01: u16 = 0x003C;
pub const QMI_WLANFW_M3_INFO_RESP_V01: u16 = 0x003C;
pub const QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01: u16 = 0x003E;
pub const QMI_WLANFW_DEVICE_INFO_REQ_V01: u16 = 0x004C;
pub const QMI_WLANFW_DEVICE_INFO_RESP_V01: u16 = 0x004C;

// ── Max lengths (qmi.h) ────────────────────────────────────────────

pub const QMI_WLANFW_HOST_CAP_REQ_MSG_V01_MAX_LEN: usize = 261;
pub const QMI_WLANFW_HOST_CAP_RESP_MSG_V01_MAX_LEN: usize = 7;
pub const QMI_WLANFW_IND_REGISTER_REQ_MSG_V01_MAX_LEN: usize = 54;
pub const QMI_WLANFW_IND_REGISTER_RESP_MSG_V01_MAX_LEN: usize = 18;
pub const QMI_WLANFW_REQUEST_MEM_IND_MSG_V01_MAX_LEN: usize = 1824;
pub const QMI_WLANFW_RESPOND_MEM_REQ_MSG_V01_MAX_LEN: usize = 888;
pub const QMI_WLANFW_RESPOND_MEM_RESP_MSG_V01_MAX_LEN: usize = 7;
pub const QMI_WLANFW_CAP_REQ_MSG_V01_MAX_LEN: usize = 0;
pub const QMI_WLANFW_CAP_RESP_MSG_V01_MAX_LEN: usize = 235;
pub const QMI_WLANFW_DEVICE_INFO_REQ_MSG_V01_MAX_LEN: usize = 0;
pub const QMI_WLANFW_BDF_DOWNLOAD_REQ_MSG_V01_MAX_LEN: usize = 6182;
pub const QMI_WLANFW_BDF_DOWNLOAD_RESP_MSG_V01_MAX_LEN: usize = 7;
pub const QMI_WLANFW_M3_INFO_REQ_MSG_V01_MAX_MSG_LEN: usize = 18;
pub const QMI_WLANFW_M3_INFO_RESP_MSG_V01_MAX_MSG_LEN: usize = 7;
pub const QMI_WLANFW_WLAN_MODE_REQ_MSG_V01_MAX_LEN: usize = 11;
pub const QMI_WLANFW_WLAN_MODE_RESP_MSG_V01_MAX_LEN: usize = 7;
pub const QMI_WLANFW_WLAN_CFG_REQ_MSG_V01_MAX_LEN: usize = 803;
pub const QMI_WLANFW_WLAN_CFG_RESP_MSG_V01_MAX_LEN: usize = 7;
pub const QMI_WLANFW_WLAN_INI_REQ_MSG_V01_MAX_LEN: usize = 4;

// ── Array bounds (qmi.h) ───────────────────────────────────────────

pub const QMI_WLFW_MAX_NUM_GPIO_V01: usize = 32;
pub const ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01: usize = 52;
pub const QMI_WLANFW_MAX_NUM_MEM_CFG_V01: usize = 2;
pub const ATH11K_QMI_WLANFW_MAX_TIMESTAMP_LEN_V01: usize = 32;
pub const ATH11K_QMI_WLANFW_MAX_BUILD_ID_LEN_V01: usize = 128;
pub const QMI_WLANFW_MAX_DATA_SIZE_V01: usize = 6144;
pub const QMI_WLANFW_MAX_STR_LEN_V01: usize = 16;
pub const QMI_WLANFW_MAX_NUM_CE_V01: usize = 12;
pub const QMI_WLANFW_MAX_NUM_SVC_V01: usize = 24;
pub const QMI_WLANFW_MAX_NUM_SHADOW_REG_V01: usize = 24;
pub const QMI_WLANFW_MAX_NUM_SHADOW_REG_V2_V01: usize = 36;
/// `ATH11K_QMI_MAX_BDF_FILE_NAME_SIZE` — the `data_len` ath11k sets
/// (with `data_valid = 0`) for an EEPROM caldata download.
pub const ATH11K_QMI_MAX_BDF_FILE_NAME_SIZE: usize = 64;

// ── Flags and enums ────────────────────────────────────────────────

/// `nm_modem` bit: sleep clock select internal.
pub const SLEEP_CLOCK_SELECT_INTERNAL_BIT: u8 = 0x02;
/// `nm_modem` bit: host is a non-Qualcomm platform.
pub const HOST_CSTATE_BIT: u8 = 0x04;
pub const PLATFORM_CAP_PCIE_GLOBAL_RESET: u8 = 0x08;
pub const PLATFORM_CAP_PCIE_PME_D3COLD: u8 = 0x10;

/// `enum ath11k_firmware_mode` (`core.h`) + `ATH11K_FIRMWARE_MODE_OFF`
/// (`qmi.h`) — the `mode` of [`WlanModeReq`].
pub const ATH11K_FIRMWARE_MODE_NORMAL: u32 = 0;
pub const ATH11K_FIRMWARE_MODE_FTM: u32 = 1;
pub const ATH11K_FIRMWARE_MODE_OFF: u32 = 4;
pub const ATH11K_FIRMWARE_MODE_COLD_BOOT: u32 = 7;

/// `enum ath11k_qmi_file_type` — the `bdf_type` ath11k passes for
/// caldata downloads.
pub const ATH11K_QMI_FILE_TYPE_BDF_GOLDEN: u8 = 0;
pub const ATH11K_QMI_FILE_TYPE_CALDATA: u8 = 2;
pub const ATH11K_QMI_FILE_TYPE_EEPROM: u8 = 3;

/// `enum ath11k_qmi_bdf_type`.
pub const ATH11K_QMI_BDF_TYPE_BIN: u8 = 0;
pub const ATH11K_QMI_BDF_TYPE_ELF: u8 = 1;
pub const ATH11K_QMI_BDF_TYPE_REGDB: u8 = 4;

/// `enum qmi_wlanfw_mem_type_enum_v01`.
pub const QMI_WLANFW_MEM_TYPE_MSA_V01: i32 = 0;
pub const QMI_WLANFW_MEM_TYPE_DDR_V01: i32 = 1;
pub const QMI_WLANFW_MEM_BDF_V01: i32 = 2;
pub const QMI_WLANFW_MEM_M3_V01: i32 = 3;
pub const QMI_WLANFW_MEM_CAL_V01: i32 = 4;
pub const QMI_WLANFW_MEM_DPD_V01: i32 = 5;
/// `PAGEABLE_MEM_REGION_TYPE`, included in Linux's ath11k device coredump.
pub const QMI_WLANFW_MEM_PAGEABLE_V01: i32 = 9;

/// Region types ath11k switches on in `assign_target_mem_chunk`.
pub const HOST_DDR_REGION_TYPE: u32 = 0x1;
pub const BDF_MEM_REGION_TYPE: u32 = 0x2;
pub const M3_DUMP_REGION_TYPE: u32 = 0x3;
pub const CALDB_MEM_REGION_TYPE: u32 = 0x4;
pub const PAGEABLE_MEM_REGION_TYPE: u32 = 0x9;
/// `ATH11K_QMI_FW_MEM_REQ_SEGMENT_CNT` — at or below this many
/// segments a failed allocation is answered "delayed" so firmware
/// retries with smaller chunks.
pub const ATH11K_QMI_FW_MEM_REQ_SEGMENT_CNT: usize = 5;

/// `enum qmi_wlanfw_pipedir_enum_v01` / ce.h `PIPEDIR_*`.
pub const PIPEDIR_NONE: u32 = 0;
pub const PIPEDIR_IN: u32 = 1;
pub const PIPEDIR_OUT: u32 = 2;
pub const PIPEDIR_INOUT: u32 = 3;
pub const PIPEDIR_INOUT_H2H: u32 = 4;

/// ce.h `CE_ATTR_DIS_INTR`.
pub const CE_ATTR_DIS_INTR: u32 = 8;
/// ce.h `CE_ATTR_FLAGS` — `0` on little-endian hosts (`CE_ATTR_BYTE_SWAP_DATA`
/// only under `__BIG_ENDIAN`); both NARF targets are little-endian.
pub const CE_ATTR_FLAGS: u32 = 0;

// ── Per-chip parameters ────────────────────────────────────────────

/// The `ath11k_hw_params` fields the QMI layer reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WlfwHwParams {
    pub qmi_service_ins_id: u32,
    pub m3_fw_support: bool,
    pub internal_sleep_clock: bool,
    pub global_reset: bool,
    /// `fw_mem_mode` → `qmi.target_mem_mode` → host-cap `mem_cfg_mode`.
    pub fw_mem_mode: u8,
    pub fixed_fw_mem: bool,
    pub fixed_bdf_addr: bool,
    pub supports_shadow_regs: bool,
    pub fw_wmi_diag_event: bool,
    pub supports_regdb: bool,
    /// `fw.board_size` — BDF / caldata are truncated to this.
    pub board_size: usize,
    /// `coldboot_cal_mm` — cold-boot calibration in mission mode
    /// (`ath11k_core_coldboot_cal_support` with `cold_boot_cal = 1`,
    /// `ftm_mode = 0`, the module defaults).
    pub coldboot_cal_mm: bool,
    /// `coldboot_cal_ftm`.
    pub coldboot_cal_ftm: bool,
    /// `cbcal_restart_fw` — FW_READY is ignored; FW_INIT_DONE follows
    /// a firmware restart.
    pub cbcal_restart_fw: bool,
    /// `fixed_mem_region` — target memory from a reserved region
    /// (AHB parts) instead of `dma_alloc_coherent`.
    pub fixed_mem_region: bool,
    /// `hybrid_bus_type` — sends DEVICE_INFO (WCN6750 only).
    pub hybrid_bus_type: bool,
    /// `bdf_addr` — the BDF_MEM segment / `fixed_bdf_addr` window.
    pub bdf_addr: u64,
    /// `fw.cal_offset` — caldata offset inside the `fixed_bdf_addr`
    /// window.
    pub cal_offset: usize,
}

/// QCA6390 and all WCN6855-family entries in `ath11k_hw_params`
/// differ only in `supports_regdb` among the fields above (none of
/// them does cold-boot calibration: `coldboot_cal_mm` /
/// `coldboot_cal_ftm` / `cbcal_restart_fw` are all false).
const QCA6390_FAMILY: WlfwHwParams = WlfwHwParams {
    qmi_service_ins_id: ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCA6390,
    m3_fw_support: true,
    internal_sleep_clock: true,
    global_reset: true,
    fw_mem_mode: 0,
    fixed_fw_mem: false,
    fixed_bdf_addr: false,
    supports_shadow_regs: true,
    fw_wmi_diag_event: true,
    supports_regdb: true,
    board_size: 256 * 1024,
    coldboot_cal_mm: false,
    coldboot_cal_ftm: false,
    cbcal_restart_fw: false,
    fixed_mem_region: false,
    hybrid_bus_type: false,
    bdf_addr: 0x4B0C_0000,
    cal_offset: 128 * 1024,
};

/// `ath11k_hw_params` QMI fields for `rev` (`core.c`).
pub fn wlfw_hw_params(rev: HwRev) -> Option<WlfwHwParams> {
    Some(match rev {
        HwRev::Qca6390Hw20 => WlfwHwParams {
            supports_regdb: false,
            ..QCA6390_FAMILY
        },
        HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
            QCA6390_FAMILY
        }
        HwRev::Qcn9074Hw10 => WlfwHwParams {
            qmi_service_ins_id: ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCN9074,
            m3_fw_support: true,
            internal_sleep_clock: false,
            global_reset: false,
            fw_mem_mode: 2,
            fixed_fw_mem: false,
            fixed_bdf_addr: false,
            supports_shadow_regs: false,
            fw_wmi_diag_event: false,
            supports_regdb: false,
            board_size: 256 * 1024,
            coldboot_cal_mm: false,
            coldboot_cal_ftm: true,
            cbcal_restart_fw: true,
            fixed_mem_region: false,
            hybrid_bus_type: false,
            bdf_addr: 0,
            cal_offset: 128 * 1024,
        },
        HwRev::Ipq8074 | HwRev::Ipq6018Hw10 | HwRev::Ipq5018Hw10 | HwRev::Wcn6750Hw10 => {
            return rev.ahb_chip().map(|c| c.wlfw_hw_params())
        }
        HwRev::Unknown => return None,
    })
}

// ── Message plumbing ───────────────────────────────────────────────

/// A request the host sends.
pub trait WlfwRequest {
    const MSG_ID: u16;
    /// The `*_MAX_LEN` ath11k passes to `qmi_send_request`.
    const MAX_LEN: usize;

    /// Append the TLVs in ei order.
    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError>;

    /// The TLV payload alone.
    fn payload(&self) -> Result<Vec<u8>, QmiError> {
        let mut w = TlvWriter::new(Self::MAX_LEN);
        self.write(&mut w)?;
        w.finish()
    }

    /// Header + payload — `qmi_send_request` → `qmi_encode_message`.
    fn encode(&self, txn_id: u16) -> Result<Vec<u8>, QmiError> {
        Ok(encode_message(
            QMI_REQUEST,
            Self::MSG_ID,
            txn_id,
            &self.payload()?,
        ))
    }
}

/// A response or indication the host decodes.
pub trait WlfwMessage: Sized {
    const MSG_TYPE: u8;
    const MSG_ID: u16;

    /// Decode the TLV payload (everything after the 7-byte header).
    fn decode_payload(payload: &[u8]) -> Result<Self, QmiError>;

    /// Decode a whole message, checking header `type` and `msg_id`.
    /// (Linux matches a response by `txn_id` alone; the transaction
    /// layer still has to compare `txn_id` itself.)
    fn decode(buf: &[u8]) -> Result<(QmiHeader, Self), QmiError> {
        let (hdr, payload) = split_message(buf)?;
        if hdr.msg_type != Self::MSG_TYPE || hdr.msg_id != Self::MSG_ID {
            return Err(QmiError::UnexpectedMessage {
                msg_type: hdr.msg_type,
                msg_id: hdr.msg_id,
            });
        }
        Ok((hdr, Self::decode_payload(payload)?))
    }
}

/// Decode a response whose ei table is just
/// `{ QMI_STRUCT resp, tlv 0x02 }`.
fn decode_resp_only(payload: &[u8]) -> Result<QmiResponse, QmiError> {
    let mut resp = QmiResponse::default();
    decode_tlvs(payload, &[QMI_RESPONSE_TLV], |_, v| {
        resp = QmiResponse::from_tlv(v)?;
        Ok(())
    })?;
    Ok(resp)
}

macro_rules! resp_only {
    ($(#[$m:meta])* $name:ident, $id:expr) => {
        $(#[$m])*
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name {
            pub resp: QmiResponse,
        }

        impl WlfwMessage for $name {
            const MSG_TYPE: u8 = QMI_RESPONSE;
            const MSG_ID: u16 = $id;

            fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
                Ok(Self {
                    resp: decode_resp_only(payload)?,
                })
            }
        }
    };
}

/// Decode a message whose ei table is empty (`QMI_EOTI` only).
fn decode_empty(payload: &[u8]) -> Result<(), QmiError> {
    decode_tlvs(payload, &[], |_, _| Ok(())).map(|_| ())
}

macro_rules! empty_ind {
    ($(#[$m:meta])* $name:ident, $id:expr) => {
        $(#[$m])*
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name;

        impl WlfwMessage for $name {
            const MSG_TYPE: u8 = QMI_INDICATION;
            const MSG_ID: u16 = $id;

            fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
                decode_empty(payload)?;
                Ok(Self)
            }
        }
    };
}

// ── host_cap (0x0034) ──────────────────────────────────────────────

/// `struct qmi_wlanfw_host_cap_req_msg_v01` /
/// `qmi_wlanfw_host_cap_req_msg_v01_ei`. Every field is an
/// `QMI_OPT_FLAG`-guarded optional; `None` = `*_valid == 0`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostCapReq {
    /// 0x10 u32.
    pub num_clients: Option<u32>,
    /// 0x11 u32.
    pub wake_msi: Option<u32>,
    /// 0x12 u8 count + u32[≤32].
    pub gpios: Option<Vec<u32>>,
    /// 0x13 u8.
    pub nm_modem: Option<u8>,
    /// 0x14 u8.
    pub bdf_support: Option<u8>,
    /// 0x15 u8.
    pub bdf_cache_support: Option<u8>,
    /// 0x16 u8.
    pub m3_support: Option<u8>,
    /// 0x17 u8.
    pub m3_cache_support: Option<u8>,
    /// 0x18 u8.
    pub cal_filesys_support: Option<u8>,
    /// 0x19 u8.
    pub cal_cache_support: Option<u8>,
    /// 0x1A u8.
    pub cal_done: Option<u8>,
    /// 0x1B u32.
    pub mem_bucket: Option<u32>,
    /// 0x1C u8.
    pub mem_cfg_mode: Option<u8>,
}

impl HostCapReq {
    /// Exactly the fields `ath11k_qmi_host_cap_send` sets:
    /// `num_clients = 1`, `mem_cfg_mode = target_mem_mode`,
    /// `bdf_support = 1`, `m3_support` + `m3_cache_support = 1` iff
    /// `m3_fw_support`, `cal_done` = the driver's cal_done flag, and —
    /// only when `internal_sleep_clock` — `nm_modem` = HOST_CSTATE |
    /// SLEEP_CLOCK_SELECT_INTERNAL | (GLOBAL_RESET if `global_reset`)
    /// | PME_D3COLD. (Linux ORs the last two bits in regardless, but
    /// they are only sent when `nm_modem_valid`.)
    ///
    /// WCN6855 HW2.1, first boot (`cal_done = 0`): 0x10=1, 0x13=0x1e,
    /// 0x14=1, 0x16=1, 0x17=1, 0x1A=0, 0x1C=0.
    pub fn ath11k(hw: &WlfwHwParams, cal_done: u8) -> Self {
        let mut nm_modem = 0u8;
        let mut nm_modem_valid = false;
        if hw.internal_sleep_clock {
            nm_modem_valid = true;
            nm_modem |= HOST_CSTATE_BIT;
            nm_modem |= SLEEP_CLOCK_SELECT_INTERNAL_BIT;
        }
        if hw.global_reset {
            nm_modem |= PLATFORM_CAP_PCIE_GLOBAL_RESET;
        }
        nm_modem |= PLATFORM_CAP_PCIE_PME_D3COLD;
        let m3 = if hw.m3_fw_support { Some(1) } else { None };
        Self {
            num_clients: Some(1),
            nm_modem: nm_modem_valid.then_some(nm_modem),
            bdf_support: Some(1),
            m3_support: m3,
            m3_cache_support: m3,
            cal_done: Some(cal_done),
            mem_cfg_mode: Some(hw.fw_mem_mode),
            ..Self::default()
        }
    }
}

impl WlfwRequest for HostCapReq {
    const MSG_ID: u16 = QMI_WLANFW_HOST_CAP_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_HOST_CAP_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.opt_u32(0x10, self.num_clients)
            .opt_u32(0x11, self.wake_msi);
        if let Some(g) = &self.gpios {
            w.var_u32_array(0x12, LenSize::U8, g, QMI_WLFW_MAX_NUM_GPIO_V01)?;
        }
        w.opt_u8(0x13, self.nm_modem)
            .opt_u8(0x14, self.bdf_support)
            .opt_u8(0x15, self.bdf_cache_support)
            .opt_u8(0x16, self.m3_support)
            .opt_u8(0x17, self.m3_cache_support)
            .opt_u8(0x18, self.cal_filesys_support)
            .opt_u8(0x19, self.cal_cache_support)
            .opt_u8(0x1A, self.cal_done)
            .opt_u32(0x1B, self.mem_bucket)
            .opt_u8(0x1C, self.mem_cfg_mode);
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_host_cap_resp_msg_v01_ei`.
    HostCapResp,
    QMI_WLFW_HOST_CAP_RESP_V01
);

// ── ind_register (0x0020) ──────────────────────────────────────────

/// `struct qmi_wlanfw_ind_register_req_msg_v01` /
/// `qmi_wlanfw_ind_register_req_msg_v01_ei`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IndRegisterReq {
    /// 0x10 u8.
    pub fw_ready_enable: Option<u8>,
    /// 0x11 u8.
    pub initiate_cal_download_enable: Option<u8>,
    /// 0x12 u8.
    pub initiate_cal_update_enable: Option<u8>,
    /// 0x13 u8.
    pub msa_ready_enable: Option<u8>,
    /// 0x14 u8.
    pub pin_connect_result_enable: Option<u8>,
    /// 0x15 u32.
    pub client_id: Option<u32>,
    /// 0x16 u8.
    pub request_mem_enable: Option<u8>,
    /// 0x17 u8.
    pub fw_mem_ready_enable: Option<u8>,
    /// 0x18 u8.
    pub fw_init_done_enable: Option<u8>,
    /// 0x19 — `u32` in the C struct, but the ei entry is
    /// `QMI_UNSIGNED_1_BYTE`, so one byte goes on the wire.
    pub rejuvenate_enable: Option<u8>,
    /// 0x1A u8.
    pub xo_cal_enable: Option<u8>,
    /// 0x1B u8.
    pub cal_done_enable: Option<u8>,
}

impl IndRegisterReq {
    /// The fields `ath11k_qmi_fw_ind_register_send` sets:
    /// client_id, fw_ready, cal_done, fw_init_done, and — unless
    /// `fixed_fw_mem` (WCN6750) — request_mem + fw_mem_ready.
    pub fn ath11k(hw: &WlfwHwParams) -> Self {
        let mem = if hw.fixed_fw_mem { None } else { Some(1) };
        Self {
            client_id: Some(QMI_WLANFW_CLIENT_ID),
            fw_ready_enable: Some(1),
            cal_done_enable: Some(1),
            fw_init_done_enable: Some(1),
            pin_connect_result_enable: None,
            request_mem_enable: mem,
            fw_mem_ready_enable: mem,
            ..Self::default()
        }
    }
}

impl WlfwRequest for IndRegisterReq {
    const MSG_ID: u16 = QMI_WLANFW_IND_REGISTER_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_IND_REGISTER_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.opt_u8(0x10, self.fw_ready_enable)
            .opt_u8(0x11, self.initiate_cal_download_enable)
            .opt_u8(0x12, self.initiate_cal_update_enable)
            .opt_u8(0x13, self.msa_ready_enable)
            .opt_u8(0x14, self.pin_connect_result_enable)
            .opt_u32(0x15, self.client_id)
            .opt_u8(0x16, self.request_mem_enable)
            .opt_u8(0x17, self.fw_mem_ready_enable)
            .opt_u8(0x18, self.fw_init_done_enable)
            .opt_u8(0x19, self.rejuvenate_enable)
            .opt_u8(0x1A, self.xo_cal_enable)
            .opt_u8(0x1B, self.cal_done_enable);
        Ok(())
    }
}

/// `struct qmi_wlanfw_ind_register_resp_msg_v01` /
/// `qmi_wlanfw_ind_register_resp_msg_v01_ei`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IndRegisterResp {
    /// 0x02.
    pub resp: QmiResponse,
    /// 0x10 u64.
    pub fw_status: Option<u64>,
}

impl WlfwMessage for IndRegisterResp {
    const MSG_TYPE: u8 = QMI_RESPONSE;
    const MSG_ID: u16 = QMI_WLANFW_IND_REGISTER_RESP_V01;

    fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
        let mut m = Self::default();
        decode_tlvs(payload, &[0x02, 0x10], |ty, v| {
            match ty {
                0x02 => m.resp = QmiResponse::from_tlv(v)?,
                _ => m.fw_status = Some(tlv_u64(ty, v)?),
            }
            Ok(())
        })?;
        Ok(m)
    }
}

// ── request_mem indication (0x0035) / respond_mem (0x0036) ─────────

/// `struct qmi_wlanfw_mem_cfg_s_v01` / `qmi_wlanfw_mem_cfg_s_v01_ei`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemCfg {
    pub offset: u64,
    pub size: u32,
    pub secure_flag: u8,
}

/// `struct qmi_wlanfw_mem_seg_s_v01` / `qmi_wlanfw_mem_seg_s_v01_ei`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemSeg {
    pub size: u32,
    /// `enum qmi_wlanfw_mem_type_enum_v01`, `QMI_SIGNED_4_BYTE_ENUM`.
    pub mem_type: i32,
    /// u8 count + up to [`QMI_WLANFW_MAX_NUM_MEM_CFG_V01`].
    pub mem_cfg: Vec<MemCfg>,
}

/// `struct qmi_wlanfw_request_mem_ind_msg_v01` /
/// `qmi_wlanfw_request_mem_ind_msg_v01_ei` — mandatory TLV 0x01:
/// u8 count + up to 52 [`MemSeg`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMemInd {
    pub mem_seg: Vec<MemSeg>,
}

fn read_mem_cfg(r: &mut StructReader<'_>) -> Result<MemCfg, QmiError> {
    Ok(MemCfg {
        offset: r.u64()?,
        size: r.u32()?,
        secure_flag: r.u8()?,
    })
}

fn read_mem_seg(r: &mut StructReader<'_>) -> Result<MemSeg, QmiError> {
    let size = r.u32()?;
    let mem_type = r.i32()?;
    let mem_cfg =
        nested_var_struct_array(r, LenSize::U8, QMI_WLANFW_MAX_NUM_MEM_CFG_V01, read_mem_cfg)?;
    Ok(MemSeg {
        size,
        mem_type,
        mem_cfg,
    })
}

impl WlfwMessage for RequestMemInd {
    const MSG_TYPE: u8 = QMI_INDICATION;
    const MSG_ID: u16 = QMI_WLFW_REQUEST_MEM_IND_V01;

    fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
        let mut m = Self::default();
        decode_tlvs(payload, &[0x01], |ty, v| {
            m.mem_seg = tlv_var_struct_array(
                ty,
                v,
                LenSize::U8,
                ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
                read_mem_seg,
            )?;
            Ok(())
        })?;
        Ok(m)
    }
}

impl RequestMemInd {
    /// Encode as firmware would (for tests and loopback models).
    pub fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.var_struct_array(
            0x01,
            LenSize::U8,
            self.mem_seg.len(),
            ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
            |s, i| {
                let seg = &self.mem_seg[i];
                s.u32(seg.size).i32(seg.mem_type);
                s.var_struct_array(
                    LenSize::U8,
                    seg.mem_cfg.len(),
                    QMI_WLANFW_MAX_NUM_MEM_CFG_V01,
                    |s, j| {
                        let c = &seg.mem_cfg[j];
                        s.u64(c.offset).u32(c.size).u8(c.secure_flag);
                        Ok(())
                    },
                )?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// `struct qmi_wlanfw_mem_seg_resp_s_v01` /
/// `qmi_wlanfw_mem_seg_resp_s_v01_ei` — 17 bytes on the wire.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemSegResp {
    pub addr: u64,
    pub size: u32,
    pub mem_type: i32,
    pub restore: u8,
}

/// `struct qmi_wlanfw_respond_mem_req_msg_v01` /
/// `qmi_wlanfw_respond_mem_req_msg_v01_ei` — mandatory TLV 0x01:
/// u8 count + up to 52 [`MemSegResp`]. An empty list is the
/// "delayed" answer `ath11k_qmi_respond_fw_mem_request` sends while
/// `target_mem_delayed`; firmware answers it with a failure response
/// whose `error == 0`, which ath11k treats as expected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RespondMemReq {
    pub mem_seg: Vec<MemSegResp>,
}

impl WlfwRequest for RespondMemReq {
    const MSG_ID: u16 = QMI_WLANFW_RESPOND_MEM_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_RESPOND_MEM_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.var_struct_array(
            0x01,
            LenSize::U8,
            self.mem_seg.len(),
            ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
            |s, i| {
                let m = &self.mem_seg[i];
                s.u64(m.addr).u32(m.size).i32(m.mem_type).u8(m.restore);
                Ok(())
            },
        )?;
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_respond_mem_resp_msg_v01_ei`.
    RespondMemResp,
    QMI_WLANFW_RESPOND_MEM_RESP_V01
);

empty_ind!(
    /// `qmi_wlanfw_mem_ready_ind_msg_v01_ei` (no TLVs).
    FwMemReadyInd,
    QMI_WLFW_FW_MEM_READY_IND_V01
);
empty_ind!(
    /// `qmi_wlanfw_fw_ready_ind_msg_v01_ei` (no TLVs).
    FwReadyInd,
    QMI_WLFW_FW_READY_IND_V01
);
empty_ind!(
    /// `qmi_wlanfw_cold_boot_cal_done_ind_msg_v01_ei` (no TLVs).
    ColdBootCalDoneInd,
    QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01
);
empty_ind!(
    /// `qmi_wlfw_fw_init_done_ind_msg_v01_ei` (no TLVs).
    FwInitDoneInd,
    QMI_WLFW_FW_INIT_DONE_IND_V01
);

// ── cap / target_cap (0x0024) ──────────────────────────────────────

/// `qmi_wlanfw_cap_req_msg_v01_ei` — no TLVs; the message is the
/// bare 7-byte header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapReq;

impl WlfwRequest for CapReq {
    const MSG_ID: u16 = QMI_WLANFW_CAP_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_CAP_REQ_MSG_V01_MAX_LEN;

    fn write(&self, _w: &mut TlvWriter) -> Result<(), QmiError> {
        Ok(())
    }
}

/// `struct qmi_wlanfw_rf_chip_info_s_v01`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RfChipInfo {
    pub chip_id: u32,
    pub chip_family: u32,
}

/// `struct qmi_wlanfw_fw_version_info_s_v01` — u32 + nested string
/// (u8 count, `elem_len` 33).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FwVersionInfo {
    pub fw_version: u32,
    pub fw_build_timestamp: Vec<u8>,
}

/// `struct qmi_wlanfw_cap_resp_msg_v01` /
/// `qmi_wlanfw_cap_resp_msg_v01_ei`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapResp {
    /// 0x02.
    pub resp: QmiResponse,
    /// 0x10 struct { u32 chip_id; u32 chip_family; }.
    pub chip_info: Option<RfChipInfo>,
    /// 0x11 struct { u32 board_id; }.
    pub board_id: Option<u32>,
    /// 0x12 struct { u32 soc_id; }.
    pub soc_id: Option<u32>,
    /// 0x13 struct { u32; string[33]; }.
    pub fw_version_info: Option<FwVersionInfo>,
    /// 0x14 top-level string, `elem_len` 129.
    pub fw_build_id: Option<Vec<u8>>,
    /// 0x15 u8.
    pub num_macs: Option<u8>,
    /// 0x16 u32.
    pub voltage_mv: Option<u32>,
    /// 0x17 u32.
    pub time_freq_hz: Option<u32>,
    /// 0x18 u32.
    pub otp_version: Option<u32>,
    /// 0x19 u32.
    pub eeprom_read_timeout: Option<u32>,
}

const FW_TIMESTAMP_ELEM_LEN: usize = ATH11K_QMI_WLANFW_MAX_TIMESTAMP_LEN_V01 + 1;
const FW_BUILD_ID_ELEM_LEN: usize = ATH11K_QMI_WLANFW_MAX_BUILD_ID_LEN_V01 + 1;

impl WlfwMessage for CapResp {
    const MSG_TYPE: u8 = QMI_RESPONSE;
    const MSG_ID: u16 = QMI_WLANFW_CAP_RESP_V01;

    fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
        let mut m = Self::default();
        let known = [
            0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        decode_tlvs(payload, &known, |ty, v| {
            match ty {
                0x02 => m.resp = QmiResponse::from_tlv(v)?,
                0x10 => {
                    m.chip_info = Some(tlv_struct(ty, v, |r| {
                        Ok(RfChipInfo {
                            chip_id: r.u32()?,
                            chip_family: r.u32()?,
                        })
                    })?)
                }
                0x11 => m.board_id = Some(tlv_struct(ty, v, |r| r.u32())?),
                0x12 => m.soc_id = Some(tlv_struct(ty, v, |r| r.u32())?),
                0x13 => {
                    m.fw_version_info = Some(tlv_struct(ty, v, |r| {
                        Ok(FwVersionInfo {
                            fw_version: r.u32()?,
                            fw_build_timestamp: r.string(FW_TIMESTAMP_ELEM_LEN)?,
                        })
                    })?)
                }
                0x14 => m.fw_build_id = Some(tlv_string(ty, v, FW_BUILD_ID_ELEM_LEN)?),
                0x15 => m.num_macs = Some(tlv_u8(ty, v)?),
                0x16 => m.voltage_mv = Some(tlv_u32(ty, v)?),
                0x17 => m.time_freq_hz = Some(tlv_u32(ty, v)?),
                0x18 => m.otp_version = Some(tlv_u32(ty, v)?),
                _ => m.eeprom_read_timeout = Some(tlv_u32(ty, v)?),
            }
            Ok(())
        })?;
        Ok(m)
    }
}

impl CapResp {
    /// Encode as firmware would (for tests and loopback models).
    pub fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.struct_tlv(0x02, |s| {
            s.u16(self.resp.result).u16(self.resp.error);
            Ok(())
        })?;
        if let Some(c) = self.chip_info {
            w.struct_tlv(0x10, |s| {
                s.u32(c.chip_id).u32(c.chip_family);
                Ok(())
            })?;
        }
        if let Some(b) = self.board_id {
            w.struct_tlv(0x11, |s| {
                s.u32(b);
                Ok(())
            })?;
        }
        if let Some(id) = self.soc_id {
            w.struct_tlv(0x12, |s| {
                s.u32(id);
                Ok(())
            })?;
        }
        if let Some(f) = &self.fw_version_info {
            w.struct_tlv(0x13, |s| {
                s.u32(f.fw_version)
                    .string(&f.fw_build_timestamp, FW_TIMESTAMP_ELEM_LEN)?;
                Ok(())
            })?;
        }
        if let Some(id) = &self.fw_build_id {
            w.string(0x14, id, FW_BUILD_ID_ELEM_LEN)?;
        }
        w.opt_u8(0x15, self.num_macs)
            .opt_u32(0x16, self.voltage_mv)
            .opt_u32(0x17, self.time_freq_hz)
            .opt_u32(0x18, self.otp_version)
            .opt_u32(0x19, self.eeprom_read_timeout);
        Ok(())
    }
}

/// `struct target_info` as `ath11k_qmi_request_target_cap` fills it
/// from a successful [`CapResp`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetInfo {
    pub chip_id: u32,
    pub chip_family: u32,
    /// `0xFF` when firmware sent no board_info.
    pub board_id: u32,
    pub soc_id: u32,
    pub fw_version: u32,
    /// `eeprom_read_timeout` when sent — non-zero selects EEPROM
    /// caldata in `ath11k_qmi_load_bdf_qmi`.
    pub eeprom_caldata: u32,
    pub fw_build_timestamp: Vec<u8>,
    pub fw_build_id: Vec<u8>,
}

impl TargetInfo {
    pub fn from_cap(cap: &CapResp) -> Self {
        let mut t = Self::default();
        if let Some(c) = cap.chip_info {
            t.chip_id = c.chip_id;
            t.chip_family = c.chip_family;
        }
        t.board_id = cap.board_id.unwrap_or(0xFF);
        if let Some(s) = cap.soc_id {
            t.soc_id = s;
        }
        if let Some(f) = &cap.fw_version_info {
            t.fw_version = f.fw_version;
            t.fw_build_timestamp = f.fw_build_timestamp.clone();
        }
        if let Some(id) = &cap.fw_build_id {
            t.fw_build_id = id.clone();
        }
        if let Some(e) = cap.eeprom_read_timeout {
            t.eeprom_caldata = e;
        }
        t
    }

    /// `fw_build_id` without the `QC_IMAGE_VERSION_STRING=` prefix,
    /// as ath11k logs it.
    pub fn fw_build_id_display(&self) -> &[u8] {
        self.fw_build_id
            .strip_prefix(FW_BUILD_ID_MASK)
            .unwrap_or(&self.fw_build_id)
    }
}

// ── device_info (0x004C, hybrid-bus parts only) ────────────────────

/// `qmi_wlanfw_device_info_req_msg_v01_ei` — no TLVs. ath11k sends it
/// only when `hw_params.hybrid_bus_type` (WCN6750), never on PCIe.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfoReq;

impl WlfwRequest for DeviceInfoReq {
    const MSG_ID: u16 = QMI_WLANFW_DEVICE_INFO_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_DEVICE_INFO_REQ_MSG_V01_MAX_LEN;

    fn write(&self, _w: &mut TlvWriter) -> Result<(), QmiError> {
        Ok(())
    }
}

/// `qmi_wlfw_device_info_resp_msg_v01_ei`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfoResp {
    pub resp: QmiResponse,
    /// 0x10 u64.
    pub bar_addr: Option<u64>,
    /// 0x11 u32.
    pub bar_size: Option<u32>,
}

impl WlfwMessage for DeviceInfoResp {
    const MSG_TYPE: u8 = QMI_RESPONSE;
    const MSG_ID: u16 = QMI_WLANFW_DEVICE_INFO_RESP_V01;

    fn decode_payload(payload: &[u8]) -> Result<Self, QmiError> {
        let mut m = Self::default();
        decode_tlvs(payload, &[0x02, 0x10, 0x11], |ty, v| {
            match ty {
                0x02 => m.resp = QmiResponse::from_tlv(v)?,
                0x10 => m.bar_addr = Some(tlv_u64(ty, v)?),
                _ => m.bar_size = Some(tlv_u32(ty, v)?),
            }
            Ok(())
        })?;
        Ok(m)
    }
}

// ── bdf_download (0x0025) ──────────────────────────────────────────

/// `struct qmi_wlanfw_bdf_download_req_msg_v01` /
/// `qmi_wlanfw_bdf_download_req_msg_v01_ei`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BdfDownloadReq<'a> {
    /// 0x01 u8, mandatory.
    pub valid: u8,
    /// 0x10 `enum qmi_wlanfw_cal_temp_id_enum_v01` (4 bytes). ath11k
    /// puts `target.board_id` here.
    pub file_id: Option<i32>,
    /// 0x11 u32 — the bytes remaining *including* this segment.
    pub total_size: Option<u32>,
    /// 0x12 u32.
    pub seg_id: Option<u32>,
    /// 0x13 u16 count + up to 6144 bytes.
    pub data: Option<&'a [u8]>,
    /// 0x14 u8.
    pub end: Option<u8>,
    /// 0x15 u8 — `ATH11K_QMI_BDF_TYPE_*` or `ATH11K_QMI_FILE_TYPE_*`.
    pub bdf_type: Option<u8>,
}

impl WlfwRequest for BdfDownloadReq<'_> {
    const MSG_ID: u16 = QMI_WLANFW_BDF_DOWNLOAD_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_BDF_DOWNLOAD_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.u8(0x01, self.valid)
            .opt_i32(0x10, self.file_id)
            .opt_u32(0x11, self.total_size)
            .opt_u32(0x12, self.seg_id);
        if let Some(d) = self.data {
            w.var_u8_array(0x13, LenSize::U16, d, QMI_WLANFW_MAX_DATA_SIZE_V01)?;
        }
        w.opt_u8(0x14, self.end).opt_u8(0x15, self.bdf_type);
        Ok(())
    }
}

/// `bdf_type` for a board file, as `ath11k_qmi_load_bdf_qmi` picks
/// it: REGDB for the regulatory db, ELF if the blob starts with
/// `\x7fELF`, else BIN.
pub fn bdf_type_for(data: &[u8], regdb: bool) -> u8 {
    if regdb {
        ATH11K_QMI_BDF_TYPE_REGDB
    } else if data.starts_with(b"\x7fELF") {
        ATH11K_QMI_BDF_TYPE_ELF
    } else {
        ATH11K_QMI_BDF_TYPE_BIN
    }
}

/// The segment sequence `ath11k_qmi_load_file_target_mem` sends for
/// `data` (already truncated to `board_size` by the caller, as
/// `ath11k_qmi_load_bdf_qmi` does), on a part without
/// `fixed_bdf_addr` and for any `bdf_type` but EEPROM. Segments are
/// at most 6144 bytes; `total_size` counts down; `seg_id` counts up
/// from 0; only the last has `end = 1`. Empty `data` sends nothing
/// (Linux's `while (remaining)` loop).
pub fn bdf_segments<'a>(
    data: &'a [u8],
    board_id: u32,
    bdf_type: u8,
) -> impl Iterator<Item = BdfDownloadReq<'a>> + 'a {
    data.chunks(QMI_WLANFW_MAX_DATA_SIZE_V01)
        .enumerate()
        .map(move |(i, chunk)| {
            let offset = i * QMI_WLANFW_MAX_DATA_SIZE_V01;
            let remaining = data.len() - offset;
            BdfDownloadReq {
                valid: 1,
                file_id: Some(board_id as i32),
                total_size: Some(remaining as u32),
                seg_id: Some(i as u32),
                data: Some(chunk),
                end: Some((remaining <= QMI_WLANFW_MAX_DATA_SIZE_V01) as u8),
                bdf_type: Some(bdf_type),
            }
        })
}

/// The single request `ath11k_qmi_load_file_target_mem` sends for
/// EEPROM caldata (`type == ATH11K_QMI_FILE_TYPE_EEPROM`): no data
/// TLV (`data_valid = 0`), `end = 1`, `total_size` = the
/// [`ATH11K_QMI_MAX_BDF_FILE_NAME_SIZE`] length ath11k passes.
pub fn bdf_eeprom_request(board_id: u32) -> BdfDownloadReq<'static> {
    BdfDownloadReq {
        valid: 1,
        file_id: Some(board_id as i32),
        total_size: Some(ATH11K_QMI_MAX_BDF_FILE_NAME_SIZE as u32),
        seg_id: Some(0),
        data: None,
        end: Some(1),
        bdf_type: Some(ATH11K_QMI_FILE_TYPE_EEPROM),
    }
}

/// The single request `ath11k_qmi_load_file_target_mem` sends on
/// `fixed_bdf_addr` parts after copying the file into the BDF window:
/// no data TLV, `end = 1`, `total_size` = the file length, segment 0.
pub fn bdf_fixed_addr_request(board_id: u32, len: u32, bdf_type: u8) -> BdfDownloadReq<'static> {
    BdfDownloadReq {
        valid: 1,
        file_id: Some(board_id as i32),
        total_size: Some(len),
        seg_id: Some(0),
        data: None,
        end: Some(1),
        bdf_type: Some(bdf_type),
    }
}

resp_only!(
    /// `qmi_wlanfw_bdf_download_resp_msg_v01_ei`.
    BdfDownloadResp,
    QMI_WLANFW_BDF_DOWNLOAD_RESP_V01
);

// ── m3_info (0x003C) ───────────────────────────────────────────────

/// `struct qmi_wlanfw_m3_info_req_msg_v01` — two mandatory TLVs:
/// 0x01 u64 DMA address, 0x02 u32 size of the `m3.bin` copy. ath11k
/// sends 0/0 on parts without `m3_fw_support`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct M3InfoReq {
    pub addr: u64,
    pub size: u32,
}

impl WlfwRequest for M3InfoReq {
    const MSG_ID: u16 = QMI_WLANFW_M3_INFO_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_M3_INFO_REQ_MSG_V01_MAX_MSG_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.u64(0x01, self.addr).u32(0x02, self.size);
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_m3_info_resp_msg_v01_ei`.
    M3InfoResp,
    QMI_WLANFW_M3_INFO_RESP_V01
);

// ── wlan_mode (0x0022) ─────────────────────────────────────────────

/// `struct qmi_wlanfw_wlan_mode_req_msg_v01`: 0x01 u32 mode
/// (mandatory), 0x10 u8 hw_debug.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WlanModeReq {
    pub mode: u32,
    pub hw_debug: Option<u8>,
}

impl WlanModeReq {
    /// `ath11k_qmi_wlanfw_mode_send`: `hw_debug_valid = 1`,
    /// `hw_debug = 0`.
    pub fn ath11k(mode: u32) -> Self {
        Self {
            mode,
            hw_debug: Some(0),
        }
    }
}

impl WlfwRequest for WlanModeReq {
    const MSG_ID: u16 = QMI_WLANFW_WLAN_MODE_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_WLAN_MODE_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.u32(0x01, self.mode).opt_u8(0x10, self.hw_debug);
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_wlan_mode_resp_msg_v01_ei`.
    WlanModeResp,
    QMI_WLANFW_WLAN_MODE_RESP_V01
);

// ── wlan_cfg (0x0023) ──────────────────────────────────────────────

/// `struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01` (20 bytes) — also the
/// sent subset of ce.h `struct ce_pipe_config` (whose `reserved`
/// word is not transmitted).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CeTgtPipeCfg {
    pub pipe_num: u32,
    /// `enum qmi_wlanfw_pipedir_enum_v01`.
    pub pipe_dir: u32,
    pub nentries: u32,
    pub nbytes_max: u32,
    pub flags: u32,
}

/// `struct qmi_wlanfw_ce_svc_pipe_cfg_s_v01` (12 bytes) / ce.h
/// `struct service_to_pipe`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CeSvcPipeCfg {
    pub service_id: u32,
    pub pipe_dir: u32,
    pub pipe_num: u32,
}

/// `struct qmi_wlanfw_shadow_reg_cfg_s_v01` (4 bytes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ShadowRegCfg {
    pub id: u16,
    pub offset: u16,
}

/// `struct qmi_wlanfw_wlan_cfg_req_msg_v01` /
/// `qmi_wlanfw_wlan_cfg_req_msg_v01_ei`. All TLVs optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WlanCfgReq<'a> {
    /// 0x10 top-level string, `elem_len` 17.
    pub host_version: Option<&'a [u8]>,
    /// 0x11 u8 count + up to 12 × 20 bytes.
    pub tgt_cfg: Option<&'a [CeTgtPipeCfg]>,
    /// 0x12 u8 count + up to 24 × 12 bytes.
    pub svc_cfg: Option<&'a [CeSvcPipeCfg]>,
    /// 0x13 u8 count + up to 24 × 4 bytes.
    pub shadow_reg: Option<&'a [ShadowRegCfg]>,
    /// 0x14 u8 count + up to 36 × u32 addresses.
    pub shadow_reg_v2: Option<&'a [u32]>,
}

impl<'a> WlanCfgReq<'a> {
    /// `ath11k_qmi_wlanfw_wlan_cfg_send`: host_version "WIN", the
    /// chip's target CE + service maps (sent even when empty),
    /// `shadow_reg_valid = 0`, and — iff `supports_shadow_regs` —
    /// the shadow v2 list clamped to 36 entries.
    pub fn ath11k(
        hw: &WlfwHwParams,
        tgt_ce: &'a [CeTgtPipeCfg],
        svc_map: &'a [CeSvcPipeCfg],
        shadow_reg_v2: &'a [u32],
    ) -> Self {
        Self {
            host_version: Some(ATH11K_HOST_VERSION_STRING),
            tgt_cfg: Some(tgt_ce),
            svc_cfg: Some(svc_map),
            shadow_reg: None,
            shadow_reg_v2: hw.supports_shadow_regs.then(|| {
                &shadow_reg_v2[..shadow_reg_v2
                    .len()
                    .min(QMI_WLANFW_MAX_NUM_SHADOW_REG_V2_V01)]
            }),
        }
    }
}

impl WlfwRequest for WlanCfgReq<'_> {
    const MSG_ID: u16 = QMI_WLANFW_WLAN_CFG_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_WLAN_CFG_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        if let Some(v) = self.host_version {
            w.string(0x10, v, QMI_WLANFW_MAX_STR_LEN_V01 + 1)?;
        }
        if let Some(t) = self.tgt_cfg {
            w.var_struct_array(
                0x11,
                LenSize::U8,
                t.len(),
                QMI_WLANFW_MAX_NUM_CE_V01,
                |s, i| {
                    let c = &t[i];
                    s.u32(c.pipe_num)
                        .u32(c.pipe_dir)
                        .u32(c.nentries)
                        .u32(c.nbytes_max)
                        .u32(c.flags);
                    Ok(())
                },
            )?;
        }
        if let Some(t) = self.svc_cfg {
            w.var_struct_array(
                0x12,
                LenSize::U8,
                t.len(),
                QMI_WLANFW_MAX_NUM_SVC_V01,
                |s, i| {
                    let c = &t[i];
                    s.u32(c.service_id).u32(c.pipe_dir).u32(c.pipe_num);
                    Ok(())
                },
            )?;
        }
        if let Some(t) = self.shadow_reg {
            w.var_struct_array(
                0x13,
                LenSize::U8,
                t.len(),
                QMI_WLANFW_MAX_NUM_SHADOW_REG_V01,
                |s, i| {
                    s.u16(t[i].id).u16(t[i].offset);
                    Ok(())
                },
            )?;
        }
        if let Some(t) = self.shadow_reg_v2 {
            w.var_struct_array(
                0x14,
                LenSize::U8,
                t.len(),
                QMI_WLANFW_MAX_NUM_SHADOW_REG_V2_V01,
                |s, i| {
                    s.u32(t[i]);
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_wlan_cfg_resp_msg_v01_ei`.
    WlanCfgResp,
    QMI_WLANFW_WLAN_CFG_RESP_V01
);

/// HTC service id: `SVC(group, idx)` (`htc.h`).
const fn htc_svc(group: u32, idx: u32) -> u32 {
    (group << 8) | idx
}
pub const ATH11K_HTC_SVC_ID_RSVD_CTRL: u32 = htc_svc(0, 1);
pub const ATH11K_HTC_SVC_ID_WMI_CONTROL: u32 = htc_svc(1, 0);
pub const ATH11K_HTC_SVC_ID_WMI_DATA_BE: u32 = htc_svc(1, 1);
pub const ATH11K_HTC_SVC_ID_WMI_DATA_BK: u32 = htc_svc(1, 2);
pub const ATH11K_HTC_SVC_ID_WMI_DATA_VI: u32 = htc_svc(1, 3);
pub const ATH11K_HTC_SVC_ID_WMI_DATA_VO: u32 = htc_svc(1, 4);
pub const ATH11K_HTC_SVC_ID_HTT_DATA_MSG: u32 = htc_svc(3, 0);

const fn tgt(
    pipe_num: u32,
    pipe_dir: u32,
    nentries: u32,
    nbytes_max: u32,
    flags: u32,
) -> CeTgtPipeCfg {
    CeTgtPipeCfg {
        pipe_num,
        pipe_dir,
        nentries,
        nbytes_max,
        flags,
    }
}

/// `ath11k_target_ce_config_wlan_qca6390` (`hw.c`) — the
/// `target_ce_config` of QCA6390 and every WCN6855-family part
/// (`target_ce_count = 9`; CE 9–11 belong to MHI).
pub const TARGET_CE_CONFIG_WLAN_QCA6390: [CeTgtPipeCfg; 9] = [
    tgt(0, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(1, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(2, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(4, PIPEDIR_OUT, 256, 256, CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
    tgt(5, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(6, PIPEDIR_INOUT, 32, 16384, CE_ATTR_FLAGS),
    tgt(7, PIPEDIR_INOUT_H2H, 0, 0, CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
    tgt(8, PIPEDIR_INOUT, 32, 16384, CE_ATTR_FLAGS),
];

const fn svc(service_id: u32, pipe_dir: u32, pipe_num: u32) -> CeSvcPipeCfg {
    CeSvcPipeCfg {
        service_id,
        pipe_dir,
        pipe_num,
    }
}

/// `ath11k_target_service_to_ce_map_wlan_qca6390` (`hw.c`) without
/// its all-zero terminator — `svc_to_ce_map_len = 14`.
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390: [CeSvcPipeCfg; 14] = [
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_VO, PIPEDIR_OUT, 3),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_VO, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_BK, PIPEDIR_OUT, 3),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_BK, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_BE, PIPEDIR_OUT, 3),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_BE, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_VI, PIPEDIR_OUT, 3),
    svc(ATH11K_HTC_SVC_ID_WMI_DATA_VI, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_WMI_CONTROL, PIPEDIR_OUT, 3),
    svc(ATH11K_HTC_SVC_ID_WMI_CONTROL, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_RSVD_CTRL, PIPEDIR_OUT, 0),
    svc(ATH11K_HTC_SVC_ID_RSVD_CTRL, PIPEDIR_IN, 2),
    svc(ATH11K_HTC_SVC_ID_HTT_DATA_MSG, PIPEDIR_OUT, 4),
    svc(ATH11K_HTC_SVC_ID_HTT_DATA_MSG, PIPEDIR_IN, 1),
];

// ── wlan_ini (0x002F) ──────────────────────────────────────────────

/// `struct qmi_wlanfw_wlan_ini_req_msg_v01`: 0x10 u8 enablefwlog.
/// ath11k sends it (enable = true) before wlan_cfg when
/// `fw_wmi_diag_event`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WlanIniReq {
    pub enablefwlog: Option<u8>,
}

impl WlanIniReq {
    /// `ath11k_qmi_wlanfw_wlan_ini_send(ab, enable)`.
    pub fn ath11k(enable: bool) -> Self {
        Self {
            enablefwlog: Some(enable as u8),
        }
    }
}

impl WlfwRequest for WlanIniReq {
    const MSG_ID: u16 = QMI_WLANFW_WLAN_INI_REQ_V01;
    const MAX_LEN: usize = QMI_WLANFW_WLAN_INI_REQ_MSG_V01_MAX_LEN;

    fn write(&self, w: &mut TlvWriter) -> Result<(), QmiError> {
        w.opt_u8(0x10, self.enablefwlog);
        Ok(())
    }
}

resp_only!(
    /// `qmi_wlanfw_wlan_ini_resp_msg_v01_ei`.
    WlanIniResp,
    QMI_WLANFW_WLAN_INI_RESP_V01
);

// ── Indication dispatch ────────────────────────────────────────────

/// An indication ath11k registers a handler for
/// (`ath11k_qmi_msg_handlers`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WlfwIndication {
    RequestMem(RequestMemInd),
    FwMemReady,
    FwReady,
    ColdBootCalDone,
    FwInitDone,
}

/// Dispatch a received indication the way `qmi_invoke_handler` does:
/// match `(type, msg_id)` against the handler table. `Ok(None)` for a
/// message no handler claims (Linux drops it silently), `Err` when
/// the claimed message fails to decode (Linux logs "failed to decode
/// incoming message" and drops it).
pub fn decode_indication(buf: &[u8]) -> Result<Option<WlfwIndication>, QmiError> {
    let (hdr, payload) = split_message(buf)?;
    if hdr.msg_type != QMI_INDICATION {
        return Ok(None);
    }
    Ok(Some(match hdr.msg_id {
        QMI_WLFW_REQUEST_MEM_IND_V01 => {
            WlfwIndication::RequestMem(RequestMemInd::decode_payload(payload)?)
        }
        QMI_WLFW_FW_MEM_READY_IND_V01 => {
            FwMemReadyInd::decode_payload(payload)?;
            WlfwIndication::FwMemReady
        }
        QMI_WLFW_FW_READY_IND_V01 => {
            FwReadyInd::decode_payload(payload)?;
            WlfwIndication::FwReady
        }
        QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01 => {
            ColdBootCalDoneInd::decode_payload(payload)?;
            WlfwIndication::ColdBootCalDone
        }
        QMI_WLFW_FW_INIT_DONE_IND_V01 => {
            FwInitDoneInd::decode_payload(payload)?;
            WlfwIndication::FwInitDone
        }
        _ => return Ok(None),
    }))
}

//! Modem Host Interface (MHI) — wire-level definitions.
//!
//! Everything the host and the device agree on: the MHI / BHI / BHIe
//! register maps and bit fields, the 16-byte ring element encodings
//! (transfer, command, event), the channel / event / command context
//! structures the host places in DMA memory, the protocol enums, and
//! the WCN6855 / QCA6390 controller configuration ath11k registers.
//! The host state machine that drives these lives in
//! [`super::mhi_host`].
//!
//! Linux references (GPL-2.0 / BSD-3-Clause-Clear):
//! - `drivers/bus/mhi/common.h` — registers, bit fields, ring element
//!   macros, context structs, `enum mhi_pkt_type` / `mhi_ev_ccs` /
//!   `mhi_ch_state` / `mhi_cmd_type`.
//! - `drivers/bus/mhi/host/internal.h` — `struct bhi_vec_entry`,
//!   `MHI_IN_PBL` & friends, PM state bits, `NR_OF_CMD_RINGS`,
//!   `CMD_EL_PER_RING`, `MHI_DEV_WAKE_DB`.
//! - `include/linux/mhi.h` — `enum mhi_ee_type`, `enum mhi_state`,
//!   `enum mhi_db_brst_mode`, `enum mhi_er_data_type`.
//! - `drivers/net/wireless/ath/ath11k/mhi.{c,h}` — channel / event
//!   tables, controller config, `PCIE_*VEC*` and `MHICTRL` offsets.

#![allow(dead_code)]

// ── ath11k `mhi.h` ─────────────────────────────────────────────────

pub const PCIE_TXVECDB: u32 = 0x360;
pub const PCIE_TXVECSTATUS: u32 = 0x368;
pub const PCIE_RXVECDB: u32 = 0x394;
pub const PCIE_RXVECSTATUS: u32 = 0x39C;

// ── MHI registers (`common.h`), offsets from BAR0 ─────────────────

pub const MHIREGLEN: u32 = 0x00;
pub const MHIVER: u32 = 0x08;
pub const MHICFG: u32 = 0x10;
pub const CHDBOFF: u32 = 0x18;
pub const ERDBOFF: u32 = 0x20;
pub const BHIOFF: u32 = 0x28;
pub const BHIEOFF: u32 = 0x2c;
pub const DEBUGOFF: u32 = 0x30;
pub const MHICTRL: u32 = 0x38;
pub const MHISTATUS: u32 = 0x48;
pub const CCABAP_LOWER: u32 = 0x58;
pub const CCABAP_HIGHER: u32 = 0x5c;
pub const ECABAP_LOWER: u32 = 0x60;
pub const ECABAP_HIGHER: u32 = 0x64;
pub const CRCBAP_LOWER: u32 = 0x68;
pub const CRCBAP_HIGHER: u32 = 0x6c;
pub const CRDB_LOWER: u32 = 0x70;
pub const CRDB_HIGHER: u32 = 0x74;
pub const MHICTRLBASE_LOWER: u32 = 0x80;
pub const MHICTRLBASE_HIGHER: u32 = 0x84;
pub const MHICTRLLIMIT_LOWER: u32 = 0x88;
pub const MHICTRLLIMIT_HIGHER: u32 = 0x8c;
pub const MHIDATABASE_LOWER: u32 = 0x98;
pub const MHIDATABASE_HIGHER: u32 = 0x9c;
pub const MHIDATALIMIT_LOWER: u32 = 0xa0;
pub const MHIDATALIMIT_HIGHER: u32 = 0xa4;

/// `internal.h` host request register (SoC reset).
pub const MHI_SOC_RESET_REQ_OFFSET: u32 = 0xb0;
pub const MHI_SOC_RESET_REQ: u32 = 1 << 0;

// ── BHI registers, offsets from `BHIOFF` ──────────────────────────

pub const BHI_BHIVERSION_MINOR: u32 = 0x00;
pub const BHI_BHIVERSION_MAJOR: u32 = 0x04;
pub const BHI_IMGADDR_LOW: u32 = 0x08;
pub const BHI_IMGADDR_HIGH: u32 = 0x0c;
pub const BHI_IMGSIZE: u32 = 0x10;
pub const BHI_RSVD1: u32 = 0x14;
pub const BHI_IMGTXDB: u32 = 0x18;
pub const BHI_RSVD2: u32 = 0x1c;
pub const BHI_INTVEC: u32 = 0x20;
pub const BHI_RSVD3: u32 = 0x24;
pub const BHI_EXECENV: u32 = 0x28;
pub const BHI_STATUS: u32 = 0x2c;
pub const BHI_ERRCODE: u32 = 0x30;
pub const BHI_ERRDBG1: u32 = 0x34;
pub const BHI_ERRDBG2: u32 = 0x38;
pub const BHI_ERRDBG3: u32 = 0x3c;
pub const BHI_SERIALNU: u32 = 0x40;
pub const BHI_SBLANTIROLLVER: u32 = 0x44;
pub const BHI_NUMSEG: u32 = 0x48;
pub const fn bhi_msmhwid(n: u32) -> u32 {
    0x4c + 4 * n
}
pub const fn bhi_oempkhash(n: u32) -> u32 {
    0x64 + 4 * n
}
pub const BHI_RSVD5: u32 = 0xc4;

pub const BHI_TXDB_SEQNUM_BMSK: u32 = genmask(29, 0);
pub const BHI_STATUS_MASK: u32 = genmask(31, 30);
pub const BHI_STATUS_ERROR: u32 = 0x03;
pub const BHI_STATUS_SUCCESS: u32 = 0x02;
pub const BHI_STATUS_RESET: u32 = 0x00;

// ── BHIe registers, offsets from `BHIEOFF` ────────────────────────

pub const BHIE_MSMSOCID_OFFS: u32 = 0x00;
pub const BHIE_TXVECADDR_LOW_OFFS: u32 = 0x2c;
pub const BHIE_TXVECADDR_HIGH_OFFS: u32 = 0x30;
pub const BHIE_TXVECSIZE_OFFS: u32 = 0x34;
pub const BHIE_TXVECDB_OFFS: u32 = 0x3c;
pub const BHIE_TXVECSTATUS_OFFS: u32 = 0x44;
pub const BHIE_RXVECADDR_LOW_OFFS: u32 = 0x60;
pub const BHIE_RXVECADDR_HIGH_OFFS: u32 = 0x64;
pub const BHIE_RXVECSIZE_OFFS: u32 = 0x68;
pub const BHIE_RXVECDB_OFFS: u32 = 0x70;
pub const BHIE_RXVECSTATUS_OFFS: u32 = 0x78;

pub const BHIE_TXVECDB_SEQNUM_BMSK: u32 = genmask(29, 0);
pub const BHIE_TXVECSTATUS_SEQNUM_BMSK: u32 = genmask(29, 0);
pub const BHIE_TXVECSTATUS_STATUS_BMSK: u32 = genmask(31, 30);
pub const BHIE_TXVECSTATUS_STATUS_RESET: u32 = 0x00;
pub const BHIE_TXVECSTATUS_STATUS_XFER_COMPL: u32 = 0x02;
pub const BHIE_TXVECSTATUS_STATUS_ERROR: u32 = 0x03;
pub const BHIE_RXVECSTATUS_STATUS_BMSK: u32 = genmask(31, 30);
pub const BHIE_RXVECSTATUS_STATUS_RESET: u32 = 0x00;
pub const BHIE_RXVECSTATUS_STATUS_XFER_COMPL: u32 = 0x02;
pub const BHIE_RXVECSTATUS_STATUS_ERROR: u32 = 0x03;

// ── MHI register bits ─────────────────────────────────────────────

pub const MHICFG_NHWER_MASK: u32 = genmask(31, 24);
pub const MHICFG_NER_MASK: u32 = genmask(23, 16);
pub const MHICFG_NHWCH_MASK: u32 = genmask(15, 8);
pub const MHICFG_NCH_MASK: u32 = genmask(7, 0);
pub const MHICTRL_MHISTATE_MASK: u32 = genmask(15, 8);
pub const MHICTRL_RESET_MASK: u32 = 1 << 1;
pub const MHISTATUS_MHISTATE_MASK: u32 = genmask(15, 8);
pub const MHISTATUS_SYSERR_MASK: u32 = 1 << 2;
pub const MHISTATUS_READY_MASK: u32 = 1 << 0;

/// Linux `GENMASK(h, l)` for 32-bit registers.
pub const fn genmask(h: u32, l: u32) -> u32 {
    (u32::MAX >> (31 - h)) & (u32::MAX << l)
}

/// Linux `FIELD_GET(mask, v)`.
pub const fn field_get(mask: u32, v: u32) -> u32 {
    (v & mask) >> mask.trailing_zeros()
}

/// Linux `FIELD_PREP(mask, v)`.
pub const fn field_prep(mask: u32, v: u32) -> u32 {
    (v << mask.trailing_zeros()) & mask
}

// ── Protocol enums ────────────────────────────────────────────────

/// `enum mhi_ee_type` (`include/linux/mhi.h`). A newtype, not a Rust
/// enum: `BHI_EXECENV` is read as a raw 32-bit value (Linux
/// `mhi_get_exec_env`) and the device may report anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MhiEe(pub u32);

impl MhiEe {
    pub const PBL: MhiEe = MhiEe(0);
    pub const SBL: MhiEe = MhiEe(1);
    pub const AMSS: MhiEe = MhiEe(2);
    pub const RDDM: MhiEe = MhiEe(3);
    pub const WFW: MhiEe = MhiEe(4);
    pub const PTHRU: MhiEe = MhiEe(5);
    pub const EDL: MhiEe = MhiEe(6);
    pub const FP: MhiEe = MhiEe(7);
    pub const MAX_SUPPORTED: MhiEe = MhiEe::FP;
    /// Local EE, not part of the MHI spec.
    pub const DISABLE_TRANSITION: MhiEe = MhiEe(8);
    pub const NOT_SUPPORTED: MhiEe = MhiEe(9);
    pub const MAX: MhiEe = MhiEe(10);

    /// `TO_MHI_EXEC_STR` (`mhi_ee_str[]`).
    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "PRIMARY BOOTLOADER",
            1 => "SECONDARY BOOTLOADER",
            2 => "MISSION MODE",
            3 => "RAMDUMP DOWNLOAD MODE",
            4 => "WLAN FIRMWARE",
            5 => "PASS THROUGH",
            6 => "EMERGENCY DOWNLOAD",
            7 => "FLASH PROGRAMMER",
            8 => "DISABLE",
            9 => "NOT SUPPORTED",
            _ => "INVALID_EE",
        }
    }

    /// `MHI_IN_PBL`.
    pub fn in_pbl(self) -> bool {
        matches!(self, MhiEe::PBL | MhiEe::PTHRU | MhiEe::EDL)
    }
    /// `MHI_POWER_UP_CAPABLE`.
    pub fn power_up_capable(self) -> bool {
        self.in_pbl() || self == MhiEe::AMSS
    }
    /// `MHI_FW_LOAD_CAPABLE`.
    pub fn fw_load_capable(self) -> bool {
        matches!(self, MhiEe::PBL | MhiEe::EDL)
    }
    /// `MHI_IN_MISSION_MODE`.
    pub fn in_mission_mode(self) -> bool {
        matches!(self, MhiEe::AMSS | MhiEe::WFW | MhiEe::FP)
    }
    /// `BIT(ee)` as used against a channel's `ee_mask`; 0 for an EE
    /// that does not fit in the mask word.
    pub fn bit(self) -> u32 {
        if self.0 < 32 {
            1 << self.0
        } else {
            0
        }
    }
}

/// `enum mhi_state` (`include/linux/mhi.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MhiState(pub u32);

impl MhiState {
    pub const RESET: MhiState = MhiState(0x0);
    pub const READY: MhiState = MhiState(0x1);
    pub const M0: MhiState = MhiState(0x2);
    pub const M1: MhiState = MhiState(0x3);
    pub const M2: MhiState = MhiState(0x4);
    pub const M3: MhiState = MhiState(0x5);
    pub const M3_FAST: MhiState = MhiState(0x6);
    pub const BHI: MhiState = MhiState(0x7);
    pub const SYS_ERR: MhiState = MhiState(0xff);
    pub const MAX: MhiState = MhiState(0x100);

    /// `mhi_state_str`.
    pub fn name(self) -> &'static str {
        match self {
            MhiState::RESET => "RESET",
            MhiState::READY => "READY",
            MhiState::M0 => "M0",
            MhiState::M1 => "M1",
            MhiState::M2 => "M2",
            MhiState::M3 => "M3",
            MhiState::M3_FAST => "M3_FAST",
            MhiState::BHI => "BHI",
            MhiState::SYS_ERR => "SYS ERROR",
            _ => "Unknown state",
        }
    }
}

/// `enum mhi_pkt_type` (`common.h`) — the TYPE field of a ring element.
pub mod pkt {
    pub const INVALID: u32 = 0x0;
    pub const NOOP_CMD: u32 = 0x1;
    pub const TRANSFER: u32 = 0x2;
    pub const COALESCING: u32 = 0x8;
    pub const RESET_CHAN_CMD: u32 = 0x10;
    pub const STOP_CHAN_CMD: u32 = 0x11;
    pub const START_CHAN_CMD: u32 = 0x12;
    pub const STATE_CHANGE_EVENT: u32 = 0x20;
    pub const CMD_COMPLETION_EVENT: u32 = 0x21;
    pub const TX_EVENT: u32 = 0x22;
    pub const RSC_TX_EVENT: u32 = 0x28;
    pub const EE_EVENT: u32 = 0x40;
    pub const TSYNC_EVENT: u32 = 0x48;
    pub const BW_REQ_EVENT: u32 = 0x50;
    /// Host-internal.
    pub const STALE_EVENT: u32 = 0x51;
}

/// `enum mhi_ev_ccs` — completion codes.
pub mod ccs {
    pub const INVALID: u32 = 0x0;
    pub const SUCCESS: u32 = 0x1;
    pub const EOT: u32 = 0x2;
    pub const OVERFLOW: u32 = 0x3;
    pub const EOB: u32 = 0x4;
    pub const OOB: u32 = 0x5;
    pub const DB_MODE: u32 = 0x6;
    pub const UNDEFINED_ERR: u32 = 0x10;
    pub const BAD_TRE: u32 = 0x11;
}

/// `enum mhi_ch_state`.
pub mod ch_state {
    pub const DISABLED: u32 = 0;
    pub const ENABLED: u32 = 1;
    pub const RUNNING: u32 = 2;
    pub const SUSPENDED: u32 = 3;
    pub const STOP: u32 = 4;
    pub const ERROR: u32 = 5;
}

/// `enum mhi_cmd_type`.
pub mod cmd {
    pub const NOP: u32 = 1;
    pub const RESET_CHAN: u32 = 16;
    pub const STOP_CHAN: u32 = 17;
    pub const START_CHAN: u32 = 18;
}

/// `enum mhi_db_brst_mode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BrstMode {
    Disable = 0x2,
    Enable = 0x3,
}

/// `enum dma_data_direction` values used as channel direction and,
/// via `parse_ch_cfg`, as the channel context `chtype`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DmaDir {
    ToDevice = 1,
    FromDevice = 2,
}

/// `enum mhi_er_data_type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErDataType {
    Data = 0,
    Ctrl = 1,
}

/// `enum mhi_er_type`.
pub const MHI_ER_TYPE_INVALID: u32 = 0;
pub const MHI_ER_TYPE_VALID: u32 = 1;

/// `internal.h`.
pub const NR_OF_CMD_RINGS: usize = 1;
pub const CMD_EL_PER_RING: usize = 128;
pub const PRIMARY_CMD_RING: usize = 0;
pub const MHI_DEV_WAKE_DB: u32 = 127;
pub const MHI_MAX_MTU: u32 = 0xffff;
pub const MHI_TIMEOUT_MS: u32 = 1000;

// ── Internal PM states (`internal.h`) ─────────────────────────────

/// `MHI_PM_*` — one bit per `enum mhi_pm_state`.
pub mod pm {
    pub const DISABLE: u32 = 1 << 0;
    pub const POR: u32 = 1 << 1;
    pub const M0: u32 = 1 << 2;
    pub const M2: u32 = 1 << 3;
    pub const M3_ENTER: u32 = 1 << 4;
    pub const M3: u32 = 1 << 5;
    pub const M3_EXIT: u32 = 1 << 6;
    pub const FW_DL_ERR: u32 = 1 << 7;
    pub const SYS_ERR_DETECT: u32 = 1 << 8;
    pub const SYS_ERR_PROCESS: u32 = 1 << 9;
    pub const SYS_ERR_FAIL: u32 = 1 << 10;
    pub const SHUTDOWN_PROCESS: u32 = 1 << 11;
    pub const LD_ERR_FATAL_DETECT: u32 = 1 << 12;

    /// `MHI_REG_ACCESS_VALID`.
    pub const fn reg_access_valid(s: u32) -> bool {
        s & (POR
            | M0
            | M2
            | M3_ENTER
            | M3_EXIT
            | SYS_ERR_DETECT
            | SYS_ERR_PROCESS
            | SYS_ERR_FAIL
            | SHUTDOWN_PROCESS
            | FW_DL_ERR)
            != 0
    }
    /// `MHI_PM_IN_ERROR_STATE`.
    pub const fn in_error_state(s: u32) -> bool {
        s >= FW_DL_ERR
    }
    /// `MHI_PM_IN_FATAL_STATE`.
    pub const fn in_fatal_state(s: u32) -> bool {
        s == LD_ERR_FATAL_DETECT
    }
    /// `MHI_WAKE_DB_CLEAR_VALID`.
    pub const fn wake_db_clear_valid(s: u32) -> bool {
        s & (M0 | M2 | M3_EXIT) != 0
    }
    /// `MHI_WAKE_DB_SET_VALID`.
    pub const fn wake_db_set_valid(s: u32) -> bool {
        s & M2 != 0
    }
    /// `MHI_WAKE_DB_FORCE_SET_VALID`.
    pub const fn wake_db_force_set_valid(s: u32) -> bool {
        wake_db_clear_valid(s)
    }
    /// `MHI_EVENT_ACCESS_INVALID`.
    pub const fn event_access_invalid(s: u32) -> bool {
        s == DISABLE || in_error_state(s)
    }
    /// `MHI_PM_IN_SUSPEND_STATE`.
    pub const fn in_suspend_state(s: u32) -> bool {
        s & (M3_ENTER | M3) != 0
    }
    /// `MHI_PM_FATAL_ERROR`.
    pub const fn fatal_error(s: u32) -> bool {
        s == FW_DL_ERR || s >= SYS_ERR_FAIL
    }

    /// `dev_state_transitions[]` (`pm.c`): `(from, allowed to-states)`,
    /// indexed by the bit number of `from`.
    pub const TRANSITIONS: [(u32, u32); 13] = [
        (DISABLE, POR),
        (
            POR,
            POR | DISABLE
                | M0
                | SYS_ERR_DETECT
                | SHUTDOWN_PROCESS
                | LD_ERR_FATAL_DETECT
                | FW_DL_ERR,
        ),
        (
            M0,
            M0 | M2
                | M3_ENTER
                | SYS_ERR_DETECT
                | SHUTDOWN_PROCESS
                | LD_ERR_FATAL_DETECT
                | FW_DL_ERR,
        ),
        (
            M2,
            M0 | SYS_ERR_DETECT | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (
            M3_ENTER,
            M3 | SYS_ERR_DETECT | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (M3, M3_EXIT | SYS_ERR_DETECT | LD_ERR_FATAL_DETECT),
        (
            M3_EXIT,
            M0 | SYS_ERR_DETECT | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (
            FW_DL_ERR,
            FW_DL_ERR | SYS_ERR_DETECT | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (
            SYS_ERR_DETECT,
            SYS_ERR_PROCESS | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (
            SYS_ERR_PROCESS,
            POR | SYS_ERR_FAIL | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (
            SYS_ERR_FAIL,
            SYS_ERR_DETECT | SHUTDOWN_PROCESS | LD_ERR_FATAL_DETECT,
        ),
        (SHUTDOWN_PROCESS, DISABLE | LD_ERR_FATAL_DETECT),
        (LD_ERR_FATAL_DETECT, LD_ERR_FATAL_DETECT | DISABLE),
    ];

    /// `mhi_tryset_pm_state`: the state after the attempt (unchanged
    /// when the transition is not allowed).
    pub fn tryset(cur: u32, to: u32) -> u32 {
        if cur == 0 {
            return cur;
        }
        // find_last_bit
        let index = 31 - cur.leading_zeros() as usize;
        if index >= TRANSITIONS.len() {
            return cur;
        }
        let (from, allowed) = TRANSITIONS[index];
        if from != cur || allowed & to == 0 {
            return cur;
        }
        to
    }

    /// `to_mhi_pm_state_str`.
    pub fn name(s: u32) -> &'static str {
        match s {
            DISABLE => "DISABLE",
            POR => "POWER ON RESET",
            M0 => "M0",
            M2 => "M2",
            M3_ENTER => "M?->M3",
            M3 => "M3",
            M3_EXIT => "M3->M0",
            FW_DL_ERR => "Firmware Download Error",
            SYS_ERR_DETECT => "SYS ERROR Detect",
            SYS_ERR_PROCESS => "SYS ERROR Process",
            SYS_ERR_FAIL => "SYS ERROR Failure",
            SHUTDOWN_PROCESS => "SHUTDOWN Process",
            LD_ERR_FATAL_DETECT => "Linkdown or Error Fatal Detect",
            _ => "Invalid State",
        }
    }
}

// ── Ring element (`struct mhi_ring_element`) ──────────────────────

/// One 16-byte ring element (TRE / command / event). All fields are
/// little-endian on the wire; NARF targets are little-endian, so the
/// in-memory layout is the wire layout.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MhiRingElement {
    pub ptr: u64,
    pub dword: [u32; 2],
}

impl MhiRingElement {
    pub const SIZE: usize = 16;

    /// `MHI_TRE_DATA_PTR` / `DWORD0` / `DWORD1(bei, ieot, ieob, chain)`.
    pub const fn data(ptr: u64, len: u32, bei: bool, ieot: bool, ieob: bool, chain: bool) -> Self {
        MhiRingElement {
            ptr,
            dword: [
                field_prep(genmask(15, 0), len),
                field_prep(genmask(23, 16), pkt::TRANSFER)
                    | field_prep(1 << 10, bei as u32)
                    | field_prep(1 << 9, ieot as u32)
                    | field_prep(1 << 8, ieob as u32)
                    | field_prep(1 << 0, chain as u32),
            ],
        }
    }

    /// `MHI_TRE_CMD_{NOOP,RESET,STOP,START}_*`. `None` for a command
    /// type Linux's `mhi_send_cmd` does not build.
    pub const fn command(cmd_type: u32, chid: u32) -> Option<Self> {
        let dword1 = match cmd_type {
            cmd::NOP => field_prep(genmask(23, 16), cmd::NOP),
            cmd::RESET_CHAN | cmd::STOP_CHAN | cmd::START_CHAN => {
                field_prep(genmask(31, 24), chid) | field_prep(genmask(23, 16), cmd_type)
            }
            _ => return None,
        };
        Some(MhiRingElement {
            ptr: 0,
            dword: [0, dword1],
        })
    }

    /// `MHI_TRE_EV_DWORD0/1` — a transfer completion event (device side;
    /// used by tests).
    pub const fn tx_event(ptr: u64, code: u32, len: u32, chid: u32) -> Self {
        MhiRingElement {
            ptr,
            dword: [
                field_prep(genmask(31, 24), code) | field_prep(genmask(15, 0), len),
                field_prep(genmask(31, 24), chid) | field_prep(genmask(23, 16), pkt::TX_EVENT),
            ],
        }
    }

    /// `MHI_SC_EV_*` — state change event.
    pub const fn state_change_event(state: u32) -> Self {
        MhiRingElement {
            ptr: 0,
            dword: [
                field_prep(genmask(31, 24), state),
                field_prep(genmask(23, 16), pkt::STATE_CHANGE_EVENT),
            ],
        }
    }

    /// `MHI_EE_EV_*` — execution environment event.
    pub const fn ee_event(ee: u32) -> Self {
        MhiRingElement {
            ptr: 0,
            dword: [
                field_prep(genmask(31, 24), ee),
                field_prep(genmask(23, 16), pkt::EE_EVENT),
            ],
        }
    }

    /// `MHI_CC_EV_*` — command completion event.
    pub const fn cmd_completion_event(ptr: u64, code: u32) -> Self {
        MhiRingElement {
            ptr,
            dword: [
                field_prep(genmask(31, 24), code),
                field_prep(genmask(23, 16), pkt::CMD_COMPLETION_EVENT),
            ],
        }
    }

    /// `MHI_TRE_GET_EV_TYPE`.
    pub const fn ev_type(&self) -> u32 {
        field_get(genmask(23, 16), self.dword[1])
    }
    /// `MHI_TRE_GET_EV_CODE`.
    pub const fn ev_code(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[0])
    }
    /// `MHI_TRE_GET_EV_LEN`.
    pub const fn ev_len(&self) -> u32 {
        field_get(genmask(15, 0), self.dword[0])
    }
    /// `MHI_TRE_GET_EV_CHID`.
    pub const fn ev_chid(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[1])
    }
    /// `MHI_TRE_GET_EV_STATE`.
    pub const fn ev_state(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[0])
    }
    /// `MHI_TRE_GET_EV_EXECENV`.
    pub const fn ev_execenv(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[0])
    }
    /// `MHI_TRE_GET_EV_LINKSPEED`.
    pub const fn ev_linkspeed(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[1])
    }
    /// `MHI_TRE_GET_EV_LINKWIDTH`.
    pub const fn ev_linkwidth(&self) -> u32 {
        field_get(genmask(7, 0), self.dword[0])
    }
    /// `MHI_TRE_GET_CMD_CHID`.
    pub const fn cmd_chid(&self) -> u32 {
        field_get(genmask(31, 24), self.dword[1])
    }
    /// `MHI_TRE_GET_CMD_TYPE`.
    pub const fn cmd_type(&self) -> u32 {
        field_get(genmask(23, 16), self.dword[1])
    }
    /// `MHI_TRE_DATA_GET_LEN`.
    pub const fn data_len(&self) -> u32 {
        field_get(genmask(15, 0), self.dword[0])
    }
    /// `MHI_TRE_DATA_GET_CHAIN`.
    pub const fn data_chain(&self) -> bool {
        self.dword[1] & 1 != 0
    }
    /// `MHI_TRE_DATA_GET_IEOB`.
    pub const fn data_ieob(&self) -> bool {
        self.dword[1] & (1 << 8) != 0
    }
    /// `MHI_TRE_DATA_GET_IEOT`.
    pub const fn data_ieot(&self) -> bool {
        self.dword[1] & (1 << 9) != 0
    }
    /// `MHI_TRE_DATA_GET_BEI`.
    pub const fn data_bei(&self) -> bool {
        self.dword[1] & (1 << 10) != 0
    }
}

// ── Contexts (`common.h`) ─────────────────────────────────────────

pub const EV_CTX_RESERVED_MASK: u32 = genmask(7, 0);
pub const EV_CTX_INTMODC_MASK: u32 = genmask(15, 8);
pub const EV_CTX_INTMODT_MASK: u32 = genmask(31, 16);
pub const CHAN_CTX_CHSTATE_MASK: u32 = genmask(7, 0);
pub const CHAN_CTX_BRSTMODE_MASK: u32 = genmask(9, 8);
pub const CHAN_CTX_POLLCFG_MASK: u32 = genmask(15, 10);
pub const CHAN_CTX_RESERVED_MASK: u32 = genmask(31, 16);

/// `struct mhi_event_ctxt`: three u32 then four `__le64 __packed
/// __aligned(4)` — 44 bytes, 4-byte aligned.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, Default)]
pub struct MhiEventCtxt {
    pub intmod: u32,
    pub ertype: u32,
    pub msivec: u32,
    pub rbase: u64,
    pub rlen: u64,
    pub rp: u64,
    pub wp: u64,
}

/// `struct mhi_chan_ctxt` — 44 bytes, 4-byte aligned.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, Default)]
pub struct MhiChanCtxt {
    pub chcfg: u32,
    pub chtype: u32,
    pub erindex: u32,
    pub rbase: u64,
    pub rlen: u64,
    pub rp: u64,
    pub wp: u64,
}

/// `struct mhi_cmd_ctxt` — 44 bytes, 4-byte aligned.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, Default)]
pub struct MhiCmdCtxt {
    pub reserved0: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub rbase: u64,
    pub rlen: u64,
    pub rp: u64,
    pub wp: u64,
}

/// Byte offsets of the shared context fields (identical in all three
/// context structs).
pub const CTXT_SIZE: usize = 44;
pub const CTXT_RBASE: usize = 12;
pub const CTXT_RLEN: usize = 20;
pub const CTXT_RP: usize = 28;
pub const CTXT_WP: usize = 36;

/// `struct bhi_vec_entry` (`internal.h`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BhiVecEntry {
    pub dma_addr: u64,
    pub size: u64,
}

// ── Controller configuration (`include/linux/mhi.h`) ──────────────

/// `struct mhi_channel_config` (fields ath11k sets).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChannelConfig {
    pub num: u32,
    pub name: &'static str,
    pub num_elements: u32,
    /// 0 = same as `num_elements` (`parse_ch_cfg`).
    pub local_elements: u32,
    pub event_ring: u32,
    pub dir: DmaDir,
    pub ee_mask: u32,
    pub pollcfg: u32,
    pub doorbell: BrstMode,
    pub lpm_notify: bool,
    pub offload_channel: bool,
    pub doorbell_mode_switch: bool,
}

/// `struct mhi_event_config` (fields ath11k sets).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventConfig {
    pub num_elements: u32,
    pub irq_moderation_ms: u32,
    pub irq: u32,
    /// ath11k leaves `.channel` unset (0). Linux `parse_ev_cfg` treats
    /// any value other than `U32_MAX` as a dedicated channel, so it
    /// records channel 0 here; only client-managed rings act on it.
    pub channel: u32,
    pub priority: u32,
    pub mode: BrstMode,
    pub data_type: ErDataType,
    pub hardware_event: bool,
    pub client_managed: bool,
    pub offload_channel: bool,
}

/// `struct mhi_controller_config` (fields ath11k sets).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ControllerConfig {
    pub max_channels: u32,
    pub timeout_ms: u32,
    pub ready_timeout_ms: u32,
    pub use_bounce_buf: bool,
    pub buf_len: u32,
    pub ch_cfg: &'static [ChannelConfig],
    pub event_cfg: &'static [EventConfig],
}

/// `ath11k_mhi_channels_qca6390`.
pub const ATH11K_MHI_CHANNELS_QCA6390: [ChannelConfig; 2] = [
    ChannelConfig {
        num: 20,
        name: "IPCR",
        num_elements: 64,
        local_elements: 0,
        event_ring: 1,
        dir: DmaDir::ToDevice,
        ee_mask: 0x4,
        pollcfg: 0,
        doorbell: BrstMode::Disable,
        lpm_notify: false,
        offload_channel: false,
        doorbell_mode_switch: false,
    },
    ChannelConfig {
        num: 21,
        name: "IPCR",
        num_elements: 64,
        local_elements: 0,
        event_ring: 1,
        dir: DmaDir::FromDevice,
        ee_mask: 0x4,
        pollcfg: 0,
        doorbell: BrstMode::Disable,
        lpm_notify: false,
        offload_channel: false,
        doorbell_mode_switch: false,
    },
];

/// `ath11k_mhi_events_qca6390`. Event ring 1's `.data_type` is
/// unset in Linux, i.e. `MHI_ER_DATA` (0).
pub const ATH11K_MHI_EVENTS_QCA6390: [EventConfig; 2] = [
    EventConfig {
        num_elements: 32,
        irq_moderation_ms: 0,
        irq: 1,
        channel: 0,
        priority: 0,
        mode: BrstMode::Disable,
        data_type: ErDataType::Ctrl,
        hardware_event: false,
        client_managed: false,
        offload_channel: false,
    },
    EventConfig {
        num_elements: 256,
        irq_moderation_ms: 1,
        irq: 2,
        channel: 0,
        priority: 1,
        mode: BrstMode::Disable,
        data_type: ErDataType::Data,
        hardware_event: false,
        client_managed: false,
        offload_channel: false,
    },
];

/// `ath11k_mhi_config_qca6390` — used for QCA6390, WCN6855 HW2.0/2.1,
/// QCA2066 and QCA6698AQ.
pub const ATH11K_MHI_CONFIG_QCA6390: ControllerConfig = ControllerConfig {
    max_channels: 128,
    timeout_ms: 2000,
    ready_timeout_ms: 0,
    use_bounce_buf: false,
    buf_len: 8192,
    ch_cfg: &ATH11K_MHI_CHANNELS_QCA6390,
    event_cfg: &ATH11K_MHI_EVENTS_QCA6390,
};

/// `ath11k_mhi_channels_qcn9074`.
pub const ATH11K_MHI_CHANNELS_QCN9074: [ChannelConfig; 2] = [
    ChannelConfig {
        num: 20,
        name: "IPCR",
        num_elements: 32,
        local_elements: 0,
        event_ring: 1,
        dir: DmaDir::ToDevice,
        ee_mask: 0x14,
        pollcfg: 0,
        doorbell: BrstMode::Disable,
        lpm_notify: false,
        offload_channel: false,
        doorbell_mode_switch: false,
    },
    ChannelConfig {
        num: 21,
        name: "IPCR",
        num_elements: 32,
        local_elements: 0,
        event_ring: 1,
        dir: DmaDir::FromDevice,
        ee_mask: 0x14,
        pollcfg: 0,
        doorbell: BrstMode::Disable,
        lpm_notify: false,
        offload_channel: false,
        doorbell_mode_switch: false,
    },
];

/// `ath11k_mhi_config_qcn9074` (events identical to QCA6390's).
pub const ATH11K_MHI_CONFIG_QCN9074: ControllerConfig = ControllerConfig {
    max_channels: 30,
    timeout_ms: 10000,
    ready_timeout_ms: 0,
    use_bounce_buf: false,
    buf_len: 0,
    ch_cfg: &ATH11K_MHI_CHANNELS_QCN9074,
    event_cfg: &ATH11K_MHI_EVENTS_QCA6390,
};

/// ath11k `mhi.c`: `MHI_TIMEOUT_DEFAULT_MS` — `ath11k_mhi_start`
/// overrides the config's `timeout_ms` with this before
/// `mhi_prepare_for_power_up`, so every MHI wait during bring-up is
/// bounded by 20 s, not the table's 2 s.
pub const ATH11K_MHI_TIMEOUT_DEFAULT_MS: u32 = 20000;
/// ath11k `RDDM_DUMP_SIZE`.
pub const ATH11K_RDDM_DUMP_SIZE: u32 = 0x420000;
/// `ath11k_mhi_register`: `sbl_size = seg_len = SZ_512K`.
pub const ATH11K_SBL_SIZE: usize = 512 * 1024;
pub const ATH11K_SEG_LEN: usize = 512 * 1024;
/// ath11k `pci.c`: streaming DMA mask (`ATH11K_PCI_DMA_MASK` = 36);
/// `iova_stop = ab_pci->dma_mask`.
pub const ATH11K_PCI_DMA_MASK: u64 = (1 << 36) - 1;
/// ath11k `pci.c`: `ATH11K_PCI_COHERENT_DMA_MASK` = 32.
pub const ATH11K_PCI_COHERENT_DMA_MASK: u64 = (1 << 32) - 1;
/// `ATH11K_AMSS_FILE`.
pub const ATH11K_AMSS_FILE: &str = "amss.bin";

/// `ath11k_mhi_register`'s config switch.
pub fn config_for(hw_rev: super::hw::HwRev) -> Option<&'static ControllerConfig> {
    use super::hw::HwRev::*;
    match hw_rev {
        Qcn9074Hw10 => Some(&ATH11K_MHI_CONFIG_QCN9074),
        Qca6390Hw20 | Wcn6855Hw20 | Wcn6855Hw21 | Qca2066Hw21 | Qca6698aqHw21 => {
            Some(&ATH11K_MHI_CONFIG_QCA6390)
        }
        Unknown => None,
    }
}

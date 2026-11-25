//! Intel HDCP 1.4 and HDCP 2.2 content protection for external DP and
//! HDMI, behind `narf.intel.hdcp=1`.
//!
//! ## References
//!
//! - `drivers/gpu/drm/i915/display/intel_hdcp.c` (Linux 7.4-rc4): the
//!   HDCP 1.4 key load (`intel_hdcp_load_keys`), authentication
//!   (`intel_hdcp_auth`, `intel_hdcp_auth_downstream`,
//!   `intel_hdcp_validate_v_prime`), link check
//!   (`intel_hdcp_check_link`), the HDCP 2.2 AKE / LC / SKE / repeater /
//!   stream-management flow (`hdcp2_authenticate_and_encrypt` and its
//!   helpers, `intel_hdcp2_check_link`), the enable choice
//!   (`_intel_hdcp_enable`), `intel_hdcp_disable`,
//!   `intel_hdcp_update_pipe`, `intel_hdcp_atomic_check` and the
//!   property value updates (`intel_hdcp_update_value`,
//!   `intel_hdcp_prop_work`).
//! - `intel_hdcp_regs.h`: the display-12+ transcoder HDCP registers and the
//!   port-indexed ones of display 9 to 11 (`TRANS_HDCP(display)`), the
//!   HDCP 1.4 repeater control (`intel_hdcp_get_repeater_ctl`), the key
//!   load (`intel_hdcp_load_keys`: the pcode mailbox on Gen9 big core) and
//!   PW_1 (`hdcp_key_loadable`) by display version ([`HdcpHw`]).
//! - `drivers/gpu/drm/display/drm_hdcp_helper.c`: SRM parsing and
//!   `drm_hdcp_check_ksvs_revoked` ([`Srm`]).
//! - The sink side (`intel_hdcp_shim.h`) is [`HdcpShim`]; its DP and HDMI
//!   implementations are `crate::intel_hdcp_shim`. The HDCP 2.2 firmware
//!   (`i915_hdcp_ops`) is `crate::intel_hdcp_msg::Fw` over the MEI or GSC
//!   transport.
//!
//! ## Scope and refusals
//!
//! DP (not eDP) and HDMI on a transcoder A–D. Display 12 and later use the
//! `TRANS_HDCP` register layout (`TRANS_HDCP(display)` =
//! `DISPLAY_VER >= 12`); display 9 to 11 use the DDI port's `PORT_HDCP`
//! block, on ports A to D only (`is_hdcp_supported`: `port < PORT_E`).
//! DP MST streams are [`mst::MstHdcp`]: the link on the master transcoder,
//! each stream's encryption by its own transcoder's HDCP select. Every
//! other display, port and transcoder is refused with
//! [`HdcpError::Unsupported`] before any register access. HDCP 2.2 needs
//! the firmware and a platform `is_hdcp2_supported` admits: the MEI HDCP
//! client below display 14 (display 10+, and Kaby/Coffee/Comet Lake on
//! display 9), the GSC on display 14 and later; without it the enable
//! falls back to HDCP 1.4 for type-0 content, exactly as
//! `intel_hdcp2_prerequisite` makes Linux do.
//!
//! ## Secrets
//!
//! Nothing here logs. An, Bksv, the KSV FIFO, receiver IDs and every
//! HDCP 2.2 message stay in local buffers; errors carry no key material.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_hdcp_msg::{self as msg, Fw, FwError, HdcpFuture, HdcpPortData, HdcpTransport};

/// The strict boot option.
pub const BOOT_OPTION: &str = "narf.intel.hdcp";

/// `narf.intel.hdcp=1` is on the command line.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

// ── intel_hdcp_regs.h ────────────────────────────────────────────────

pub const HDCP_KEY_CONF: u64 = 0x66c00;
pub const HDCP_AKSV_SEND_TRIGGER: u32 = 1 << 31;
pub const HDCP_CLEAR_KEYS_TRIGGER: u32 = 1 << 30;
pub const HDCP_KEY_LOAD_TRIGGER: u32 = 1 << 8;
pub const HDCP_KEY_STATUS: u64 = 0x66c04;
pub const HDCP_FUSE_IN_PROGRESS: u32 = 1 << 7;
pub const HDCP_FUSE_ERROR: u32 = 1 << 6;
pub const HDCP_FUSE_DONE: u32 = 1 << 5;
pub const HDCP_KEY_LOAD_STATUS: u32 = 1 << 1;
pub const HDCP_KEY_LOAD_DONE: u32 = 1 << 0;

pub const HDCP_REP_CTL: u64 = 0x66d00;
pub const HDCP_SHA1_BUSY: u32 = 1 << 16;
pub const HDCP_SHA1_READY: u32 = 1 << 17;
pub const HDCP_SHA1_COMPLETE: u32 = 1 << 18;
pub const HDCP_SHA1_V_MATCH: u32 = 1 << 19;
pub const HDCP_SHA1_TEXT_32: u32 = 1 << 1;
pub const HDCP_SHA1_COMPLETE_HASH: u32 = 2 << 1;
pub const HDCP_SHA1_TEXT_24: u32 = 4 << 1;
pub const HDCP_SHA1_TEXT_16: u32 = 5 << 1;
pub const HDCP_SHA1_TEXT_8: u32 = 6 << 1;
pub const HDCP_SHA1_TEXT_0: u32 = 7 << 1;
/// `HDCP_SHA_V_PRIME(h)`.
pub const fn hdcp_sha_v_prime(h: usize) -> u64 {
    0x66d04 + h as u64 * 4
}
pub const HDCP_SHA_TEXT: u64 = 0x66d18;

/// `_MMIO_TRANS(trans, _TRANSA_*, _TRANSB_*)`: the B block is 0x100 past A.
const fn trans_reg(trans: u8, a: u64) -> u64 {
    a + trans as u64 * 0x100
}
pub const fn trans_hdcp_conf(t: u8) -> u64 {
    trans_reg(t, 0x66400)
}
pub const fn trans_hdcp_aninit(t: u8) -> u64 {
    trans_reg(t, 0x66404)
}
pub const fn trans_hdcp_anlo(t: u8) -> u64 {
    trans_reg(t, 0x66408)
}
pub const fn trans_hdcp_anhi(t: u8) -> u64 {
    trans_reg(t, 0x6640c)
}
pub const fn trans_hdcp_bksvlo(t: u8) -> u64 {
    trans_reg(t, 0x66410)
}
pub const fn trans_hdcp_bksvhi(t: u8) -> u64 {
    trans_reg(t, 0x66414)
}
pub const fn trans_hdcp_rprime(t: u8) -> u64 {
    trans_reg(t, 0x66418)
}
pub const fn trans_hdcp_status(t: u8) -> u64 {
    trans_reg(t, 0x6641c)
}
pub const HDCP_CONF_CAPTURE_AN: u32 = 1 << 0;
pub const HDCP_CONF_AUTH_AND_ENC: u32 = (1 << 1) | (1 << 0);
pub const HDCP_STATUS_AUTH: u32 = 1 << 21;
pub const HDCP_STATUS_ENC: u32 = 1 << 20;
pub const HDCP_STATUS_RI_MATCH: u32 = 1 << 19;
pub const HDCP_STATUS_R0_READY: u32 = 1 << 18;
pub const HDCP_STATUS_AN_READY: u32 = 1 << 17;
pub const HDCP_STATUS_CIPHER: u32 = 1 << 16;

pub const fn trans_hdcp2_auth(t: u8) -> u64 {
    trans_reg(t, 0x66498)
}
pub const fn trans_hdcp2_ctl(t: u8) -> u64 {
    trans_reg(t, 0x664b0)
}
pub const fn trans_hdcp2_status(t: u8) -> u64 {
    trans_reg(t, 0x664b4)
}

/// `_PORT_HDCP_AUTHENC(port, 0)` = `_PORT_HDCP2_BASE(port, 0)`: the
/// `_PICK` of ports A to F (0x66800, 0x66500, 0x66600, 0x66700, 0x66a00,
/// 0x66900) for display 9 to 11.
pub const fn port_hdcp_base(port: u8) -> u64 {
    match port {
        0 => 0x66800,
        1 => 0x66500,
        2 => 0x66600,
        3 => 0x66700,
        4 => 0x66a00,
        _ => 0x66900,
    }
}
/// `PIPE_HDCP2_STREAM_STATUS(pipe)`: `_PICK` of 0x668c0, 0x665c0, 0x666c0,
/// 0x667c0 (what `HDCP2_STREAM_STATUS` names below display 12).
pub const fn pipe_hdcp2_stream_status(pipe: u8) -> u64 {
    match pipe {
        0 => 0x668c0,
        1 => 0x665c0,
        2 => 0x666c0,
        _ => 0x667c0,
    }
}
/// `PORT_HDCP2_AUTH_STREAM(port)`: `_MMIO_PORT(port, 0x66f00, 0x66f04)`.
pub const fn port_hdcp2_auth_stream(port: u8) -> u64 {
    0x66f00 + port as u64 * 4
}

/// `HDCP_DDIx_REP_PRESENT | HDCP_DDIx_SHA1_M0`, the HDCP 1.4 repeater
/// control of a display 9-11 port (`intel_hdcp_get_repeater_ctl`): A is
/// bit 29 | 2 << 20, B bit 30 | 1 << 20, C bit 28 | 3 << 20, D bit 27 |
/// 4 << 20, E bit 25 | 6 << 20; Linux has no entry for F (0).
pub const fn port_repeater_ctl(port: u8) -> u32 {
    match port {
        0 => 1 << 29 | 2 << 20,
        1 => 1 << 30 | 1 << 20,
        2 => 1 << 28 | 3 << 20,
        3 => 1 << 27 | 4 << 20,
        4 => 1 << 25 | 6 << 20,
        _ => 0,
    }
}

/// Where a link's HDCP registers sit (`TRANS_HDCP(display)`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpRegs {
    /// Display 12+: the CPU transcoder's `TRANS_HDCP_*` block.
    Transcoder,
    /// Display 9 to 11: the DDI port's `PORT_HDCP_*` block (port A = 0).
    Port(u8),
}

impl HdcpRegs {
    const fn at(self, t: u8, trans_a: u64, x: u64) -> u64 {
        match self {
            Self::Transcoder => trans_reg(t, trans_a),
            Self::Port(port) => port_hdcp_base(port) + x,
        }
    }
    /// `HDCP_CONF(display, trans, port)`.
    pub const fn conf(self, t: u8) -> u64 {
        self.at(t, 0x66400, 0x0)
    }
    /// `HDCP_ANINIT`.
    pub const fn aninit(self, t: u8) -> u64 {
        self.at(t, 0x66404, 0x4)
    }
    /// `HDCP_ANLO`.
    pub const fn anlo(self, t: u8) -> u64 {
        self.at(t, 0x66408, 0x8)
    }
    /// `HDCP_ANHI`.
    pub const fn anhi(self, t: u8) -> u64 {
        self.at(t, 0x6640c, 0xc)
    }
    /// `HDCP_BKSVLO`.
    pub const fn bksvlo(self, t: u8) -> u64 {
        self.at(t, 0x66410, 0x10)
    }
    /// `HDCP_BKSVHI`.
    pub const fn bksvhi(self, t: u8) -> u64 {
        self.at(t, 0x66414, 0x14)
    }
    /// `HDCP_RPRIME`.
    pub const fn rprime(self, t: u8) -> u64 {
        self.at(t, 0x66418, 0x18)
    }
    /// `HDCP_STATUS`.
    pub const fn status(self, t: u8) -> u64 {
        self.at(t, 0x6641c, 0x1c)
    }
    /// `HDCP2_AUTH`.
    pub const fn hdcp2_auth(self, t: u8) -> u64 {
        self.at(t, 0x66498, 0x98)
    }
    /// `HDCP2_CTL`.
    pub const fn hdcp2_ctl(self, t: u8) -> u64 {
        self.at(t, 0x664b0, 0xb0)
    }
    /// `HDCP2_STATUS`.
    pub const fn hdcp2_status(self, t: u8) -> u64 {
        self.at(t, 0x664b4, 0xb4)
    }
    /// `HDCP2_STREAM_STATUS(display, cpu_transcoder, pipe)` of the stream
    /// on transcoder (and pipe) `t`.
    pub const fn hdcp2_stream_status(self, t: u8) -> u64 {
        match self {
            Self::Transcoder => trans_reg(t, 0x664c0),
            Self::Port(_) => pipe_hdcp2_stream_status(t),
        }
    }
    /// `HDCP2_AUTH_STREAM(display, cpu_transcoder, port)`.
    pub const fn hdcp2_auth_stream(self, t: u8) -> u64 {
        match self {
            Self::Transcoder => 0x66f00 + t as u64 * 4,
            Self::Port(port) => port_hdcp2_auth_stream(port),
        }
    }
    /// `intel_hdcp_get_repeater_ctl` for the link on transcoder `t`.
    pub const fn repeater_ctl(self, t: u8) -> u32 {
        match self {
            Self::Transcoder => HdcpLink::repeater_ctl(t),
            Self::Port(port) => port_repeater_ctl(port),
        }
    }
}

/// `SKL_PCODE_LOAD_HDCP_KEYS` (`intel_pcode_regs.h`).
pub const SKL_PCODE_LOAD_HDCP_KEYS: u32 = 0x5;
/// `SKL_PW_CTL_IDX_PW_1` (display 9) and `ICL_PW_CTL_IDX_PW_1` (11+).
pub const SKL_PW_CTL_IDX_PW_1: u8 = 14;
pub const ICL_PW_CTL_IDX_PW_1: u8 = 0;

/// What `intel_hdcp.c` decides by display version for one port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HdcpHw {
    /// The register block (`TRANS_HDCP(display)`).
    pub regs: HdcpRegs,
    /// `intel_hdcp_load_keys`: display 9 except Broxton (and Gemini Lake,
    /// display 10) starts the fuse load through the pcode mailbox
    /// (`SKL_PCODE_LOAD_HDCP_KEYS`); every other display writes
    /// `HDCP_KEY_LOAD_TRIGGER`.
    pub pcode_key_load: bool,
    /// PW_1's index in `HSW_PWR_WELL_CTL*` (`hdcp_key_loadable`).
    pub pw1_idx: u8,
}

impl HdcpHw {
    /// Display 12 and later.
    pub const TRANSCODER: Self = Self {
        regs: HdcpRegs::Transcoder,
        pcode_key_load: false,
        pw1_idx: ICL_PW_CTL_IDX_PW_1,
    };

    /// A display 9-11 port `port` (A = 0): `None` past D
    /// (`is_hdcp_supported`). `display_ver` 9 is Skylake-family or
    /// Broxton (`big_core` false), 10 Gemini Lake, 11 Ice/Elkhart/Jasper
    /// Lake.
    pub const fn legacy(display_ver: u8, big_core: bool, port: u8) -> Option<Self> {
        if port > 3 || !matches!(display_ver, 9..=11) {
            return None;
        }
        Some(Self {
            regs: HdcpRegs::Port(port),
            pcode_key_load: display_ver == 9 && big_core,
            pw1_idx: if display_ver == 11 {
                ICL_PW_CTL_IDX_PW_1
            } else {
                SKL_PW_CTL_IDX_PW_1
            },
        })
    }
}
pub const AUTH_LINK_AUTHENTICATED: u32 = 1 << 31;
pub const AUTH_LINK_TYPE: u32 = 1 << 30;
pub const CTL_LINK_ENCRYPTION_REQ: u32 = 1 << 31;
pub const LINK_TYPE_STATUS: u32 = 1 << 22;
pub const LINK_AUTH_STATUS: u32 = 1 << 21;
pub const LINK_ENCRYPTION_STATUS: u32 = 1 << 20;

/// `TRANS_DDI_FUNC_CTL(trans)` and its HDCP bits.
pub const fn trans_ddi_func_ctl(t: u8) -> u64 {
    0x60400 + t as u64 * 0x1000
}
pub const TRANS_DDI_HDCP_SIGNALLING: u32 = 1 << 9;
pub const TRANS_DDI_HDCP_LINE_REKEY_DISABLE: u32 = 1 << 12;
pub const XE3_TRANS_DDI_HDCP_LINE_REKEY_DISABLE: u32 = 1 << 15;
/// `_MTL_CHICKEN_TRANS(trans)` and `HDCP_LINE_REKEY_DISABLE`.
pub const fn mtl_chicken_trans(t: u8) -> u64 {
    0x604e0 + t as u64 * 0x1000
}
pub const HDCP_LINE_REKEY_DISABLE: u32 = 1 << 0;
/// `HSW_PWR_WELL_CTL1` (BIOS) and `HSW_PWR_WELL_CTL2` (driver) power-well
/// request registers; PW_1 is index 0 (`ICL_PW_CTL_IDX_PW_1`), its state
/// bit 0.
pub const HSW_PWR_WELL_CTL1: u64 = 0x45400;
pub const HSW_PWR_WELL_CTL2: u64 = 0x45404;
const PW1_STATE: u32 = 0b01;

/// `HDCP_ENCRYPT_STATUS_CHANGE_TIMEOUT_MS`.
pub const ENCRYPT_STATUS_CHANGE_TIMEOUT_MS: u64 = 50;
/// `KEY_LOAD_TRIES`.
pub const KEY_LOAD_TRIES: u32 = 5;
/// `HDCP2_LC_RETRY_CNT`.
pub const HDCP2_LC_RETRY_CNT: u32 = 3;
/// `DRM_HDCP_CHECK_PERIOD_MS` and `DRM_HDCP2_CHECK_PERIOD_MS`.
pub const HDCP_CHECK_PERIOD_MS: u64 = 128 * 16;
pub const HDCP2_CHECK_PERIOD_MS: u64 = 500;
/// `HDCP_2_2_DELAY_BEFORE_ENCRYPTION_EN`.
pub const DELAY_BEFORE_ENCRYPTION_MS: u64 = 200;
/// How often a CP_IRQ wait looks at the shim's CP_IRQ count (the wait
/// queue of `intel_dp_hdcp_wait_for_cp_irq`); no sink access.
pub const CP_IRQ_WAIT_MS: u64 = 1;

/// `DRM_HDCP_DDC_BCAPS` bits, `DRM_HDCP_MAX_DEVICE_EXCEEDED`,
/// `DRM_HDCP_MAX_CASCADE_EXCEEDED`, `DRM_HDCP_NUM_DOWNSTREAM`.
const fn max_device_exceeded(b: u8) -> bool {
    b & (1 << 7) != 0
}
const fn max_cascade_exceeded(b: u8) -> bool {
    b & (1 << 3) != 0
}
const fn num_downstream(b: u8) -> u8 {
    b & 0x7f
}
/// `DRM_HDCP_SHA1_TERMINATOR`.
const SHA1_TERMINATOR: u32 = 0x80;

// ── Types ────────────────────────────────────────────────────────────

/// The adaptation on the port (`hdcp_wired_protocol`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    Dp,
    Hdmi,
}

impl Protocol {
    /// `shim->protocol` as the firmware numbers it.
    pub const fn fw(self) -> u8 {
        match self {
            Protocol::Dp => msg::HDCP_PROTOCOL_DP,
            Protocol::Hdmi => msg::HDCP_PROTOCOL_HDMI,
        }
    }
}

/// The DRM "Content Protection" values (`DRM_MODE_CONTENT_PROTECTION_*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum CpValue {
    #[default]
    Undesired = 0,
    Desired = 1,
    Enabled = 2,
}

impl CpValue {
    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Undesired),
            1 => Some(Self::Desired),
            2 => Some(Self::Enabled),
            _ => None,
        }
    }
}

/// `enum check_link_response` of `check_2_2_link`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkCheck {
    Protected,
    TopologyChange,
    IntegrityFailure,
    ReauthRequest,
}

/// How the transmitter waits for one HDCP 2.2 message from the sink.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsgTiming {
    /// The sink announces it (DP RxStatus bit, HDMI RxStatus size);
    /// otherwise the transmitter waits `timeout_ms` and reads.
    pub detectable: bool,
    pub timeout_ms: u64,
    /// The whole message must be read this long after its first byte
    /// (DP `msg_read_timeout`); 0 for none.
    pub read_timeout_ms: u64,
    /// The interval between availability checks.
    pub poll_ms: u64,
}

/// Why an HDCP step failed or was refused. [`HdcpError::errno`] is the
/// errno the Linux function returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpError {
    /// `narf.intel.hdcp=1` is not set.
    Disabled,
    /// Not an HDCP-capable DP/HDMI port on transcoder A–D (display 12+,
    /// or a display 9-11 port A–D).
    Unsupported,
    /// No live route behind the connector (or several).
    NoRoute,
    /// The sink is not HDCP capable (`-EINVAL`) or has no valid Bksv
    /// (`-ENODEV`).
    NotCapable,
    InvalidBksv,
    /// HDCP 2.2 needs its firmware and the sink's support
    /// (`intel_hdcp2_get_capability` false) and type-1 content cannot
    /// fall back to HDCP 1.4.
    Type1Unavailable,
    /// PW_1 is off (`hdcp_key_loadable`, `-ENXIO`).
    KeyNotLoadable,
    /// The fuse key load reported failure (`-ENXIO`).
    KeyLoad,
    /// A hardware status bit did not change in time (`-ETIMEDOUT`).
    Timeout,
    /// R0' / Ri' never matched (`-ETIMEDOUT`).
    RiMismatch,
    /// V' did not match the SHA-1 of the KSV list (`-ENXIO`).
    VPrimeMismatch,
    /// A KSV or receiver ID is in the SRM (`-EPERM`).
    Revoked,
    /// The repeater topology exceeds the device or cascade limit.
    TopologyExceeded,
    /// An HDCP 1.4 repeater with no downstream device (`-EINVAL`).
    NoDownstream,
    /// AKE_Send_Cert's rx_caps do not claim HDCP 2.2 (`-EINVAL`).
    NotHdcp22,
    /// seq_num_v not 0 on the first list, or repeated (`-EINVAL`).
    SeqNumV,
    /// seq_num_m rolled over (`-ERANGE`).
    SeqNumM,
    /// Type-1 content with an HDCP 1.x or 2.0 device downstream.
    Type1Downstream,
    /// The link was not encrypted after authentication (`-EPERM`).
    LinkNotEncrypted,
    /// Encryption stopped on a link reported enabled (`-ENXIO`).
    LinkStopped,
    /// The HDCP 2.2 firmware failed.
    Fw(FwError),
    /// The sink transport (AUX or DDC) failed with this errno.
    Sink(i32),
    /// The sink did not produce the message in time (`-ETIMEDOUT`).
    MsgTimeout,
    /// The sink's message did not fit its buffer (`-EINVAL`).
    MsgSize,
    /// A check ran without enabled protection (`-EINVAL`).
    NotEnabled,
}

impl HdcpError {
    pub const fn errno(self) -> i32 {
        use narf_lib::errno as e;
        let v: i64 = match self {
            Self::Disabled | Self::Unsupported => e::EOPNOTSUPP,
            Self::NoRoute => e::ENODEV,
            Self::NotCapable
            | Self::Type1Unavailable
            | Self::NoDownstream
            | Self::NotHdcp22
            | Self::SeqNumV
            | Self::Type1Downstream
            | Self::MsgSize
            | Self::NotEnabled
            | Self::TopologyExceeded => e::EINVAL,
            Self::InvalidBksv => e::ENODEV,
            Self::KeyNotLoadable | Self::KeyLoad | Self::VPrimeMismatch | Self::LinkStopped => {
                e::ENXIO
            }
            Self::Timeout | Self::RiMismatch | Self::MsgTimeout => e::ETIMEDOUT,
            Self::Revoked | Self::LinkNotEncrypted => e::EPERM,
            Self::SeqNumM => e::ERANGE,
            Self::Fw(f) => return f.errno(),
            Self::Sink(errno) => return errno,
        };
        -(v as i32)
    }
}

impl From<FwError> for HdcpError {
    fn from(e: FwError) -> Self {
        Self::Fw(e)
    }
}

/// The sink side of HDCP (`struct intel_hdcp_shim`), over DP AUX or HDMI
/// DDC. Every call is one bounded transfer; waiting is the engine's.
pub trait HdcpShim: Send {
    fn protocol(&self) -> Protocol;
    /// `write_an_aksv`: An, then the hardware-sourced Aksv.
    fn write_an_aksv(&mut self, an: &[u8; 8]) -> Result<(), HdcpError>;
    fn read_bksv(&mut self) -> Result<[u8; 5], HdcpError>;
    /// BSTATUS (HDMI) / BINFO (DP).
    fn read_bstatus(&mut self) -> Result<[u8; 2], HdcpError>;
    fn repeater_present(&mut self) -> Result<bool, HdcpError>;
    fn read_ri_prime(&mut self) -> Result<[u8; 2], HdcpError>;
    fn read_ksv_ready(&mut self) -> Result<bool, HdcpError>;
    /// `num` KSVs into `out[..num * 5]`.
    fn read_ksv_fifo(&mut self, num: usize, out: &mut [u8]) -> Result<(), HdcpError>;
    /// V'.H`i` as the little-endian word the sink's bytes form.
    fn read_v_prime_part(&mut self, i: usize) -> Result<u32, HdcpError>;
    /// `hdcp_get_capability` (DP BCAPS); `None` where the shim has none
    /// (HDMI: a valid Bksv is the capability).
    fn hdcp_capable(&mut self) -> Option<Result<bool, HdcpError>>;
    /// DP `check_link` (BSTATUS link-failure / reauth bits); `None` for
    /// HDMI, whose Ri' check needs the transcoder registers.
    fn check_link_status(&mut self) -> Option<bool>;
    /// `hdcp_2_2_get_capability`.
    fn hdcp2_capable(&mut self) -> Result<bool, HdcpError>;
    /// `write_2_2_msg` (`msg[0]` is the message id).
    fn write_2_2_msg(&mut self, msg: &[u8]) -> Result<(), HdcpError>;
    /// How to wait for message `msg_id`.
    fn msg_timing(&self, msg_id: u8, paired: bool) -> Result<MsgTiming, HdcpError>;
    /// Whether message `msg_id` is ready (DP RxStatus bits, HDMI RxStatus
    /// size): `Some(size)` when ready, `size` 0 when the sink gives none.
    fn msg_available(&mut self, msg_id: u8) -> Result<Option<usize>, HdcpError>;
    /// Read message `msg_id` into `buf` (`buf[0]` becomes the id);
    /// `available` is what [`HdcpShim::msg_available`] reported. Returns
    /// the message size.
    fn read_2_2_msg(
        &mut self,
        msg_id: u8,
        available: usize,
        buf: &mut [u8],
    ) -> Result<usize, HdcpError>;
    /// `config_stream_type` (DP errata); HDMI has none.
    fn config_stream_type(&mut self, is_repeater: bool, content_type: u8) -> Result<(), HdcpError>;
    /// `check_2_2_link`.
    fn check_2_2_link(&mut self) -> Result<LinkCheck, HdcpError>;
    /// `intel_dp_hdcp_wait_for_cp_irq`'s condition: whether the sink raised
    /// a CP_IRQ since the last message was read
    /// (`cp_irq_count_cached != cp_irq_count`). `None` where nothing
    /// delivers the sink's CP_IRQ (HDMI, or a DP route without a hotplug
    /// owner): detectable messages are then polled every
    /// [`MsgTiming::poll_ms`].
    fn cp_irq_pending(&mut self) -> Option<bool> {
        None
    }
    /// `hdcp->cp_irq_count_cached = atomic_read(&hdcp->cp_irq_count)`, once
    /// a message is ready to read.
    fn cp_irq_consume(&mut self) {}
}

/// Time, randomness and revocation for the engine.
pub trait HdcpEnv: Send {
    /// A monotonic microsecond clock.
    fn now_us(&mut self) -> u64;
    /// Sleep `ms` (`msleep` / `mdelay`).
    fn delay_ms(&mut self, ms: u64) -> HdcpFuture<'_, ()>;
    /// Busy-wait `us` (`usleep_range` of a few µs).
    fn udelay(&mut self, us: u64);
    /// `get_random_u32`.
    fn random_u32(&mut self) -> u32;
    /// `drm_hdcp_check_ksvs_revoked`: how many of `ksvs` (5 bytes each)
    /// the SRM revokes; 0 without an SRM.
    fn revoked(&mut self, ksvs: &[u8]) -> usize;
}

/// `intel_hdcp_is_ksv_valid`: 20 ones and 20 zeros.
pub fn ksv_valid(ksv: &[u8; 5]) -> bool {
    ksv.iter().map(|b| b.count_ones()).sum::<u32>() == 20
}

// ── SRM (drm_hdcp_helper.c) ─────────────────────────────────────────

/// A parsed System Renewability Message: the revoked KSVs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Srm {
    pub revoked: Vec<[u8; 5]>,
}

impl Srm {
    /// `drm_hdcp_srm_update`: an HDCP 1.x or 2.x SRM, or `None` where
    /// Linux returns `-EINVAL`. An SRM listing no KSV parses to an empty
    /// list, as Linux's revoked count 0. The DCP signature is not
    /// verified (Linux does not either).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 5 {
            return None;
        }
        if buf[0] == 0x8 << 4 {
            Self::parse_hdcp1(buf)
        } else if buf[0] == (0x9 << 4 | 0x1) {
            Self::parse_hdcp2(buf)
        } else {
            None
        }
    }

    fn vrl_length(buf: &[u8]) -> u32 {
        msg::be24_to_cpu([buf[5], buf[6], buf[7]])
    }

    /// `drm_hdcp_parse_hdcp1_srm`.
    fn parse_hdcp1(buf: &[u8]) -> Option<Self> {
        const VRL_LENGTH_SIZE: usize = 3;
        const SIG: usize = 40;
        if buf.len() < 5 + VRL_LENGTH_SIZE + SIG {
            return None;
        }
        let vrl_length = Self::vrl_length(buf) as usize;
        if buf.len() < 5 + vrl_length || vrl_length < VRL_LENGTH_SIZE + SIG {
            return None;
        }
        let vrls = vrl_length - VRL_LENGTH_SIZE - SIG;
        if vrls == 0 {
            return None;
        }
        let mut at = 5 + VRL_LENGTH_SIZE;
        let end = at + vrls;
        let mut revoked = Vec::new();
        // drm_hdcp_get_revoked_ksv_count: invalid VRLs discard the SRM's
        // KSVs (count 0).
        let mut parsed = 0;
        let mut cursor = at;
        while parsed < vrls {
            let count = usize::from(buf[cursor]);
            let size = count * msg::KSV_LEN + 1;
            parsed += size;
            cursor += size;
            if cursor > buf.len() {
                break;
            }
        }
        if parsed != vrls {
            return Some(Self::default());
        }
        while at < end {
            let count = usize::from(buf[at]);
            at += 1;
            for i in 0..count {
                let k = &buf[at + i * 5..at + i * 5 + 5];
                revoked.push([k[0], k[1], k[2], k[3], k[4]]);
            }
            at += count * msg::KSV_LEN;
        }
        Some(Self { revoked })
    }

    /// `drm_hdcp_parse_hdcp2_srm`.
    fn parse_hdcp2(buf: &[u8]) -> Option<Self> {
        const VRL_LENGTH_SIZE: usize = 3;
        const SIG: usize = 384;
        if buf.len() < 5 + VRL_LENGTH_SIZE + SIG || buf[1] != 0 {
            return None;
        }
        let vrl_length = Self::vrl_length(buf) as usize;
        if buf.len() < 5 + vrl_length || vrl_length < VRL_LENGTH_SIZE + SIG {
            return None;
        }
        if vrl_length == VRL_LENGTH_SIZE + SIG {
            return None;
        }
        let at = 5 + VRL_LENGTH_SIZE;
        let count = (usize::from(buf[at]) << 2) | usize::from((buf[at + 1] & 0xC0) >> 6);
        let ids = at + 4;
        let mut revoked = Vec::new();
        for i in 0..count {
            let k = buf.get(ids + i * 5..ids + i * 5 + 5)?;
            revoked.push([k[0], k[1], k[2], k[3], k[4]]);
        }
        Some(Self { revoked })
    }

    /// `drm_hdcp_check_ksvs_revoked`'s match count.
    pub fn revoked_count(&self, ksvs: &[u8]) -> usize {
        let mut n = 0;
        for r in &self.revoked {
            for k in ksvs.chunks_exact(msg::KSV_LEN) {
                if k == r {
                    n += 1;
                }
            }
        }
        n
    }
}

// ── The link ─────────────────────────────────────────────────────────

/// Which register disables HDMI line rekeying for HDCP 2.2
/// (`intel_hdcp_adjust_hdcp_line_rekeying`), decided by display version
/// and stepping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LineRekey {
    /// Display 12/13, and 14.00 before D0: nothing to program.
    None,
    /// 14.00 D0+: `CHICKEN_TRANS` bit 0.
    ChickenTrans,
    /// 14.01 B0+ and 20.00 B0+: `TRANS_DDI_FUNC_CTL` bit 12.
    TransDdi,
    /// Display 30+: `TRANS_DDI_FUNC_CTL` bit 15.
    Xe3TransDdi,
}

impl LineRekey {
    /// From the display IP version, release and GMD stepping
    /// (`GMD_ID_STEP`: A0 = 0, B0 = 4, C0 = 8, D0 = 12).
    pub const fn for_display(ver: u8, rel: u8, step: u8) -> Self {
        if ver >= 30 {
            Self::Xe3TransDdi
        } else if (ver == 14 && rel == 1 && step >= 4) || (ver == 20 && rel == 0 && step >= 4) {
            Self::TransDdi
        } else if ver == 14 && rel == 0 && step >= 12 {
            Self::ChickenTrans
        } else {
            Self::None
        }
    }
}

/// One protected link: `struct intel_hdcp` plus the port's
/// `intel_digital_port.hdcp` (one stream per port: SST and HDMI).
#[derive(Clone, Debug)]
pub struct HdcpLink {
    /// `hdcp->value`: what the driver reports.
    pub value: CpValue,
    pub protocol: Protocol,
    /// `hdcp->cpu_transcoder` (0..=3).
    pub transcoder: u8,
    /// The display version's registers, key load and PW_1.
    pub hw: HdcpHw,
    pub rekey: LineRekey,
    /// `hdcp->hdcp2_supported`: the platform has the HDCP 2.2 firmware.
    pub hdcp2_supported: bool,
    /// `hdcp->force_hdcp14`.
    pub force_hdcp14: bool,
    /// `hdcp->content_type`.
    pub content_type: u8,
    pub hdcp_encrypted: bool,
    pub hdcp2_encrypted: bool,
    pub is_paired: bool,
    pub is_repeater: bool,
    pub seq_num_v: u32,
    pub seq_num_m: u32,
    /// `dig_port->hdcp.auth_status`.
    pub auth_status: bool,
    /// `dig_port->hdcp.mst_type1_capable`.
    pub mst_type1_capable: bool,
    pub port_data: HdcpPortData,
    /// `hdcp->stream_transcoder` of the DP MST stream being operated on;
    /// `None` (`INVALID_TRANSCODER`) for SST and HDMI.
    pub stream_transcoder: Option<u8>,
    /// `dig_port->hdcp.num_streams`: the port's ENABLED connectors.
    pub num_streams: u8,
    /// The port's MST streams' payload IDs, in stream order
    /// (`intel_hdcp_required_content_stream`'s stream IDs).
    pub mst_vcpis: Vec<u8>,
}

/// Which HDCP versions an enable may use.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Versions {
    pub hdcp2: bool,
    pub hdcp1: bool,
}

impl Versions {
    /// `_intel_hdcp_enable`: HDCP 2.2 when it can, else HDCP 1.4.
    pub const ANY: Self = Self {
        hdcp2: true,
        hdcp1: true,
    };
    pub const HDCP2: Self = Self {
        hdcp2: true,
        hdcp1: false,
    };
    pub const HDCP1: Self = Self {
        hdcp2: false,
        hdcp1: true,
    };
}

impl HdcpLink {
    /// `intel_hdcp_init` for a display-12+ port.
    pub fn new(protocol: Protocol, transcoder: u8, rekey: LineRekey, hdcp2: bool) -> Self {
        Self {
            value: CpValue::Undesired,
            protocol,
            transcoder,
            hw: HdcpHw::TRANSCODER,
            rekey,
            hdcp2_supported: hdcp2,
            force_hdcp14: false,
            content_type: msg::STREAM_TYPE0,
            hdcp_encrypted: false,
            hdcp2_encrypted: false,
            is_paired: false,
            is_repeater: false,
            seq_num_v: 0,
            seq_num_m: 0,
            auth_status: false,
            mst_type1_capable: false,
            port_data: HdcpPortData::gen12(protocol.fw()),
            stream_transcoder: None,
            num_streams: 0,
            mst_vcpis: Vec::new(),
        }
    }

    /// The port's HDCP hardware. A display 9-11 port's firmware data names
    /// its DDI (`initialize_hdcp_port_data`: `intel_get_hdcp_ddi_index`)
    /// and keeps the transcoder invalid forever.
    pub fn with_hw(mut self, hw: HdcpHw) -> Self {
        self.hw = hw;
        self.port_data.hdcp_ddi = match hw.regs {
            HdcpRegs::Transcoder => msg::HDCP_DDI_INVALID_PORT,
            HdcpRegs::Port(port) => msg::hdcp_ddi_index(port),
        };
        self
    }

    /// `intel_hdcp_update_value`: the value, and the port's count of
    /// ENABLED connectors.
    pub fn update_value(&mut self, value: CpValue) {
        if self.value == value {
            return;
        }
        if self.value == CpValue::Enabled {
            self.num_streams = self.num_streams.saturating_sub(1);
        } else if value == CpValue::Enabled {
            self.num_streams = self.num_streams.saturating_add(1);
        }
        self.value = value;
    }
}

/// What one operation needs: the display registers, the sink, the HDCP
/// 2.2 firmware (absent when unbound) and the environment.
pub struct Ctx<'a, M: ?Sized, S, T: ?Sized, E> {
    pub io: &'a M,
    pub shim: &'a mut S,
    pub fw: Option<&'a mut T>,
    pub env: &'a mut E,
}

impl<M: ?Sized, S, T: ?Sized, E> core::fmt::Debug for Ctx<'_, M, S, T, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ctx")
            .field("fw", &self.fw.is_some())
            .finish_non_exhaustive()
    }
}

impl<M, S, T, E> Ctx<'_, M, S, T, E>
where
    M: MmioWindow + Sync + ?Sized,
    S: HdcpShim,
    T: HdcpTransport + ?Sized,
    E: HdcpEnv,
{
    fn read(&self, reg: u64) -> u32 {
        self.io.read32(reg)
    }
    fn write(&self, reg: u64, value: u32) {
        self.io.write32(reg, value);
    }
    fn rmw(&self, reg: u64, clear: u32, set: u32) {
        let v = self.io.read32(reg);
        self.io.write32(reg, (v & !clear) | set);
    }

    /// `intel_de_wait_ms(reg, mask, value, timeout)`: poll until
    /// `reg & mask == value`; the last value read on success.
    fn wait(&mut self, reg: u64, mask: u32, value: u32, timeout_ms: u64) -> Result<u32, HdcpError> {
        let start = self.env.now_us();
        loop {
            let v = self.read(reg);
            if v & mask == value {
                return Ok(v);
            }
            if self.env.now_us().saturating_sub(start) >= timeout_ms * 1000 {
                return Err(HdcpError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// `poll_timeout_us(val = read(reg), val & any, 100, timeout_us)`.
    fn poll_any(&mut self, reg: u64, any: u32, timeout_us: u64) -> Result<u32, u32> {
        let start = self.env.now_us();
        loop {
            let v = self.read(reg);
            if v & any != 0 {
                return Ok(v);
            }
            if self.env.now_us().saturating_sub(start) >= timeout_us {
                return Err(v);
            }
            self.env.udelay(100);
        }
    }

    fn fw(&mut self) -> Result<Fw<'_, T>, HdcpError> {
        match self.fw.as_deref_mut() {
            Some(t) => Ok(Fw(t)),
            None => Err(HdcpError::Fw(FwError::Invalid)),
        }
    }
}

// ── HDCP 1.4 ─────────────────────────────────────────────────────────

impl HdcpLink {
    fn conf(&self) -> u64 {
        self.hw.regs.conf(self.transcoder)
    }
    fn status(&self) -> u64 {
        self.hw.regs.status(self.transcoder)
    }
    /// `intel_hdcp_get_repeater_ctl` for this link.
    fn rep_ctl(&self) -> u32 {
        self.hw.regs.repeater_ctl(self.transcoder)
    }

    /// `intel_hdcp_get_repeater_ctl` for display 12+.
    pub const fn repeater_ctl(transcoder: u8) -> u32 {
        (1 << (31 - transcoder as u32)) | ((transcoder as u32 + 1) << 20)
    }

    /// `hdcp_key_loadable`: PW_1 (`SKL_DISP_PW_1`) on. Linux checks its
    /// own driver request and the state bit, ORing in the BIOS request on
    /// Gen9 big core (the DMC bug in `hsw_power_well_enabled`); a display
    /// NARF inherited from the firmware has PW_1 on by the BIOS request, so
    /// the state bit (`HSW_PWR_WELL_CTL_STATE(pw_idx)`) of either request
    /// register is taken.
    fn key_loadable<M: MmioWindow + ?Sized>(&self, io: &M) -> bool {
        let (bios, driver) = (io.read32(HSW_PWR_WELL_CTL1), io.read32(HSW_PWR_WELL_CTL2));
        let state = PW1_STATE << (2 * u32::from(self.hw.pw1_idx));
        bios != u32::MAX && driver != u32::MAX && (bios | driver) & state != 0
    }

    /// `intel_hdcp_clear_keys`.
    fn clear_keys<M, S, T, E>(cx: &Ctx<'_, M, S, T, E>)
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        cx.write(HDCP_KEY_CONF, HDCP_CLEAR_KEYS_TRIGGER);
        cx.write(
            HDCP_KEY_STATUS,
            HDCP_KEY_LOAD_DONE
                | HDCP_KEY_LOAD_STATUS
                | HDCP_FUSE_IN_PROGRESS
                | HDCP_FUSE_ERROR
                | HDCP_FUSE_DONE,
        );
    }

    /// `intel_hdcp_load_keys`: the `HDCP_KEY_CONF` trigger, or on Gen9 big
    /// core `SKL_PCODE_LOAD_HDCP_KEYS` with data 1 through the pcode
    /// mailbox (`intel_parent_pcode_write`; its failure is the load's).
    fn load_keys<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let val = cx.read(HDCP_KEY_STATUS);
        if val & HDCP_KEY_LOAD_DONE != 0 && val & HDCP_KEY_LOAD_STATUS != 0 {
            return Ok(());
        }
        if self.hw.pcode_key_load {
            crate::intel_gpu_pcode::pcode_write(cx.io, SKL_PCODE_LOAD_HDCP_KEYS, 0, 0, 1, 0)
                .map_err(|_| HdcpError::KeyLoad)?;
        } else {
            cx.write(HDCP_KEY_CONF, HDCP_KEY_LOAD_TRIGGER);
        }
        let val = cx.wait(HDCP_KEY_STATUS, HDCP_KEY_LOAD_DONE, HDCP_KEY_LOAD_DONE, 1)?;
        if val & HDCP_KEY_LOAD_STATUS == 0 {
            return Err(HdcpError::KeyLoad);
        }
        cx.write(HDCP_KEY_CONF, HDCP_AKSV_SEND_TRIGGER);
        Ok(())
    }

    /// `intel_hdcp_adjust_hdcp_line_rekeying` (HDMI only).
    fn adjust_line_rekeying<M, S, T, E>(&self, cx: &Ctx<'_, M, S, T, E>, enable: bool)
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.protocol != Protocol::Hdmi {
            return;
        }
        let (reg, bit) = match self.rekey {
            LineRekey::None => return,
            LineRekey::ChickenTrans => {
                (mtl_chicken_trans(self.transcoder), HDCP_LINE_REKEY_DISABLE)
            }
            LineRekey::TransDdi => (
                trans_ddi_func_ctl(self.transcoder),
                TRANS_DDI_HDCP_LINE_REKEY_DISABLE,
            ),
            LineRekey::Xe3TransDdi => (
                trans_ddi_func_ctl(self.transcoder),
                XE3_TRANS_DDI_HDCP_LINE_REKEY_DISABLE,
            ),
        };
        cx.rmw(reg, bit, if enable { 0 } else { bit });
    }

    /// `toggle_signalling`: HDMI sets `TRANS_DDI_HDCP_SIGNALLING`
    /// (`intel_hdmi_hdcp_toggle_signalling`, ≥ 6 µs before clearing);
    /// single-stream DP has nothing to toggle.
    fn toggle_signalling<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>, enable: bool)
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.protocol != Protocol::Hdmi {
            return;
        }
        if !enable {
            cx.env.udelay(6);
        }
        cx.rmw(
            trans_ddi_func_ctl(self.transcoder),
            TRANS_DDI_HDCP_SIGNALLING,
            if enable { TRANS_DDI_HDCP_SIGNALLING } else { 0 },
        );
    }

    /// `intel_hdcp_read_valid_bksv`: two tries.
    fn read_valid_bksv<S: HdcpShim>(shim: &mut S) -> Result<[u8; 5], HdcpError> {
        for _ in 0..2 {
            let bksv = shim.read_bksv()?;
            if ksv_valid(&bksv) {
                return Ok(bksv);
            }
        }
        Err(HdcpError::InvalidBksv)
    }

    /// `intel_hdcp_get_capability`: HDCP 1.4 on the sink.
    pub fn hdcp1_capable<S: HdcpShim>(shim: &mut S) -> bool {
        match shim.hdcp_capable() {
            Some(r) => r.unwrap_or(false),
            None => Self::read_valid_bksv(shim).is_ok(),
        }
    }

    /// `intel_write_sha_text`.
    fn write_sha_text<M, S, T, E>(cx: &mut Ctx<'_, M, S, T, E>, text: u32) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        cx.write(HDCP_SHA_TEXT, text);
        cx.wait(HDCP_REP_CTL, HDCP_SHA1_READY, HDCP_SHA1_READY, 1)
            .map(drop)
    }

    /// `intel_hdcp_validate_v_prime`: V' into `HDCP_SHA_V_PRIME`, then the
    /// KSV list, BSTATUS/BINFO and M0 through `HDCP_SHA_TEXT`, 64 bytes per
    /// `HDCP_REP_CTL` pass, big endian, and the bit length last.
    fn validate_v_prime<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
        ksv_fifo: &[u8],
        num: usize,
        bstatus: [u8; 2],
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        for i in 0..5 {
            let vprime = cx.shim.read_v_prime_part(i)?;
            cx.write(hdcp_sha_v_prime(i), vprime);
        }
        let mut sha_idx: usize = 0;
        let mut sha_text: u32 = 0;
        let mut leftovers: usize = 0;
        let rep_ctl = self.rep_ctl();
        cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
        for i in 0..num {
            let ksv = &ksv_fifo[i * 5..i * 5 + 5];
            let empty = 4 - leftovers;
            for (j, &b) in ksv.iter().enumerate().take(empty) {
                let off = (4 - j - 1 - leftovers) * 8;
                sha_text |= u32::from(b) << off;
            }
            Self::write_sha_text(cx, sha_text)?;
            sha_idx += 4;
            if sha_idx % 64 == 0 {
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
            }
            leftovers = 5 - empty;
            sha_text = 0;
            for j in 0..leftovers {
                sha_text |= u32::from(ksv[empty + j]) << ((4 - j - 1) * 8);
            }
            if 4 > leftovers {
                continue;
            }
            Self::write_sha_text(cx, sha_text)?;
            leftovers = 0;
            sha_text = 0;
            sha_idx += 4;
        }
        let bs0 = u32::from(bstatus[0]);
        let bs1 = u32::from(bstatus[1]);
        match leftovers {
            0 => {
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_16);
                Self::write_sha_text(cx, bs0 << 8 | bs1)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_0);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_16);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
            }
            1 => {
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_24);
                sha_text |= bs0 << 16 | bs1 << 8;
                sha_text = (sha_text & 0xffff_ff00) >> 8;
                Self::write_sha_text(cx, sha_text)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_0);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_8);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
            }
            2 => {
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
                sha_text |= bs0 << 8 | bs1;
                Self::write_sha_text(cx, sha_text)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_0);
                for _ in 0..2 {
                    Self::write_sha_text(cx, 0)?;
                    sha_idx += 4;
                }
                // The hardware appends the terminator itself in the
                // other cases.
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
                Self::write_sha_text(cx, SHA1_TERMINATOR << 24)?;
                sha_idx += 4;
            }
            3 => {
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
                sha_text |= bs0;
                Self::write_sha_text(cx, sha_text)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_8);
                Self::write_sha_text(cx, bs1)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_0);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
                cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_24);
                Self::write_sha_text(cx, 0)?;
                sha_idx += 4;
            }
            _ => return Err(HdcpError::VPrimeMismatch),
        }
        cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_TEXT_32);
        while sha_idx % 64 < 64 - 4 {
            Self::write_sha_text(cx, 0)?;
            sha_idx += 4;
        }
        // The bit length: 5 bytes per device plus BSTATUS (2) and M0 (8).
        Self::write_sha_text(cx, ((num * 5 + 10) * 8) as u32)?;
        cx.write(HDCP_REP_CTL, rep_ctl | HDCP_SHA1_COMPLETE_HASH);
        cx.wait(HDCP_REP_CTL, HDCP_SHA1_COMPLETE, HDCP_SHA1_COMPLETE, 1)?;
        if cx.read(HDCP_REP_CTL) & HDCP_SHA1_V_MATCH == 0 {
            return Err(HdcpError::VPrimeMismatch);
        }
        Ok(())
    }

    /// `intel_hdcp_auth_downstream`: part 2, the repeater.
    async fn auth_downstream<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        // intel_hdcp_poll_ksv_fifo: every 100 ms, at most 5 s.
        let start = cx.env.now_us();
        loop {
            if cx.shim.read_ksv_ready()? {
                break;
            }
            if cx.env.now_us().saturating_sub(start) >= 5_000_000 {
                return Err(HdcpError::Timeout);
            }
            cx.env.delay_ms(100).await;
        }
        let bstatus = cx.shim.read_bstatus()?;
        if max_device_exceeded(bstatus[0]) || max_cascade_exceeded(bstatus[1]) {
            return Err(HdcpError::TopologyExceeded);
        }
        let num = usize::from(num_downstream(bstatus[0]));
        if num == 0 {
            return Err(HdcpError::NoDownstream);
        }
        let mut fifo = vec![0u8; num * msg::KSV_LEN];
        cx.shim.read_ksv_fifo(num, &mut fifo)?;
        if cx.env.revoked(&fifo) > 0 {
            return Err(HdcpError::Revoked);
        }
        // The DP spec mandates re-reading V' at least twice on mismatch.
        let mut ret = Err(HdcpError::VPrimeMismatch);
        for _ in 0..3 {
            ret = self.validate_v_prime(cx, &fifo, num, bstatus);
            if ret.is_ok() {
                break;
            }
        }
        ret
    }

    /// `intel_hdcp_auth`: part 1.
    async fn hdcp1_auth<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let (t, regs) = (self.transcoder, self.hw.regs);
        // HDCP over DP requires the capability check before An is written.
        if let Some(capable) = cx.shim.hdcp_capable() {
            if !capable? {
                return Err(HdcpError::NotCapable);
            }
        }
        for _ in 0..2 {
            let r = cx.env.random_u32();
            cx.write(regs.aninit(t), r);
        }
        cx.write(self.conf(), HDCP_CONF_CAPTURE_AN);
        cx.wait(self.status(), HDCP_STATUS_AN_READY, HDCP_STATUS_AN_READY, 1)?;
        let mut an = [0u8; 8];
        an[..4].copy_from_slice(&cx.read(regs.anlo(t)).to_le_bytes());
        an[4..].copy_from_slice(&cx.read(regs.anhi(t)).to_le_bytes());
        cx.shim.write_an_aksv(&an)?;
        let r0_start = cx.env.now_us();
        let bksv = Self::read_valid_bksv(cx.shim)?;
        if cx.env.revoked(&bksv) > 0 {
            return Err(HdcpError::Revoked);
        }
        cx.write(
            regs.bksvlo(t),
            u32::from_le_bytes([bksv[0], bksv[1], bksv[2], bksv[3]]),
        );
        cx.write(regs.bksvhi(t), u32::from(bksv[4]));
        let repeater = cx.shim.repeater_present()?;
        if repeater {
            cx.write(HDCP_REP_CTL, self.rep_ctl());
        }
        self.toggle_signalling(cx, true);
        cx.write(self.conf(), HDCP_CONF_AUTH_AND_ENC);
        cx.poll_any(self.status(), HDCP_STATUS_R0_READY | HDCP_STATUS_ENC, 1000)
            .map_err(|_| HdcpError::Timeout)?;
        // R0' is available 100 ms after Aksv; some monitors take longer.
        let elapsed_ms = cx.env.now_us().saturating_sub(r0_start) / 1000;
        if elapsed_ms < 300 {
            cx.env.delay_ms(300 - elapsed_ms).await;
        }
        // DP: two more tries on an R0' mismatch.
        let mut matched = false;
        for _ in 0..3 {
            let ri = cx.shim.read_ri_prime()?;
            cx.write(regs.rprime(t), u32::from(u16::from_le_bytes(ri)));
            if cx
                .poll_any(self.status(), HDCP_STATUS_RI_MATCH | HDCP_STATUS_ENC, 1000)
                .is_ok()
            {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(HdcpError::RiMismatch);
        }
        cx.wait(
            self.status(),
            HDCP_STATUS_ENC,
            HDCP_STATUS_ENC,
            ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
        )?;
        // DP MST Auth Part 1 Step 2.a and 2.b: this stream's encryption.
        if let Some(stream) = self.stream_transcoder {
            self.mst_stream_encryption(cx, stream, true)?;
        }
        if repeater {
            return self.auth_downstream(cx).await;
        }
        Ok(())
    }

    /// `_intel_hdcp_disable`.
    fn hdcp1_disable<M, S, T, E>(&mut self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        // An MST stream's encryption first; the link stays up while other
        // connectors on the port use it.
        if let Some(stream) = self.stream_transcoder {
            self.mst_stream_encryption(cx, stream, false)?;
            if self.num_streams > 0 {
                return Ok(());
            }
        }
        self.hdcp_encrypted = false;
        cx.write(self.conf(), 0);
        cx.wait(self.status(), !0, 0, ENCRYPT_STATUS_CHANGE_TIMEOUT_MS)?;
        cx.rmw(HDCP_REP_CTL, self.rep_ctl(), 0);
        self.toggle_signalling(cx, false);
        Ok(())
    }

    /// `intel_hdcp1_enable`.
    async fn hdcp1_enable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if !self.key_loadable(cx.io) {
            return Err(HdcpError::KeyNotLoadable);
        }
        let mut ret = Err(HdcpError::KeyLoad);
        for _ in 0..KEY_LOAD_TRIES {
            ret = self.load_keys(cx);
            if ret.is_ok() {
                break;
            }
            Self::clear_keys(cx);
        }
        ret?;
        self.adjust_line_rekeying(cx, true);
        let mut last = Err(HdcpError::NotCapable);
        for _ in 0..3 {
            last = self.hdcp1_auth(cx).await;
            if last.is_ok() {
                self.hdcp_encrypted = true;
                self.hdcp2_encrypted = false;
                return Ok(());
            }
            // Make sure encryption and signalling are stopped.
            let _ = self.hdcp1_disable(cx);
        }
        last
    }

    /// `intel_hdcp_check_link`: part 3. Returns `Ok` while protected.
    async fn hdcp1_check_link<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.value != CpValue::Enabled || !self.hdcp_encrypted {
            return Err(HdcpError::NotEnabled);
        }
        if cx.read(self.status()) & HDCP_STATUS_ENC == 0 {
            self.update_value(CpValue::Desired);
            return Err(HdcpError::LinkStopped);
        }
        let good = match cx.shim.check_link_status() {
            Some(good) => good,
            None => self.hdmi_check_link(cx),
        };
        if good {
            return Ok(());
        }
        if let Err(e) = self.hdcp1_disable(cx) {
            self.update_value(CpValue::Desired);
            return Err(e);
        }
        if let Err(e) = self.hdcp1_enable(cx).await {
            self.update_value(CpValue::Desired);
            return Err(e);
        }
        Ok(())
    }

    /// `intel_hdmi_hdcp_check_link`: three tries of Ri' against the
    /// transmitter's Ri (`RI_MATCH` and `ENC` both set within 1 ms).
    fn hdmi_check_link<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> bool
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mask = HDCP_STATUS_RI_MATCH | HDCP_STATUS_ENC;
        for _ in 0..3 {
            let Ok(ri) = cx.shim.read_ri_prime() else {
                continue;
            };
            cx.write(
                self.hw.regs.rprime(self.transcoder),
                u32::from(u16::from_le_bytes(ri)),
            );
            if cx.wait(self.status(), mask, mask, 1).is_ok() {
                return true;
            }
        }
        false
    }
}

// ── HDCP 2.2 ─────────────────────────────────────────────────────────

impl HdcpLink {
    fn hdcp2_status(&self) -> u64 {
        self.hw.regs.hdcp2_status(self.transcoder)
    }

    /// `intel_hdcp2_prerequisite` + `intel_hdcp2_get_capability`.
    pub fn hdcp2_capable<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> bool
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.hdcp2_supported && cx.fw.is_some() && cx.shim.hdcp2_capable().unwrap_or(false)
    }

    /// `read_2_2_msg`: wait for the message as the shim's timing says,
    /// then read it. A detectable message on a shim that delivers CP_IRQ
    /// waits for the sink's CP_IRQ up to the message timeout and then
    /// checks its availability once (`intel_dp_hdcp2_wait_for_msg`); one
    /// without CP_IRQ polls the availability every `poll_ms`.
    async fn read_msg<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
        msg_id: u8,
        buf: &mut [u8],
    ) -> Result<usize, HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let timing = cx.shim.msg_timing(msg_id, self.is_paired)?;
        let available = if timing.detectable && cx.shim.cp_irq_pending().is_some() {
            let start = cx.env.now_us();
            while cx.shim.cp_irq_pending() == Some(false)
                && cx.env.now_us().saturating_sub(start) < timing.timeout_ms * 1000
            {
                cx.env.delay_ms(CP_IRQ_WAIT_MS).await;
            }
            cx.shim
                .msg_available(msg_id)?
                .ok_or(HdcpError::MsgTimeout)?
        } else if timing.detectable {
            let start = cx.env.now_us();
            loop {
                if let Some(size) = cx.shim.msg_available(msg_id)? {
                    break size;
                }
                if cx.env.now_us().saturating_sub(start) >= timing.timeout_ms * 1000 {
                    return Err(HdcpError::MsgTimeout);
                }
                cx.env.delay_ms(timing.poll_ms.max(1)).await;
            }
        } else {
            if timing.timeout_ms > 0 {
                cx.env.delay_ms(timing.timeout_ms).await;
            }
            0
        };
        cx.shim.cp_irq_consume();
        let start = cx.env.now_us();
        let size = cx.shim.read_2_2_msg(msg_id, available, buf)?;
        if timing.read_timeout_ms > 0
            && cx.env.now_us().saturating_sub(start) > timing.read_timeout_ms * 1000
        {
            return Err(HdcpError::MsgTimeout);
        }
        Ok(size)
    }

    /// `hdcp2_authentication_key_exchange`.
    async fn ake<M, S, T, E>(&mut self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.seq_num_v = 0;
        self.seq_num_m = 0;
        // DP retries the first exchange 10 times, 50 ms apart, while a dock
        // stops advertising HDCP 2.2 around suspend/resume.
        let max_retries = if self.protocol == Protocol::Dp { 10 } else { 1 };
        let ake_init = cx.fw()?.initiate_session(&self.port_data).await?;
        let mut cert = vec![0u8; msg::AKE_SEND_CERT_SIZE];
        let mut ret = Err(HdcpError::NotHdcp22);
        for _ in 0..max_retries {
            if !self.hdcp2_capable(cx) {
                cx.env.delay_ms(50).await;
                continue;
            }
            if let Err(e) = cx.shim.write_2_2_msg(&ake_init) {
                ret = Err(e);
                continue;
            }
            ret = self
                .read_msg(cx, msg::AKE_SEND_CERT, &mut cert)
                .await
                .map(drop);
            if ret.is_ok() {
                break;
            }
        }
        ret?;
        if cert[msg::CERT_RXCAPS] != msg::RX_CAPS_VERSION_VAL {
            return Err(HdcpError::NotHdcp22);
        }
        self.is_repeater = msg::rx_repeater(cert[msg::CERT_RXCAPS + 2]);
        if cx
            .env
            .revoked(&cert[msg::CERT_RECEIVER_ID..msg::CERT_RECEIVER_ID + msg::KSV_LEN])
            > 0
        {
            return Err(HdcpError::Revoked);
        }
        let (stored, km) = cx
            .fw()?
            .verify_receiver_cert(&self.port_data, &cert)
            .await?;
        self.is_paired = stored;
        cx.shim.write_2_2_msg(&km)?;
        let mut hprime = [0u8; msg::AKE_SEND_HPRIME_SIZE];
        self.read_msg(cx, msg::AKE_SEND_HPRIME, &mut hprime).await?;
        cx.fw()?.verify_hprime(&self.port_data, &hprime).await?;
        if !self.is_paired {
            let mut pairing = [0u8; msg::AKE_SEND_PAIRING_INFO_SIZE];
            self.read_msg(cx, msg::AKE_SEND_PAIRING_INFO, &mut pairing)
                .await?;
            cx.fw()?
                .store_pairing_info(&self.port_data, &pairing)
                .await?;
            self.is_paired = true;
        }
        Ok(())
    }

    /// `hdcp2_locality_check`: three tries.
    async fn locality_check<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mut ret = Err(HdcpError::MsgTimeout);
        for _ in 0..HDCP2_LC_RETRY_CNT {
            let lc_init = match cx.fw()?.initiate_locality_check(&self.port_data).await {
                Ok(m) => m,
                Err(e) => {
                    ret = Err(e.into());
                    continue;
                }
            };
            if let Err(e) = cx.shim.write_2_2_msg(&lc_init) {
                ret = Err(e);
                continue;
            }
            let mut lprime = [0u8; msg::LC_SEND_LPRIME_SIZE];
            if let Err(e) = self.read_msg(cx, msg::LC_SEND_LPRIME, &mut lprime).await {
                ret = Err(e);
                continue;
            }
            ret = cx
                .fw()?
                .verify_lprime(&self.port_data, &lprime)
                .await
                .map_err(Into::into);
            if ret.is_ok() {
                break;
            }
        }
        ret
    }

    /// `hdcp2_session_key_exchange`.
    async fn ske<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let eks = cx.fw()?.get_session_key(&self.port_data).await?;
        cx.shim.write_2_2_msg(&eks)
    }

    /// `hdcp2_authenticate_repeater_topology`.
    async fn repeater_topology<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mut list = vec![0u8; msg::REP_SEND_RECVID_LIST_SIZE];
        self.read_msg(cx, msg::REP_SEND_RECVID_LIST, &mut list)
            .await?;
        let rx_info = [list[msg::RECVID_RXINFO], list[msg::RECVID_RXINFO + 1]];
        if msg::max_cascade_exceeded(rx_info[1]) || msg::max_devs_exceeded(rx_info[1]) {
            return Err(HdcpError::TopologyExceeded);
        }
        // A topology with an HDCP 1.x or 2.0/2.1 device is not type-1
        // capable.
        self.mst_type1_capable =
            !msg::hdcp1_device_connected(rx_info[1]) && !msg::hdcp_2_0_rep_connected(rx_info[1]);
        if !self.mst_type1_capable && self.content_type != msg::STREAM_TYPE0 {
            return Err(HdcpError::Type1Downstream);
        }
        let seq_num_v = msg::be24_to_cpu([
            list[msg::RECVID_SEQ_NUM_V],
            list[msg::RECVID_SEQ_NUM_V + 1],
            list[msg::RECVID_SEQ_NUM_V + 2],
        ]);
        if !self.hdcp2_encrypted && seq_num_v != 0 {
            return Err(HdcpError::SeqNumV);
        }
        if self.hdcp2_encrypted && seq_num_v <= self.seq_num_v {
            return Err(HdcpError::SeqNumV);
        }
        let devices = msg::device_count(rx_info) as usize;
        let ids = &list[msg::RECVID_IDS..msg::RECVID_IDS + devices.min(msg::MAX_DEVICE_COUNT) * 5];
        if cx.env.revoked(ids) > 0 {
            return Err(HdcpError::Revoked);
        }
        let ack = cx
            .fw()?
            .repeater_check_flow_prepare_ack(&self.port_data, &list)
            .await?;
        self.seq_num_v = seq_num_v;
        cx.shim.write_2_2_msg(&ack)
    }

    /// `hdcp2_authenticate_sink`.
    async fn authenticate_sink<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.ake(cx).await?;
        self.locality_check(cx).await?;
        self.ske(cx).await?;
        cx.shim
            .config_stream_type(self.is_repeater, self.content_type)?;
        if self.is_repeater {
            self.repeater_topology(cx).await?;
        }
        Ok(())
    }

    /// `_hdcp2_propagate_stream_management_info`.
    async fn propagate_once<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.seq_num_m > msg::SEQ_NUM_MAX {
            return Err(HdcpError::SeqNumM);
        }
        let k = usize::from(self.port_data.k);
        let mut m = vec![msg::REP_STREAM_MANAGE];
        m.extend_from_slice(&msg::cpu_to_be24(self.seq_num_m));
        m.extend_from_slice(&self.port_data.k.to_be_bytes());
        for (id, ty) in &self.port_data.streams[..k] {
            m.push(*id);
            m.push(*ty);
        }
        let result = async {
            cx.shim.write_2_2_msg(&m)?;
            let mut ready = [0u8; msg::REP_STREAM_READY_SIZE];
            self.read_msg(cx, msg::REP_STREAM_READY, &mut ready).await?;
            Ok::<_, HdcpError>(ready)
        }
        .await;
        let ret = match result {
            Ok(ready) => {
                self.port_data.seq_num_m = self.seq_num_m;
                cx.fw()?
                    .verify_mprime(&self.port_data, &ready)
                    .await
                    .map_err(Into::into)
            }
            Err(e) => Err(e),
        };
        self.seq_num_m += 1;
        ret
    }

    /// `hdcp2_propagate_stream_management_info`: repeaters only, three
    /// tries, stopping at a seq_num_m rollover.
    async fn propagate<M, S, T, E>(&mut self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if !self.is_repeater {
            return Ok(());
        }
        let mut ret = Ok(());
        for _ in 0..3 {
            ret = self.propagate_once(cx).await;
            if ret.is_ok() || self.seq_num_m > msg::SEQ_NUM_MAX {
                break;
            }
        }
        ret
    }

    /// `hdcp2_deauthenticate_port` (`close_hdcp_session`).
    async fn deauthenticate<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        cx.fw()?
            .close_session(&self.port_data)
            .await
            .map_err(Into::into)
    }

    /// `hdcp2_enable_encryption`.
    fn enable_encryption<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.toggle_signalling(cx, true);
        if cx.read(self.hdcp2_status()) & LINK_AUTH_STATUS != 0 {
            cx.rmw(
                self.hw.regs.hdcp2_ctl(self.transcoder),
                0,
                CTL_LINK_ENCRYPTION_REQ,
            );
        }
        let ret = cx
            .wait(
                self.hdcp2_status(),
                LINK_ENCRYPTION_STATUS,
                LINK_ENCRYPTION_STATUS,
                ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
            )
            .map(drop);
        self.auth_status = true;
        ret
    }

    /// `hdcp2_disable_encryption`. Linux lets the signalling toggle's
    /// result replace a status timeout.
    fn disable_encryption<M, S, T, E>(&self, cx: &mut Ctx<'_, M, S, T, E>) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        cx.rmw(
            self.hw.regs.hdcp2_ctl(self.transcoder),
            CTL_LINK_ENCRYPTION_REQ,
            0,
        );
        let _ = cx.wait(
            self.hdcp2_status(),
            LINK_ENCRYPTION_STATUS,
            0,
            ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
        );
        self.toggle_signalling(cx, false);
        Ok(())
    }

    /// `hdcp2_enable_stream_encryption` for one stream: the link must be
    /// encrypted.
    async fn enable_stream_encryption<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if cx.read(self.hdcp2_status()) & LINK_ENCRYPTION_STATUS == 0 {
            let _ = self.deauthenticate(cx).await;
            self.auth_status = false;
            self.port_data.k = 0;
            return Err(HdcpError::LinkNotEncrypted);
        }
        if let Some(stream) = self.stream_transcoder {
            self.mst_stream_2_2_encryption(cx, stream, true)?;
        }
        Ok(())
    }

    /// `intel_hdcp_prepare_streams`: one stream of the content type for
    /// SST and HDMI; for DP MST `intel_hdcp_required_content_stream`, every
    /// stream of the port (the first only when it is the port's one stream),
    /// all type 1 when the topology is type-1 capable and all type 0
    /// otherwise. Nothing changes once the port is authenticated.
    fn prepare_streams(&mut self) -> Result<(), HdcpError> {
        if self.stream_transcoder.is_none() {
            self.port_data.k = 1;
            self.port_data.streams[0] = (0, self.content_type);
            return Ok(());
        }
        if self.auth_status {
            return Ok(());
        }
        if self.mst_vcpis.is_empty() || self.mst_vcpis.len() > msg::MAX_CONTENT_STREAMS {
            return Err(HdcpError::Unsupported);
        }
        let ty = if self.mst_type1_capable {
            msg::STREAM_TYPE1
        } else {
            msg::STREAM_TYPE0
        };
        for (i, &vcpi) in self.mst_vcpis.iter().enumerate() {
            self.port_data.streams[i] = (vcpi, ty);
        }
        self.port_data.k = self.mst_vcpis.len() as u16;
        Ok(())
    }

    /// `hdcp2_authenticate_and_encrypt`.
    async fn authenticate_and_encrypt<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mut ret = Ok(());
        for _ in 0..3 {
            if self.auth_status {
                break;
            }
            ret = self.authenticate_sink(cx).await;
            if ret.is_ok() {
                ret = self.prepare_streams();
                if ret.is_err() {
                    break;
                }
                ret = self.propagate(cx).await;
                if ret.is_err() {
                    break;
                }
                ret = cx
                    .fw()?
                    .enable_authentication(&self.port_data)
                    .await
                    .map_err(Into::into);
                if ret.is_ok() {
                    break;
                }
            }
            // Clear the firmware session before the next try.
            let _ = self.deauthenticate(cx).await;
        }
        if ret.is_ok() && !self.auth_status {
            // At least 200 ms between SKE and encryption.
            cx.env.delay_ms(DELAY_BEFORE_ENCRYPTION_MS).await;
            ret = self.enable_encryption(cx);
            if ret.is_err() {
                let _ = self.deauthenticate(cx).await;
            }
        }
        if ret.is_ok() {
            ret = self.enable_stream_encryption(cx).await;
        }
        ret
    }

    /// `_intel_hdcp2_enable`.
    async fn hdcp2_enable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.adjust_line_rekeying(cx, false);
        self.authenticate_and_encrypt(cx).await?;
        self.hdcp2_encrypted = true;
        self.hdcp_encrypted = false;
        Ok(())
    }

    /// `_intel_hdcp2_disable`: an MST stream's encryption first; the link
    /// stays up while other connectors use it, unless this is link
    /// recovery.
    async fn hdcp2_disable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
        recovery: bool,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if let Some(stream) = self.stream_transcoder {
            self.mst_stream_2_2_encryption(cx, stream, false)?;
            if self.num_streams > 0 && !recovery {
                return Ok(());
            }
        }
        let ret = self.disable_encryption(cx);
        let _ = self.deauthenticate(cx).await;
        self.hdcp2_encrypted = false;
        self.auth_status = false;
        self.port_data.k = 0;
        ret
    }

    /// `intel_hdcp2_check_link`. Returns `Ok` while protected.
    async fn hdcp2_check_link<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.value != CpValue::Enabled || !self.hdcp2_encrypted {
            return Err(HdcpError::NotEnabled);
        }
        if cx.read(self.hdcp2_status()) & LINK_ENCRYPTION_STATUS == 0 {
            let _ = self.hdcp2_disable(cx, true).await;
            self.update_value(CpValue::Desired);
            return Err(HdcpError::LinkStopped);
        }
        // intel_dp_mst_hdcp2_check_link: only the connector that
        // authenticated the port reads the sink's link status.
        let check = if self.stream_transcoder.is_none() || self.is_repeater {
            cx.shim.check_2_2_link()
        } else {
            Ok(LinkCheck::Protected)
        };
        match check {
            Ok(LinkCheck::Protected) => return Ok(()),
            Ok(LinkCheck::TopologyChange) => {
                if self.repeater_topology(cx).await.is_ok() {
                    return Ok(());
                }
            }
            _ => {}
        }
        let ret = self.hdcp2_disable(cx, true).await;
        self.update_value(CpValue::Desired);
        ret.and(Err(HdcpError::LinkStopped))
    }
}

// ── The connector operations ─────────────────────────────────────────

impl HdcpLink {
    /// `_intel_hdcp_enable`: HDCP 2.2 when the platform and sink can, else
    /// HDCP 1.4 unless the content is type 1. ENABLED on success.
    pub async fn enable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
        content_type: u8,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.enable_with(cx, content_type, Versions::ANY).await
    }

    /// [`HdcpLink::enable`] limited to `versions`.
    pub async fn enable_with<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
        content_type: u8,
        versions: Versions,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.content_type = content_type;
        // Display 12+ only: below it the transcoder stays invalid.
        if self.hw.regs == HdcpRegs::Transcoder {
            self.port_data.hdcp_transcoder = msg::hdcp_transcoder(self.transcoder);
        }
        let mut ret = Err(HdcpError::Type1Unavailable);
        if versions.hdcp2 && !self.force_hdcp14 && self.hdcp2_capable(cx) {
            ret = self.hdcp2_enable(cx).await;
        }
        if ret.is_err()
            && versions.hdcp1
            && self.content_type != msg::STREAM_TYPE1
            && Self::hdcp1_capable(cx.shim)
        {
            ret = self.hdcp1_enable(cx).await;
        }
        if ret.is_ok() {
            self.update_value(CpValue::Enabled);
        }
        ret
    }

    /// `intel_hdcp_disable`: UNDESIRED, then whichever version is
    /// encrypted goes down.
    pub async fn disable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.value == CpValue::Undesired {
            return Ok(());
        }
        self.update_value(CpValue::Undesired);
        if self.hdcp2_encrypted {
            self.hdcp2_disable(cx, false).await
        } else if self.hdcp_encrypted {
            self.hdcp1_disable(cx)
        } else {
            Ok(())
        }
    }

    /// `intel_hdcp_check_work`'s check: the HDCP 2.2 link check when HDCP
    /// 2.2 is encrypted, else the HDCP 1.4 one. `Ok` keeps the check
    /// scheduled at [`HdcpLink::check_period_ms`].
    pub async fn check_link<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if !self.force_hdcp14 && self.hdcp2_encrypted {
            self.hdcp2_check_link(cx).await
        } else {
            self.hdcp1_check_link(cx).await
        }
    }

    /// The check interval of the encrypted version.
    pub fn check_period_ms(&self) -> u64 {
        if self.hdcp2_encrypted {
            HDCP2_CHECK_PERIOD_MS
        } else {
            HDCP_CHECK_PERIOD_MS
        }
    }

    /// The registers of an interrupted operation, put back to off without
    /// waiting (a route about to go down, or a cancelled enable): what
    /// `_intel_hdcp_disable` and `hdcp2_disable_encryption` write.
    /// Returns `true` when the firmware session may still be open.
    pub fn force_off<M: MmioWindow + ?Sized>(&mut self, io: &M) -> bool {
        let (t, regs) = (self.transcoder, self.hw.regs);
        io.write32(regs.conf(t), 0);
        let ctl = io.read32(regs.hdcp2_ctl(t));
        io.write32(regs.hdcp2_ctl(t), ctl & !CTL_LINK_ENCRYPTION_REQ);
        let rep = io.read32(HDCP_REP_CTL);
        io.write32(HDCP_REP_CTL, rep & !self.rep_ctl());
        if self.protocol == Protocol::Hdmi {
            let f = io.read32(trans_ddi_func_ctl(t));
            io.write32(trans_ddi_func_ctl(t), f & !TRANS_DDI_HDCP_SIGNALLING);
        }
        let session = self.hdcp2_encrypted || self.auth_status;
        self.hdcp_encrypted = false;
        self.hdcp2_encrypted = false;
        self.auth_status = false;
        self.port_data.k = 0;
        if self.value == CpValue::Enabled {
            self.update_value(CpValue::Desired);
        }
        session
    }
}

/// The uAPI side of one connector: what userspace asked for
/// (`conn_state->content_protection`, `hdcp_content_type`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Uapi {
    pub cp: CpValue,
    pub content_type: u8,
}

/// What a commit asks of the link (`intel_hdcp_update_pipe`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Commit {
    /// Nothing changes.
    Keep,
    /// Disable (UNDESIRED, or before a type change).
    Disable,
    /// Enable with the uAPI content type (after a disable when the type
    /// changed).
    Enable { disable_first: bool },
    /// Already enabled: report ENABLED (`prop_work`).
    Report,
}

/// `intel_hdcp_update_pipe`'s decision for `uapi` against the link.
pub fn update_pipe(link: &HdcpLink, uapi: Uapi) -> Commit {
    update_pipe_for(link.value, link.content_type, uapi)
}

/// [`update_pipe`] against a connector's `value` and `content_type`.
pub fn update_pipe_for(value: CpValue, content_type: u8, uapi: Uapi) -> Commit {
    let type_changed = uapi.content_type != content_type && uapi.cp != CpValue::Undesired;
    if uapi.cp == CpValue::Undesired {
        return if value == CpValue::Undesired {
            Commit::Keep
        } else {
            Commit::Disable
        };
    }
    if type_changed {
        return Commit::Enable {
            disable_first: true,
        };
    }
    if uapi.cp == CpValue::Desired {
        return if value != CpValue::Enabled {
            Commit::Enable {
                disable_first: false,
            }
        } else {
            Commit::Report
        };
    }
    Commit::Keep
}

/// `intel_hdcp_enable`'s condition at encoder enable: DESIRED, or ENABLED
/// that the driver has not (yet) enabled.
pub fn enable_on_route(link: &HdcpLink, uapi: Uapi) -> bool {
    enable_on_route_for(link.value, uapi)
}

/// [`enable_on_route`] against a connector's `value`.
pub fn enable_on_route_for(value: CpValue, uapi: Uapi) -> bool {
    uapi.cp == CpValue::Desired || (uapi.cp == CpValue::Enabled && value == CpValue::Undesired)
}

/// `intel_hdcp_atomic_check`'s rule for a connector losing its CRTC (its
/// route): ENABLED goes back to DESIRED so it re-enables when the route
/// returns.
pub fn route_lost(uapi: &mut Uapi) {
    if uapi.cp == CpValue::Enabled {
        uapi.cp = CpValue::Desired;
    }
}

/// `drm_atomic_connector_set_property`: userspace may not set ENABLED.
pub fn uapi_set(cp: u64) -> Option<CpValue> {
    match CpValue::from_u64(cp)? {
        CpValue::Enabled => None,
        v => Some(v),
    }
}

/// `intel_hdcp_prop_work` + `drm_hdcp_update_content_protection`: the
/// driver's DESIRED/ENABLED flips reach the uAPI; UNDESIRED is
/// userspace's own. Returns `true` when the uAPI value changed (Linux
/// sends the uevent there).
pub fn report(uapi: &mut Uapi, value: CpValue) -> bool {
    if value == CpValue::Undesired || uapi.cp == value {
        return false;
    }
    uapi.cp = value;
    true
}

/// The DRM property names and enum entries
/// (`drm_cp_enum_list`, `drm_hdcp_content_type_enum_list`).
pub const CONTENT_PROTECTION_NAME: &[u8] = b"Content Protection";
pub const HDCP_CONTENT_TYPE_NAME: &[u8] = b"HDCP Content Type";

#[path = "intel_hdcp_mst.rs"]
pub mod mst;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_hdcp_tests.rs"]
mod tests;

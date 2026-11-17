//! Nova Lake display-35.00 LT-PHY protocol model.
//!
//! Linux selects LT PHY through `HAS_LT_PHY(display)`, which is exactly
//! `platform.novalake`; Panther/Wildcat Lake remain on C10/C20. Nova Lake's
//! A/B and Type-C TC1/TC2 ports have the LT register layout. This module
//! contains the source-qualified portion of Linux's `intel_lt_phy.c` contract:
//! port/register selection, DP and eDP PLL images, VDR write-image
//! construction, transmitter ownership/masking, DP signal-level tables and
//! the disconnected MMIO transport. A strict, read-only display-35 route proof
//! grants no programming authority; production remains disconnected.
//!
//! Pinned source: the local Linux tree's
//! `drivers/gpu/drm/i915/display/{intel_lt_phy.c,intel_lt_phy_regs.h,
//! intel_ddi_buf_trans.c}`.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_xe2lpd::{DisplayIdentity, IpError, DFSM_PIPE_A_DISABLE, SKL_DFSM};
use crate::intel_gpu_xelpg::{
    lane_pclk_pll_ack, lane_pclk_pll_request, lane_phy_current_status, lane_pipe_reset,
    lane_powerdown_new_state, lane_powerdown_update, Cx0Error, Cx0Phy, PhyLaneConfig, XeLpgPort,
    FORWARD_CLOCK_UNGATE, LANE1_PHY_CLOCK_SELECT, P0_STATE_ACTIVE, P2_STATE_READY, P2_STATE_RESET,
    PLL_LANE_STAGGERING_DELAY_MASK, PORT_BUF_REVERSAL, POWER_STATE_ACTIVE_MASK,
    POWER_STATE_READY_MASK, SSC_ENABLE_PLLA, SSC_ENABLE_PLLB, XE3_DDI_CLOCK_SELECT_MASK,
};

/// Destructive display option reserved for the exact Nova Lake-S route.
pub(crate) const OPT_IN: &str = "narf.intel.nvl_display";
const PICA_PHY_CONFIG_CONTROL: u64 = 0x16_fe68;
const EDP_ON_TYPEC: u32 = 1 << 31;
const TRANSCONF_A: u64 = 0x70_008;

/// Strict option grammar shared by Intel's destructive route gates.
pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

/// Why display 35.00 remains on the headless profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteRefusal {
    UnsupportedPlatform,
    NotRequested,
    Ip(IpError),
    PipeAFused,
    EdpOnTypeC,
    PipeADark,
}

/// Exact, read-only Nova Lake-S display-35 route proof. This does not build a
/// [`crate::intel_gpu_xe2lpd::DisplayIp`] and therefore grants no modeset or
/// LT-PHY programming authority.
pub(crate) fn display_route(
    platform: GtPlatform,
    requested: bool,
    io: &(impl MmioWindow + ?Sized),
) -> Result<DisplayIdentity, RouteRefusal> {
    if platform != GtPlatform::NovaLakeS {
        return Err(RouteRefusal::UnsupportedPlatform);
    }
    if !requested {
        return Err(RouteRefusal::NotRequested);
    }
    let identity = DisplayIdentity::read(io).map_err(RouteRefusal::Ip)?;
    if identity != DisplayIdentity::NovaLakeS {
        let (ver, rel) = identity.version();
        return Err(RouteRefusal::Ip(IpError::Unqualified { ver, rel }));
    }
    let dfsm = io.read32(SKL_DFSM);
    let pica = io.read32(PICA_PHY_CONFIG_CONTROL);
    let conf = io.read32(TRANSCONF_A);
    if dfsm == u32::MAX || pica == u32::MAX || conf == u32::MAX || !io.display_access_ok() {
        return Err(RouteRefusal::Ip(IpError::NoDevice));
    }
    if dfsm & DFSM_PIPE_A_DISABLE != 0 {
        return Err(RouteRefusal::PipeAFused);
    }
    if pica & EDP_ON_TYPEC != 0 {
        return Err(RouteRefusal::EdpOnTypeC);
    }
    if conf & (3 << 30) != 3 << 30 {
        return Err(RouteRefusal::PipeADark);
    }
    Ok(identity)
}

pub(crate) const LANE0: u8 = 1;
pub(crate) const LANE1: u8 = 2;
pub(crate) const BOTH_LANES: u8 = LANE0 | LANE1;

pub(crate) const LT_PHY_VDR_0_CONFIG: u16 = 0x0c02;
pub(crate) const LT_PHY_VDR_1_CONFIG: u16 = 0x0c03;
pub(crate) const LT_PHY_VDR_2_CONFIG: u16 = 0x0cc3;
pub(crate) const LT_PHY_RATE_UPDATE: u16 = 0x0cc4;
pub(crate) const LT_PHY_RATE_CONTROL_VDR_UPDATE: u8 = 1;
pub(crate) const LT_PHY_MAC_VDR: u16 = 0x0c00;
pub(crate) const LT_PHY_PCLKIN_GATE: u8 = 1;

pub(crate) const LT_PHY_TX_LANE_ENABLE: u8 = 1;
pub(crate) const LT_PLL_REGISTER_COUNT: usize = 13;
pub(crate) const LT_PLL_PROGRAM_WRITE_COUNT: usize = 3 + LT_PLL_REGISTER_COUNT * 6;

/// Ports covered by Linux's two LT-PHY register ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LtPort {
    A,
    B,
    Tc1,
    Tc2,
}

impl LtPort {
    pub(crate) const fn from_xelpg(port: XeLpgPort) -> Option<Self> {
        match port {
            XeLpgPort::A => Some(Self::A),
            XeLpgPort::B => Some(Self::B),
            XeLpgPort::Tc1 => Some(Self::Tc1),
            XeLpgPort::Tc2 => Some(Self::Tc2),
            XeLpgPort::Tc3 | XeLpgPort::Tc4 => None,
        }
    }

    /// `XE3PLPD_PORT_BUF_CTL5(port)`.
    pub(crate) const fn buf_ctl5(self) -> u64 {
        match self {
            Self::A => 0x64_038,
            Self::B => 0x64_138,
            Self::Tc1 => 0x16_f234,
            Self::Tc2 => 0x16_f434,
        }
    }

    /// `XE3PLPD_PORT_P2M_MSGBUS_STATUS_P2P(port, lane)`.
    pub(crate) const fn p2m_status_p2p(self, lane: u8) -> Option<u64> {
        let base = match self {
            Self::A => 0x64_0a0,
            Self::B => 0x64_1a0,
            Self::Tc1 => 0x16_f2a0,
            Self::Tc2 => 0x16_f4a0,
        };
        match lane {
            0 | 1 => Some(base + lane as u64 * 4),
            _ => None,
        }
    }

    const fn xelpg(self) -> XeLpgPort {
        match self {
            Self::A => XeLpgPort::A,
            Self::B => XeLpgPort::B,
            Self::Tc1 => XeLpgPort::Tc1,
            Self::Tc2 => XeLpgPort::Tc2,
        }
    }
}

/// DP rates with a source LT-PLL image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LtDpRate {
    Rbr,
    Hbr,
    Hbr2,
    Hbr3,
    Uhbr10,
    Uhbr13_5,
    Uhbr20,
}

impl LtDpRate {
    pub(crate) const fn clock_khz(self) -> u32 {
        match self {
            Self::Rbr => 162_000,
            Self::Hbr => 270_000,
            Self::Hbr2 => 540_000,
            Self::Hbr3 => 810_000,
            Self::Uhbr10 => 1_000_000,
            Self::Uhbr13_5 => 1_350_000,
            Self::Uhbr20 => 2_000_000,
        }
    }

    pub(crate) const fn from_clock_khz(clock_khz: u32) -> Option<Self> {
        match clock_khz {
            162_000 => Some(Self::Rbr),
            270_000 => Some(Self::Hbr),
            540_000 => Some(Self::Hbr2),
            810_000 => Some(Self::Hbr3),
            1_000_000 => Some(Self::Uhbr10),
            1_350_000 => Some(Self::Uhbr13_5),
            2_000_000 => Some(Self::Uhbr20),
            _ => None,
        }
    }

    pub(crate) const fn is_uhbr(self) -> bool {
        matches!(self, Self::Uhbr10 | Self::Uhbr13_5 | Self::Uhbr20)
    }
}

/// eDP rates in Linux's `xe3plpd_lt_edp_tables`, including the four shared
/// DP 1.4 images and five eDP-only images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LtEdpRate {
    Rbr,
    Edp216,
    Edp243,
    Hbr,
    Edp324,
    Edp432,
    Hbr2,
    Edp675,
    Hbr3,
}

impl LtEdpRate {
    pub(crate) const fn clock_khz(self) -> u32 {
        match self {
            Self::Rbr => 162_000,
            Self::Edp216 => 216_000,
            Self::Edp243 => 243_000,
            Self::Hbr => 270_000,
            Self::Edp324 => 324_000,
            Self::Edp432 => 432_000,
            Self::Hbr2 => 540_000,
            Self::Edp675 => 675_000,
            Self::Hbr3 => 810_000,
        }
    }

    pub(crate) const fn from_clock_khz(clock_khz: u32) -> Option<Self> {
        match clock_khz {
            162_000 => Some(Self::Rbr),
            216_000 => Some(Self::Edp216),
            243_000 => Some(Self::Edp243),
            270_000 => Some(Self::Hbr),
            324_000 => Some(Self::Edp324),
            432_000 => Some(Self::Edp432),
            540_000 => Some(Self::Hbr2),
            675_000 => Some(Self::Edp675),
            810_000 => Some(Self::Hbr3),
            _ => None,
        }
    }
}

/// One internal PLL register and its big-endian VDR byte image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtPllRegister {
    pub(crate) address: u16,
    pub(crate) data: [u8; 4],
}

/// Complete `intel_lt_phy_pll_state` subset needed for a DP link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtPllState {
    pub(crate) clock_khz: u32,
    pub(crate) config: [u8; 3],
    addresses: [u16; LT_PLL_REGISTER_COUNT],
    data: [[u8; 4]; LT_PLL_REGISTER_COUNT],
}

impl LtPllState {
    pub(crate) const fn register(self, index: usize) -> Option<LtPllRegister> {
        if index >= LT_PLL_REGISTER_COUNT {
            return None;
        }
        Some(LtPllRegister {
            address: self.addresses[index],
            data: self.data[index],
        })
    }
}

const PLL_A_ADDRESSES: [u16; LT_PLL_REGISTER_COUNT] = [
    0x8510, 0x850c, 0x8514, 0x85e4, 0x860c, 0x8610, 0x8614, 0x8618, 0x8648, 0x8640, 0x864c, 0x8624,
    0x8644,
];
const PLL_B_ADDRESSES: [u16; LT_PLL_REGISTER_COUNT] = [
    0x8710, 0x870c, 0x8714, 0x87e4, 0x880c, 0x8810, 0x8814, 0x8818, 0x8848, 0x8840, 0x884c, 0x8824,
    0x8844,
];

const DP_RBR: LtPllState = LtPllState {
    clock_khz: 162_000,
    config: [0x83, 0x2d, 0x00],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x05, 0x0a, 0x2a, 0x20],
        [0x80, 0x00, 0x00, 0x00],
        [0x04, 0x04, 0x82, 0x28],
        [0xfa, 0x16, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x05, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x4b, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0a],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_HBR: LtPllState = LtPllState {
    clock_khz: 270_000,
    config: [0x8b, 0x2d, 0x00],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x03, 0xca, 0x34, 0xa0],
        [0xe0, 0x00, 0x00, 0x00],
        [0x05, 0x04, 0x81, 0xad],
        [0xfa, 0x11, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x07, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x43, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0d],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_HBR2: LtPllState = LtPllState {
    clock_khz: 540_000,
    config: [0x93, 0x2d, 0x00],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x01, 0x4d, 0x34, 0xa0],
        [0xe0, 0x00, 0x00, 0x00],
        [0x0a, 0x04, 0x81, 0xda],
        [0xfa, 0x11, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x07, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x43, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0d],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_HBR3: LtPllState = LtPllState {
    clock_khz: 810_000,
    config: [0x9b, 0x2d, 0x00],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x01, 0x4a, 0x34, 0xa0],
        [0xe0, 0x00, 0x00, 0x00],
        [0x05, 0x04, 0x80, 0xa8],
        [0xfa, 0x11, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x07, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x43, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0d],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_UHBR10: LtPllState = LtPllState {
    clock_khz: 1_000_000,
    config: [0x43, 0x2d, 0x00],
    addresses: PLL_A_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x01, 0x0a, 0x20, 0x80],
        [0x6a, 0xaa, 0xaa, 0xab],
        [0x00, 0x03, 0x04, 0x94],
        [0xfa, 0x1c, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x04, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x45, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x14, 0x2a, 0x14],
        [0x00, 0x5b, 0xe0, 0x08],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_UHBR13_5: LtPllState = LtPllState {
    clock_khz: 1_350_000,
    config: [0xcb, 0x2d, 0x00],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x02, 0x09, 0x2b, 0xe0],
        [0x90, 0x00, 0x00, 0x00],
        [0x08, 0x04, 0x80, 0xe0],
        [0xfa, 0x15, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x06, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x49, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x57, 0xe0, 0x0c],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const DP_UHBR20: LtPllState = LtPllState {
    clock_khz: 2_000_000,
    config: [0x53, 0x2d, 0x00],
    addresses: PLL_A_ADDRESSES,
    data: DP_UHBR10.data,
};

const EDP_216: LtPllState = LtPllState {
    clock_khz: 216_000,
    config: [0xa3, 0x2d, 0x01],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x03, 0xca, 0x2a, 0x20],
        [0x80, 0x00, 0x00, 0x00],
        [0x06, 0x04, 0x81, 0xbc],
        [0xfa, 0x16, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x05, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x4b, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0a],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const EDP_243: LtPllState = LtPllState {
    clock_khz: 243_000,
    config: [0xab, 0x2d, 0x01],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x03, 0xca, 0x2f, 0x60],
        [0xb0, 0x00, 0x00, 0x00],
        [0x06, 0x04, 0x81, 0xbc],
        [0xfa, 0x13, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x06, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x47, 0x48, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0c],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const EDP_324: LtPllState = LtPllState {
    clock_khz: 324_000,
    config: [0xb3, 0x2d, 0x01],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x02, 0x8a, 0x2a, 0x20],
        [0x80, 0x00, 0x00, 0x00],
        [0x06, 0x04, 0x81, 0x28],
        [0xfa, 0x16, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x05, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x4b, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0a],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const EDP_432: LtPllState = LtPllState {
    clock_khz: 432_000,
    config: [0xbb, 0x2d, 0x01],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x01, 0x4d, 0x2a, 0x20],
        [0x80, 0x00, 0x00, 0x00],
        [0x0c, 0x04, 0x81, 0xbc],
        [0xfa, 0x16, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x05, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x4b, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x5b, 0xe0, 0x0a],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

const EDP_675: LtPllState = LtPllState {
    clock_khz: 675_000,
    config: [0xdb, 0x2d, 0x01],
    addresses: PLL_B_ADDRESSES,
    data: [
        [0x00, 0x4c, 0x02, 0x00],
        [0x01, 0x4a, 0x2b, 0xe0],
        [0x90, 0x00, 0x00, 0x00],
        [0x06, 0x04, 0x80, 0xa8],
        [0xfa, 0x15, 0x83, 0x11],
        [0x80, 0x0f, 0xf9, 0x53],
        [0x84, 0x26, 0x06, 0x04],
        [0x00, 0xe0, 0x01, 0x00],
        [0x49, 0x48, 0x00, 0x00],
        [0x27, 0x08, 0x00, 0x00],
        [0x5a, 0x13, 0x29, 0x13],
        [0x00, 0x57, 0xe0, 0x0c],
        [0x00, 0x00, 0x00, 0x00],
    ],
};

pub(crate) const fn dp_pll_state(rate: LtDpRate) -> &'static LtPllState {
    match rate {
        LtDpRate::Rbr => &DP_RBR,
        LtDpRate::Hbr => &DP_HBR,
        LtDpRate::Hbr2 => &DP_HBR2,
        LtDpRate::Hbr3 => &DP_HBR3,
        LtDpRate::Uhbr10 => &DP_UHBR10,
        LtDpRate::Uhbr13_5 => &DP_UHBR13_5,
        LtDpRate::Uhbr20 => &DP_UHBR20,
    }
}

/// Exact `xe3plpd_lt_edp_tables` selection. The common 162/270/540/810 MHz
/// entries intentionally reuse the DP images; the intermediate eDP rates use
/// their own config byte and PLL data.
pub(crate) const fn edp_pll_state(rate: LtEdpRate) -> &'static LtPllState {
    match rate {
        LtEdpRate::Rbr => &DP_RBR,
        LtEdpRate::Edp216 => &EDP_216,
        LtEdpRate::Edp243 => &EDP_243,
        LtEdpRate::Hbr => &DP_HBR,
        LtEdpRate::Edp324 => &EDP_324,
        LtEdpRate::Edp432 => &EDP_432,
        LtEdpRate::Hbr2 => &DP_HBR2,
        LtEdpRate::Edp675 => &EDP_675,
        LtEdpRate::Hbr3 => &DP_HBR3,
    }
}

/// One committed VDR write in `intel_lt_phy_program_pll` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtVdrWrite {
    pub(crate) lane_mask: u8,
    pub(crate) address: u16,
    pub(crate) data: u8,
}

/// Return the indexed write from the exact 81-write DP PLL image.
pub(crate) const fn pll_program_write(
    state: &LtPllState,
    owned_lane_mask: u8,
    index: usize,
) -> Option<LtVdrWrite> {
    if owned_lane_mask == 0 || owned_lane_mask & !BOTH_LANES != 0 {
        return None;
    }
    if index == 0 {
        return Some(LtVdrWrite {
            lane_mask: owned_lane_mask,
            address: LT_PHY_VDR_0_CONFIG,
            data: state.config[0],
        });
    }
    if index == 1 {
        return Some(LtVdrWrite {
            lane_mask: LANE0,
            address: LT_PHY_VDR_1_CONFIG,
            data: state.config[1],
        });
    }
    if index == 2 {
        return Some(LtVdrWrite {
            lane_mask: owned_lane_mask,
            address: LT_PHY_VDR_2_CONFIG,
            data: state.config[2],
        });
    }
    if index >= LT_PLL_PROGRAM_WRITE_COUNT {
        return None;
    }
    let image = index - 3;
    let register = image / 6;
    let byte = image % 6;
    let base = 0x0c04 + register as u16 * 6;
    let (address, data) = match byte {
        0 => (base, (state.addresses[register] >> 8) as u8),
        1 => (base + 1, state.addresses[register] as u8),
        2..=5 => (base + byte as u16, state.data[register][byte - 2]),
        _ => return None,
    };
    Some(LtVdrWrite {
        lane_mask: LANE0,
        address,
        data,
    })
}

/// Linux's `intel_lt_phy_get_owned_lane_mask` with invalid widths rejected.
pub(crate) const fn owned_lane_mask(dp_alt: bool, max_lanes: u8) -> Option<u8> {
    if !matches!(max_lanes, 1 | 2 | 4) {
        return None;
    }
    if dp_alt && max_lanes <= 2 {
        Some(LANE0)
    } else {
        Some(BOTH_LANES)
    }
}

/// Linux's four-transmitter selection for one LT PHY.
pub(crate) const fn transmitter_mask(
    lane_count: u8,
    lane_reversal: bool,
    dp_alt: bool,
    pin_assignment_d: bool,
) -> Option<u8> {
    let mask = match lane_count {
        1 if dp_alt && pin_assignment_d => 0b0001,
        1 if dp_alt => 0b0010,
        1 if lane_reversal => 0b1000,
        1 => 0b0001,
        2 if dp_alt => 0b0011,
        2 if lane_reversal => 0b1100,
        2 => 0b0011,
        3 if dp_alt => 0b0111,
        3 if lane_reversal => 0b1110,
        3 => 0b0111,
        4 => 0b1111,
        _ => return None,
    };
    Some(mask)
}

/// One P2P transmitter-enable operation. The live transport must verify the
/// matching MAC register after the committed write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtTxEnableWrite {
    pub(crate) lane_mask: u8,
    pub(crate) address: u16,
    pub(crate) data: u8,
    pub(crate) mac_offset: u16,
    pub(crate) expected_mac: u8,
}

pub(crate) const fn tx_enable_writes(mask: u8) -> Option<[LtTxEnableWrite; 4]> {
    if mask & !0x0f != 0 {
        return None;
    }
    let e0 = if mask & 1 != 0 {
        LT_PHY_TX_LANE_ENABLE
    } else {
        0
    };
    let e1 = if mask & 2 != 0 {
        LT_PHY_TX_LANE_ENABLE
    } else {
        0
    };
    let e2 = if mask & 4 != 0 {
        LT_PHY_TX_LANE_ENABLE
    } else {
        0
    };
    let e3 = if mask & 8 != 0 {
        LT_PHY_TX_LANE_ENABLE
    } else {
        0
    };
    Some([
        LtTxEnableWrite {
            lane_mask: LANE0,
            address: 0x040a,
            data: e0,
            mac_offset: 0x040a,
            expected_mac: e0,
        },
        LtTxEnableWrite {
            lane_mask: LANE0,
            address: 0x060a,
            data: e1,
            mac_offset: 0x060a,
            expected_mac: e1,
        },
        LtTxEnableWrite {
            lane_mask: LANE1,
            address: 0x040a,
            data: e2,
            mac_offset: 0x040a,
            expected_mac: e2,
        },
        LtTxEnableWrite {
            lane_mask: LANE1,
            address: 0x060a,
            data: e3,
            mac_offset: 0x060a,
            expected_mac: e3,
        },
    ])
}

/// One `xe3plpd_lt_phy_buf_trans` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtTxLevel {
    pub(crate) tx_swing: u8,
    pub(crate) tx_swing_level: u8,
    pub(crate) pre_cursor: u8,
    pub(crate) main_cursor: u8,
    pub(crate) post_cursor: u8,
}

const fn level(
    tx_swing: u8,
    tx_swing_level: u8,
    pre_cursor: u8,
    main_cursor: u8,
    post_cursor: u8,
) -> LtTxLevel {
    LtTxLevel {
        tx_swing,
        tx_swing_level,
        pre_cursor,
        main_cursor,
        post_cursor,
    }
}

pub(crate) const DP14_LEVELS: [LtTxLevel; 10] = [
    level(1, 0, 0, 21, 0),
    level(1, 1, 0, 24, 3),
    level(1, 2, 0, 28, 7),
    level(0, 3, 0, 35, 13),
    level(1, 1, 0, 27, 0),
    level(1, 2, 0, 31, 4),
    level(0, 3, 0, 39, 9),
    level(1, 2, 0, 35, 0),
    level(0, 3, 0, 41, 7),
    level(0, 3, 0, 48, 0),
];

pub(crate) const UHBR_LEVELS: [LtTxLevel; 16] = [
    level(0, 0, 0, 48, 0),
    level(0, 0, 0, 43, 5),
    level(0, 0, 0, 40, 8),
    level(0, 0, 0, 37, 11),
    level(0, 0, 0, 33, 15),
    level(0, 0, 2, 46, 0),
    level(0, 0, 2, 42, 4),
    level(0, 0, 2, 38, 8),
    level(0, 0, 2, 35, 11),
    level(0, 0, 2, 33, 13),
    level(0, 0, 4, 44, 0),
    level(0, 0, 4, 40, 4),
    level(0, 0, 4, 37, 7),
    level(0, 0, 4, 33, 11),
    level(0, 0, 8, 40, 0),
    level(1, 0, 2, 26, 2),
];

/// Signal table selected by the negotiated DP encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LtSignalProtocol {
    Dp14,
    Uhbr,
}

pub(crate) const fn signal_level(protocol: LtSignalProtocol, index: usize) -> Option<LtTxLevel> {
    match protocol {
        LtSignalProtocol::Dp14 if index < DP14_LEVELS.len() => Some(DP14_LEVELS[index]),
        LtSignalProtocol::Uhbr if index < UHBR_LEVELS.len() => Some(UHBR_LEVELS[index]),
        LtSignalProtocol::Dp14 | LtSignalProtocol::Uhbr => None,
    }
}

const fn txy_ctl(tx: u8, register: u16) -> Option<u16> {
    if tx < 2 {
        Some(0x0400 + tx as u16 * 0x0200 + register)
    } else {
        None
    }
}

// ── Disconnected Nova Lake transport ────────────────────────────
//
// These fields are the shared Cx0 message-bus encoding.  The LT P2P flow
// differs after the committed write: it waits for the normal P2M write ACK,
// leaves 150 us for the PHY to settle, then clears both the normal response
// and the LT-only P2P-ready latch. Linux currently carries the expected MAC
// address/value through this API but does not compare them with a register
// read; the descriptor consistency check below does not invent that read.

const M2P_TRANSACTION_PENDING: u32 = 1 << 31;
const M2P_COMMAND_WRITE_COMMITTED: u32 = 0x2 << 27;
const M2P_DATA_SHIFT: u32 = 16;
const M2P_TRANSACTION_RESET: u32 = 1 << 15;
const P2M_RESPONSE_READY: u32 = 1 << 31;
const P2M_COMMAND_MASK: u32 = 0xf << 27;
const P2M_COMMAND_WRITE_ACK: u32 = 0x5 << 27;
const P2M_ERROR_SET: u32 = 1 << 15;
const MSGBUS_ATTEMPTS: u8 = 3;
const MSGBUS_TIMEOUT_US: u64 = 1_000;
const P2P_SETTLE_US: u64 = 150;
const POWERDOWN_UPDATE_TIMEOUT_US: u64 = 2_000;
const MACCLK_TURNON_TIMEOUT_US: u64 = 2_000;
const MACCLK_TURNOFF_TIMEOUT_US: u64 = 1;
const RATE_CALIBRATION_TIMEOUT_US: u64 = 1_000;
const RESET_START_TIMEOUT_US: u64 = 10;
const RESET_END_TIMEOUT_US: u64 = 2_000;

const MACCLK_RESET_0: u32 = 1 << 11;
const MACCLK_RATE_MASK: u32 = 0x1f;
const MACCLK_RATE_DEFAULT: u32 = 0x1f;
const PHY_MODE_MASK: u32 = 0xf << 12;
const PHY_MODE_DP: u32 = 0x3 << 12;
const DDI_CLOCK_SELECT_MAXPCLK: u32 = 0x8 << 12;

const fn phy_pulse_status(lane: u8) -> u32 {
    1 << (27 - lane)
}

/// Inputs to the LT-PHY DP PLL enable sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LtDpEnable {
    pub(crate) rate: LtDpRate,
    pub(crate) lane_count: u8,
    pub(crate) pin_assignment_d: bool,
    pub(crate) ssc_enabled: bool,
}

/// Nova Lake LT-PHY message-bus transport. Construction is family-qualified but
/// this type is not reachable from any display route.
pub(crate) struct LtPhy<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    port: LtPort,
    lanes: PhyLaneConfig,
    dp_alt: bool,
    max_lanes: u8,
}

impl<M: MmioWindow + ?Sized> core::fmt::Debug for LtPhy<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LtPhy")
            .field("port", &self.port)
            .field("lanes", &self.lanes)
            .field("dp_alt", &self.dp_alt)
            .field("max_lanes", &self.max_lanes)
            .finish()
    }
}

impl<'a, M: MmioWindow + ?Sized> LtPhy<'a, M> {
    pub(crate) fn new(
        mmio: &'a M,
        port: LtPort,
        dp_alt: bool,
        max_lanes: u8,
        reversed: bool,
    ) -> Result<Self, Cx0Error> {
        // Linux gates LT PHY on `platform.novalake`, not display version.
        // A Panther/Wildcat Lake C20 window must never receive these
        // same-looking Cx0 transactions.
        if !mmio.has_lt_phy() {
            return Err(Cx0Error::ProtocolMismatch);
        }
        let lanes = PhyLaneConfig::for_route(dp_alt, max_lanes, reversed)?;
        Ok(Self {
            mmio,
            port,
            lanes,
            dp_alt,
            max_lanes,
        })
    }

    fn cx0(&self) -> Cx0Phy<'_, M> {
        Cx0Phy::with_lanes(self.mmio, self.port.xelpg(), self.lanes)
    }

    fn m2p_ctl(&self, lane: u8) -> u64 {
        self.port.xelpg().msgbus_ctl_ln0() + u64::from(lane) * 4
    }

    fn p2m_status(&self, lane: u8) -> u64 {
        self.m2p_ctl(lane) + 8
    }

    fn wait_for(&self, off: u64, mask: u32, want: u32, timeout_us: u64) -> bool {
        let mut lost = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let value = self.mmio.read32(off);
                lost = value == u32::MAX || !self.mmio.display_access_ok();
                lost || value & mask == want
            },
            narf_time::Deadline::after_us(timeout_us),
        );
        done && !lost
    }

    fn rmw(&self, off: u64, clear: u32, set: u32) -> Result<(), Cx0Error> {
        let value = self.mmio.read32(off);
        if value == u32::MAX || !self.mmio.display_access_ok() {
            return Err(Cx0Error::PhyError);
        }
        self.mmio.write32(off, (value & !clear) | set);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    fn clear_response_ready(&self, lane: u8) {
        let off = self.p2m_status(lane);
        let value = self.mmio.read32(off);
        self.mmio
            .write32(off, value | P2M_RESPONSE_READY | P2M_ERROR_SET);
        compiler_fence(Ordering::SeqCst);
    }

    fn clear_p2p_ready(&self, lane: u8) -> Result<(), Cx0Error> {
        let off = self
            .port
            .p2m_status_p2p(lane)
            .ok_or(Cx0Error::ProtocolMismatch)?;
        let value = self.mmio.read32(off);
        if value == u32::MAX || !self.mmio.display_access_ok() {
            return Err(Cx0Error::PhyError);
        }
        self.mmio.write32(off, value & !P2M_RESPONSE_READY);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    fn bus_reset(&self, lane: u8) {
        let ctl = self.m2p_ctl(lane);
        self.mmio.write32(ctl, M2P_TRANSACTION_RESET);
        compiler_fence(Ordering::SeqCst);
        let _ = self.wait_for(ctl, M2P_TRANSACTION_RESET, 0, MSGBUS_TIMEOUT_US);
        self.clear_response_ready(lane);
    }

    fn wait_for_write_ack(&self, lane: u8) -> Result<u32, Cx0Error> {
        let off = self.p2m_status(lane);
        if !self.wait_for(
            off,
            P2M_RESPONSE_READY,
            P2M_RESPONSE_READY,
            MSGBUS_TIMEOUT_US,
        ) {
            self.bus_reset(lane);
            return Err(Cx0Error::Timeout);
        }
        let value = self.mmio.read32(off);
        if value & P2M_ERROR_SET != 0 {
            self.bus_reset(lane);
            return Err(Cx0Error::PhyError);
        }
        if value & P2M_COMMAND_MASK != P2M_COMMAND_WRITE_ACK {
            self.bus_reset(lane);
            return Err(Cx0Error::ProtocolMismatch);
        }
        Ok(value)
    }

    fn p2p_write_once(&self, lane: u8, address: u16, data: u8) -> Result<(), Cx0Error> {
        let ctl = self.m2p_ctl(lane);
        if !self.wait_for(ctl, M2P_TRANSACTION_PENDING, 0, MSGBUS_TIMEOUT_US) {
            self.bus_reset(lane);
            return Err(Cx0Error::Timeout);
        }

        // `intel_de_rmw(status, 0, 0)`: read/write the current W1C status so
        // stale response/error flags cannot satisfy this transaction.
        let status = self.p2m_status(lane);
        let old = self.mmio.read32(status);
        if old == u32::MAX || !self.mmio.display_access_ok() {
            return Err(Cx0Error::PhyError);
        }
        self.mmio.write32(status, old);
        compiler_fence(Ordering::SeqCst);

        self.mmio.write32(
            ctl,
            M2P_TRANSACTION_PENDING
                | M2P_COMMAND_WRITE_COMMITTED
                | (u32::from(data) << M2P_DATA_SHIFT)
                | (u32::from(address) & 0x0fff),
        );
        compiler_fence(Ordering::SeqCst);
        self.wait_for_write_ack(lane)?;

        let deadline = narf_time::Deadline::after_us(P2P_SETTLE_US);
        let _ = narf_scheduler::responsive_spin_until(|| deadline.expired(), deadline);
        self.clear_response_ready(lane);
        self.clear_p2p_ready(lane)
    }

    fn p2p_write(&self, lane_mask: u8, address: u16, data: u8) -> Result<(), Cx0Error> {
        if lane_mask == 0 || lane_mask & !BOTH_LANES != 0 {
            return Err(Cx0Error::ProtocolMismatch);
        }
        for lane in 0..2u8 {
            if lane_mask & (1 << lane) == 0 {
                continue;
            }
            let mut result = Err(Cx0Error::Timeout);
            for _ in 0..MSGBUS_ATTEMPTS {
                result = self.p2p_write_once(lane, address, data);
                if result.is_ok() {
                    break;
                }
            }
            result?;
        }
        Ok(())
    }

    fn powerdown_change(&self, state: u32) -> Result<(), Cx0Error> {
        let owned = self.lanes.owned_mask();
        let port = self.port.xelpg();
        let buf_ctl2 = port.buf_ctl2();
        let mut new_state = 0;
        let mut update = 0;
        for lane in 0..2u8 {
            if owned & (1 << lane) != 0 {
                new_state |= lane_powerdown_new_state(u32::from(lane), state);
                update |= lane_powerdown_update(u32::from(lane));
            }
        }
        self.rmw(buf_ctl2, 0xff << 16, new_state)?;
        for lane in 0..2u8 {
            if owned & (1 << lane) != 0
                && !self.wait_for(
                    self.m2p_ctl(lane),
                    M2P_TRANSACTION_PENDING,
                    0,
                    MSGBUS_TIMEOUT_US,
                )
            {
                self.bus_reset(lane);
                return Err(Cx0Error::Timeout);
            }
        }
        self.rmw(buf_ctl2, (1 << 25) | (1 << 24), update)?;
        if !self.wait_for(buf_ctl2, update, 0, POWERDOWN_UPDATE_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        Ok(())
    }

    fn setup_powerdown(&self) -> Result<(), Cx0Error> {
        let port = self.port.xelpg();
        self.rmw(port.buf_ctl2(), POWER_STATE_READY_MASK, P2_STATE_READY << 4)?;
        self.rmw(
            port.buf_ctl3(),
            POWER_STATE_ACTIVE_MASK | PLL_LANE_STAGGERING_DELAY_MASK,
            P0_STATE_ACTIVE,
        )
    }

    fn lane_reset(&self) -> Result<(), Cx0Error> {
        let port = self.port.xelpg();
        let owned = self.lanes.owned_mask();
        let mut resets = 0;
        let mut current = 0;
        let mut pulse = 0;
        for lane in 0..2u8 {
            if owned & (1 << lane) != 0 {
                resets |= lane_pipe_reset(u32::from(lane));
                current |= lane_phy_current_status(u32::from(lane));
                pulse |= phy_pulse_status(lane);
            }
        }

        self.rmw(self.port.buf_ctl5(), MACCLK_RATE_MASK, MACCLK_RATE_DEFAULT)?;
        self.rmw(port.buf_ctl1(), PHY_MODE_MASK, PHY_MODE_DP)?;
        self.setup_powerdown()?;
        self.powerdown_change(P2_STATE_RESET)?;
        self.rmw(self.port.buf_ctl5(), MACCLK_RESET_0, 0)?;

        let clock_ctl = port.port_clock_ctl();
        let request = lane_pclk_pll_request(0);
        let ack = lane_pclk_pll_ack(0);
        self.rmw(clock_ctl, request, request)?;
        if !self.wait_for(clock_ctl, ack, ack, MACCLK_TURNON_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(clock_ctl, FORWARD_CLOCK_UNGATE, FORWARD_CLOCK_UNGATE)?;
        self.rmw(port.buf_ctl2(), resets | pulse, 0)?;
        if !self.wait_for(port.buf_ctl2(), current, 0, RESET_END_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        if !self.wait_for(port.buf_ctl2(), pulse, pulse, RATE_CALIBRATION_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(port.buf_ctl2(), pulse, 0)
    }

    fn program_port_clock(&self, rate: LtDpRate, ssc_enabled: bool) -> Result<(), Cx0Error> {
        let port = self.port.xelpg();
        self.rmw(
            port.buf_ctl1(),
            PORT_BUF_REVERSAL,
            if self.lanes.reversed() {
                PORT_BUF_REVERSAL
            } else {
                0
            },
        )?;
        let mut value = FORWARD_CLOCK_UNGATE | DDI_CLOCK_SELECT_MAXPCLK;
        if matches!(rate, LtDpRate::Uhbr10 | LtDpRate::Uhbr20) {
            value |= SSC_ENABLE_PLLA;
        } else if ssc_enabled {
            value |= SSC_ENABLE_PLLB;
        }
        self.rmw(
            port.port_clock_ctl(),
            LANE1_PHY_CLOCK_SELECT
                | FORWARD_CLOCK_UNGATE
                | XE3_DDI_CLOCK_SELECT_MASK
                | SSC_ENABLE_PLLA
                | SSC_ENABLE_PLLB,
            value,
        )
    }

    /// Program the source DP PLL image through the normal Cx0 VDR transport.
    pub(crate) fn program_dp_pll(&self, rate: LtDpRate) -> Result<(), Cx0Error> {
        let state = dp_pll_state(rate);
        let cx0 = self.cx0();
        for index in 0..LT_PLL_PROGRAM_WRITE_COUNT {
            let write = pll_program_write(state, self.lanes.owned_mask(), index)
                .ok_or(Cx0Error::ProtocolMismatch)?;
            cx0.write(write.lane_mask, write.address, write.data, true)?;
        }
        Ok(())
    }

    /// Run Linux's Nova Lake LT-PHY DP PLL enable order. The caller must already
    /// own DC-off, the Type-C PHY and the D2D/AUX power wells; no production
    /// route currently establishes those preconditions.
    pub(crate) fn enable_dp(&self, request: LtDpEnable) -> Result<(), Cx0Error> {
        if !matches!(request.lane_count, 1 | 2 | 4) || request.lane_count > self.max_lanes {
            return Err(Cx0Error::ProtocolMismatch);
        }
        let port = self.port.xelpg();
        let owned = self.lanes.owned_mask();
        let mut pulse = 0;
        for lane in 0..2u8 {
            if owned & (1 << lane) != 0 {
                pulse |= phy_pulse_status(lane);
            }
        }

        self.lane_reset()?;
        self.program_port_clock(request.rate, request.ssc_enabled)?;
        self.powerdown_change(P2_STATE_READY)?;
        self.program_dp_pll(request.rate)?;
        self.p2p_write(owned, LT_PHY_RATE_UPDATE, LT_PHY_RATE_CONTROL_VDR_UPDATE)?;

        let clock_ctl = port.port_clock_ctl();
        let pll_request = lane_pclk_pll_request(0);
        let pll_ack = lane_pclk_pll_ack(0);
        self.rmw(clock_ctl, pll_request, 0)?;
        if !self.wait_for(clock_ctl, pll_ack, 0, MACCLK_TURNOFF_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.mmio.write32(
            port.clk_valfreq().ok_or(Cx0Error::ProtocolMismatch)?,
            request.rate.clock_khz(),
        );
        compiler_fence(Ordering::SeqCst);
        self.rmw(clock_ctl, pll_request, pll_request)?;
        if !self.wait_for(clock_ctl, pll_ack, pll_ack, MACCLK_TURNON_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(clock_ctl, FORWARD_CLOCK_UNGATE, FORWARD_CLOCK_UNGATE)?;
        self.rmw(port.buf_ctl2(), pulse, pulse)?;

        let cx0 = self.cx0();
        let update = cx0.read(LANE0, LT_PHY_RATE_UPDATE)?;
        cx0.write(
            owned,
            LT_PHY_RATE_UPDATE,
            update & !LT_PHY_RATE_CONTROL_VDR_UPDATE,
            true,
        )?;
        if !self.wait_for(port.buf_ctl2(), pulse, pulse, RATE_CALIBRATION_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(port.buf_ctl2(), pulse, pulse)?;
        self.powerdown_change(P0_STATE_ACTIVE)?;
        self.program_transmitters(request.lane_count, request.pin_assignment_d)
    }

    /// Assert lane reset and gate MacCLK in Linux's LT-PHY disable order.
    pub(crate) fn disable(&self) -> Result<(), Cx0Error> {
        let port = self.port.xelpg();
        let owned = self.lanes.owned_mask();
        let mut resets = 0;
        let mut current = 0;
        let mut pulse = 0;
        for lane in 0..2u8 {
            if owned & (1 << lane) != 0 {
                resets |= lane_pipe_reset(u32::from(lane));
                current |= lane_phy_current_status(u32::from(lane));
                pulse |= phy_pulse_status(lane);
            }
        }
        self.rmw(port.buf_ctl2(), pulse, pulse)?;
        self.rmw(port.buf_ctl2(), resets, resets)?;
        if !self.wait_for(port.buf_ctl2(), current, current, RESET_START_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(port.buf_ctl2(), pulse, pulse)?;

        let clock_ctl = port.port_clock_ctl();
        let request = lane_pclk_pll_request(0);
        let ack = lane_pclk_pll_ack(0);
        self.rmw(clock_ctl, request, 0)?;
        self.mmio
            .write32(port.clk_valfreq().ok_or(Cx0Error::ProtocolMismatch)?, 0);
        compiler_fence(Ordering::SeqCst);
        if !self.wait_for(clock_ctl, ack, 0, MACCLK_TURNOFF_TIMEOUT_US) {
            return Err(Cx0Error::Timeout);
        }
        self.rmw(
            clock_ctl,
            XE3_DDI_CLOCK_SELECT_MASK | FORWARD_CLOCK_UNGATE,
            0,
        )?;
        self.rmw(self.port.buf_ctl5(), MACCLK_RESET_0, MACCLK_RESET_0)
    }

    /// Enable/disable all four transmitters through the LT-specific P2P flow.
    pub(crate) fn program_transmitters(
        &self,
        lane_count: u8,
        pin_assignment_d: bool,
    ) -> Result<(), Cx0Error> {
        let mask = transmitter_mask(
            lane_count,
            self.lanes.reversed(),
            self.dp_alt,
            pin_assignment_d,
        )
        .ok_or(Cx0Error::ProtocolMismatch)?;
        let writes = tx_enable_writes(mask).ok_or(Cx0Error::ProtocolMismatch)?;
        for write in writes {
            if write.address != write.mac_offset || write.data != write.expected_mac {
                return Err(Cx0Error::ProtocolMismatch);
            }
            self.p2p_write(write.lane_mask, write.address, write.data)?;
        }
        Ok(())
    }

    /// Program per-link-lane swing/cursor values through committed VDR RMWs.
    pub(crate) fn program_signal_levels(
        &self,
        protocol: LtSignalProtocol,
        level_indices: &[u8],
    ) -> Result<(), Cx0Error> {
        if level_indices.is_empty() || level_indices.len() > 4 {
            return Err(Cx0Error::ProtocolMismatch);
        }
        let cx0 = self.cx0();
        for (link_lane, &index) in level_indices.iter().enumerate() {
            let phy_lane = (link_lane / 2) as u8;
            let tx = (link_lane % 2) as u8;
            let lane_mask = 1 << phy_lane;
            if lane_mask & self.lanes.owned_mask() == 0 {
                continue;
            }
            let level =
                signal_level(protocol, usize::from(index)).ok_or(Cx0Error::UnsupportedRate)?;
            let ctl8 = txy_ctl(tx, 8).ok_or(Cx0Error::ProtocolMismatch)?;
            let ctl2 = txy_ctl(tx, 2).ok_or(Cx0Error::ProtocolMismatch)?;
            let ctl3 = txy_ctl(tx, 3).ok_or(Cx0Error::ProtocolMismatch)?;
            let ctl4 = txy_ctl(tx, 4).ok_or(Cx0Error::ProtocolMismatch)?;
            cx0.rmw(
                lane_mask,
                ctl8,
                0xf8,
                (level.tx_swing_level << 4) | (level.tx_swing << 3),
                true,
            )?;
            cx0.rmw(lane_mask, ctl2, 0x3f, level.pre_cursor, true)?;
            cx0.rmw(lane_mask, ctl3, 0x3f, level.main_cursor, true)?;
            cx0.rmw(lane_mask, ctl4, 0x3f, level.post_cursor, true)?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Transaction {
        lane: u8,
        address: u16,
        data: u8,
    }

    #[derive(Debug)]
    struct FakeLtMmio {
        regs: RefCell<BTreeMap<u64, u32>>,
        vdr: RefCell<BTreeMap<(u8, u16), u8>>,
        transactions: RefCell<Vec<Transaction>>,
        resets: Cell<u32>,
        bad_ack: Cell<bool>,
        lt_phy: bool,
    }

    impl Default for FakeLtMmio {
        fn default() -> Self {
            let mut regs = BTreeMap::new();
            // The disabled LT PHY enters with both lanes held in pipe reset
            // and the corresponding current-status bits asserted.
            regs.insert(0x64_008, 0xf000_0000);
            regs.insert(0x64_108, 0xf000_0000);
            regs.insert(0x16_f204, 0xf000_0000);
            regs.insert(0x16_f404, 0xf000_0000);
            Self {
                regs: RefCell::new(regs),
                vdr: RefCell::new(BTreeMap::new()),
                transactions: RefCell::new(Vec::new()),
                resets: Cell::new(0),
                bad_ack: Cell::new(false),
                lt_phy: true,
            }
        }
    }

    fn lit_nvl() -> FakeLtMmio {
        let io = FakeLtMmio::default();
        io.regs.borrow_mut().extend([
            (crate::intel_gpu_xe2lpd::GMD_ID_DISPLAY, 35 << 22),
            (SKL_DFSM, 0),
            (PICA_PHY_CONFIG_CONTROL, 0),
            (TRANSCONF_A, 3 << 30),
        ]);
        io
    }

    fn smoke_nvl_display_route_is_exact_and_read_only() -> TestResult {
        use narf_boot::args::KernelCmdline;

        let io = lit_nvl();
        let before = io.regs.borrow().clone();
        assert_eq!(
            display_route(GtPlatform::NovaLakeS, true, &io),
            Ok(DisplayIdentity::NovaLakeS)
        );
        assert_eq!(*io.regs.borrow(), before);
        assert_eq!(
            display_route(
                GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
                true,
                &io,
            ),
            Err(RouteRefusal::UnsupportedPlatform)
        );
        assert_eq!(
            display_route(GtPlatform::NovaLakeS, false, &FakeLtMmio::default()),
            Err(RouteRefusal::NotRequested)
        );

        for (reg, value, refusal) in [
            (
                crate::intel_gpu_xe2lpd::GMD_ID_DISPLAY,
                (30 << 22) | (2 << 14),
                RouteRefusal::Ip(IpError::Unqualified { ver: 30, rel: 2 }),
            ),
            (SKL_DFSM, DFSM_PIPE_A_DISABLE, RouteRefusal::PipeAFused),
            (
                PICA_PHY_CONFIG_CONTROL,
                EDP_ON_TYPEC,
                RouteRefusal::EdpOnTypeC,
            ),
            (TRANSCONF_A, 0, RouteRefusal::PipeADark),
            (TRANSCONF_A, u32::MAX, RouteRefusal::Ip(IpError::NoDevice)),
        ] {
            let io = lit_nvl();
            io.regs.borrow_mut().insert(reg, value);
            assert_eq!(
                display_route(GtPlatform::NovaLakeS, true, &io),
                Err(refusal),
                "{reg:#x}={value:#x}"
            );
        }

        assert!(requested(KernelCmdline::new(
            "quiet narf.intel.nvl_display=1"
        )));
        for line in [
            "",
            "narf.intel.nvl_display",
            "narf.intel.nvl_display=0",
            "narf.intel.nvl_display=01",
            "narf.intel.ptl_display=1",
            "narf.intel.wcl_display=1",
        ] {
            assert!(!requested(KernelCmdline::new(line)), "{line}");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_display_route_is_exact_and_read_only
    );

    fn smoke_nvl_display35_cdclk_table_and_hooks() -> TestResult {
        use crate::intel_gpu_xelpg_cdclk as cdclk;

        let table = &cdclk::NOVA_LAKE_TABLE;
        assert_eq!(table.len(), 31);
        for rung in table {
            assert_eq!(
                rung.ratio * 38_400 * rung.waveform.count_ones() / 32,
                rung.cdclk_khz,
                "{rung:?}"
            );
        }
        assert_eq!(
            table[..11]
                .iter()
                .map(|rung| (rung.cdclk_khz, rung.ratio, rung.waveform))
                .collect::<Vec<_>>(),
            [
                (151_200, 21, 0xa4a4),
                (176_400, 21, 0xaa54),
                (201_600, 21, 0xaaaa),
                (226_800, 21, 0xad5a),
                (252_000, 21, 0xb6b6),
                (277_200, 21, 0xdbb6),
                (302_400, 21, 0xeeee),
                (327_600, 21, 0xf7de),
                (352_800, 21, 0xfefe),
                (378_000, 21, 0xfffe),
                (403_200, 21, 0xffff),
            ]
        );
        assert!(table[11..].windows(2).all(|rungs| {
            rungs[1].cdclk_khz - rungs[0].cdclk_khz == 19_200
                && rungs[1].ratio == rungs[0].ratio + 1
                && rungs[0].waveform == 0xffff
        }));
        assert_eq!(
            table
                .last()
                .map(|rung| (rung.cdclk_khz, rung.ratio, rung.waveform)),
            Some((787_200, 41, 0xffff))
        );
        assert_eq!(cdclk::NOVA_LAKE_MAX_CDCLK_KHZ, 787_200);
        assert_eq!(
            cdclk::calc_nova_lake_cdclk(403_201).map(|rung| rung.cdclk_khz),
            Some(422_400)
        );
        assert_eq!(cdclk::calc_nova_lake_cdclk(787_201), None);
        assert_eq!(cdclk::nova_lake_ctl_value(), 1 << 25);
        assert_eq!(cdclk::nova_lake_voltage_level(787_200), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_display35_cdclk_table_and_hooks
    );

    impl FakeLtMmio {
        fn ctl_lane(off: u64) -> Option<(LtPort, u8)> {
            for (port, base) in [
                (LtPort::A, 0x64_040),
                (LtPort::B, 0x64_140),
                (LtPort::Tc1, 0x16_f240),
                (LtPort::Tc2, 0x16_f440),
            ] {
                if off == base {
                    return Some((port, 0));
                }
                if off == base + 4 {
                    return Some((port, 1));
                }
            }
            None
        }

        fn ordinary_status(off: u64) -> bool {
            matches!(
                off,
                0x64_048
                    | 0x64_04c
                    | 0x64_148
                    | 0x64_14c
                    | 0x16_f248
                    | 0x16_f24c
                    | 0x16_f448
                    | 0x16_f44c
            )
        }

        fn p2p_status(off: u64) -> bool {
            matches!(
                off,
                0x64_0a0
                    | 0x64_0a4
                    | 0x64_1a0
                    | 0x64_1a4
                    | 0x16_f2a0
                    | 0x16_f2a4
                    | 0x16_f4a0
                    | 0x16_f4a4
            )
        }
    }

    impl MmioWindow for FakeLtMmio {
        fn display_access_ok(&self) -> bool {
            true
        }

        fn cx0_xe3(&self) -> bool {
            true
        }

        fn has_lt_phy(&self) -> bool {
            self.lt_phy
        }

        fn read32(&self, off: u64) -> u32 {
            *self.regs.borrow().get(&off).unwrap_or(&0)
        }

        fn write32(&self, off: u64, value: u32) {
            if matches!(off, 0x64_0e0 | 0x64_1e0 | 0x16_f260 | 0x16_f460) {
                let mut next = value;
                if value & lane_pclk_pll_request(0) != 0 {
                    next |= lane_pclk_pll_ack(0);
                } else {
                    next &= !lane_pclk_pll_ack(0);
                }
                self.regs.borrow_mut().insert(off, next);
                return;
            }
            if matches!(off, 0x64_008 | 0x64_108 | 0x16_f204 | 0x16_f404) {
                let old = self.read32(off);
                let reset_mask = lane_pipe_reset(0) | lane_pipe_reset(1);
                let status_mask = lane_phy_current_status(0) | lane_phy_current_status(1);
                let pulse_mask = phy_pulse_status(0) | phy_pulse_status(1);
                let update_mask = lane_powerdown_update(0) | lane_powerdown_update(1);
                let resets = value & reset_mask;
                let released = old & reset_mask & !resets;
                let mut next = value & !(status_mask | pulse_mask | update_mask);
                next |= resets >> 2;
                next |= released >> 4;
                self.regs.borrow_mut().insert(off, next);
                return;
            }
            if Self::ordinary_status(off) {
                let old = self.read32(off);
                self.regs.borrow_mut().insert(off, old & !value);
                return;
            }
            if Self::p2p_status(off) {
                self.regs.borrow_mut().insert(off, value);
                return;
            }
            let Some((port, lane)) = Self::ctl_lane(off) else {
                self.regs.borrow_mut().insert(off, value);
                return;
            };
            if value & M2P_TRANSACTION_RESET != 0 {
                self.resets.set(self.resets.get() + 1);
                self.regs.borrow_mut().insert(off, 0);
                return;
            }
            if value & M2P_TRANSACTION_PENDING == 0 {
                self.regs.borrow_mut().insert(off, value);
                return;
            }

            let address = (value & 0x0fff) as u16;
            let command = value & P2M_COMMAND_MASK;
            if command == 0x3 << 27 {
                let data = *self.vdr.borrow().get(&(lane, address)).unwrap_or(&0);
                self.regs.borrow_mut().insert(off, 0);
                self.regs.borrow_mut().insert(
                    off + 8,
                    P2M_RESPONSE_READY | (0x4 << 27) | (u32::from(data) << M2P_DATA_SHIFT),
                );
                return;
            }
            let data = ((value >> M2P_DATA_SHIFT) & 0xff) as u8;
            self.vdr.borrow_mut().insert((lane, address), data);
            if address == LT_PHY_RATE_UPDATE && data & LT_PHY_RATE_CONTROL_VDR_UPDATE == 0 {
                let buf_ctl2 = match port {
                    LtPort::A => 0x64_008,
                    LtPort::B => 0x64_108,
                    LtPort::Tc1 => 0x16_f204,
                    LtPort::Tc2 => 0x16_f404,
                };
                let current = self.read32(buf_ctl2);
                self.regs
                    .borrow_mut()
                    .insert(buf_ctl2, current | phy_pulse_status(lane));
            }
            self.transactions.borrow_mut().push(Transaction {
                lane,
                address,
                data,
            });
            self.regs.borrow_mut().insert(off, 0);
            let ack = if self.bad_ack.get() {
                0x4 << 27
            } else {
                P2M_COMMAND_WRITE_ACK
            };
            self.regs
                .borrow_mut()
                .insert(off + 8, P2M_RESPONSE_READY | ack);
            let p2p = port.p2m_status_p2p(lane).unwrap();
            self.regs
                .borrow_mut()
                .insert(p2p, P2M_RESPONSE_READY | u32::from(address));
        }
    }

    fn smoke_nvl_lt_phy_ports_and_ownership() -> TestResult {
        assert_eq!(LtPort::from_xelpg(XeLpgPort::A), Some(LtPort::A));
        assert_eq!(LtPort::from_xelpg(XeLpgPort::B), Some(LtPort::B));
        assert_eq!(LtPort::from_xelpg(XeLpgPort::Tc1), Some(LtPort::Tc1));
        assert_eq!(LtPort::from_xelpg(XeLpgPort::Tc2), Some(LtPort::Tc2));
        assert_eq!(LtPort::from_xelpg(XeLpgPort::Tc3), None);
        assert_eq!(LtPort::A.buf_ctl5(), 0x64_038);
        assert_eq!(LtPort::B.p2m_status_p2p(1), Some(0x64_1a4));
        assert_eq!(LtPort::Tc1.buf_ctl5(), 0x16_f234);
        assert_eq!(LtPort::Tc2.p2m_status_p2p(1), Some(0x16_f4a4));
        assert_eq!(LtPort::Tc2.p2m_status_p2p(2), None);
        assert_eq!(owned_lane_mask(false, 2), Some(BOTH_LANES));
        assert_eq!(owned_lane_mask(true, 2), Some(LANE0));
        assert_eq!(owned_lane_mask(true, 4), Some(BOTH_LANES));
        assert_eq!(owned_lane_mask(true, 3), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_ports_and_ownership
    );

    fn smoke_nvl_lt_phy_dp_pll_images() -> TestResult {
        let expected = [
            (LtDpRate::Rbr, 162_000, 0x83, 0x8710),
            (LtDpRate::Hbr, 270_000, 0x8b, 0x8710),
            (LtDpRate::Hbr2, 540_000, 0x93, 0x8710),
            (LtDpRate::Hbr3, 810_000, 0x9b, 0x8710),
            (LtDpRate::Uhbr10, 1_000_000, 0x43, 0x8510),
            (LtDpRate::Uhbr13_5, 1_350_000, 0xcb, 0x8710),
            (LtDpRate::Uhbr20, 2_000_000, 0x53, 0x8510),
        ];
        for (rate, clock, config0, first_address) in expected {
            let state = *dp_pll_state(rate);
            assert_eq!(rate.clock_khz(), clock);
            assert_eq!(state.clock_khz, clock);
            assert_eq!(state.config, [config0, 0x2d, 0]);
            assert_eq!(state.register(0).unwrap().address, first_address);
            assert_eq!(state.register(12).unwrap().data, [0; 4]);
            assert_eq!(LtDpRate::from_clock_khz(clock), Some(rate));
        }
        assert_eq!(LtDpRate::from_clock_khz(675_000), None);
        assert_eq!(
            (
                LT_PHY_RATE_UPDATE,
                LT_PHY_RATE_CONTROL_VDR_UPDATE,
                LT_PHY_MAC_VDR,
                LT_PHY_PCLKIN_GATE,
            ),
            (0x0cc4, 1, 0x0c00, 1)
        );
        assert!(!LtDpRate::Hbr3.is_uhbr());
        assert!(LtDpRate::Uhbr10.is_uhbr());
        assert_eq!(DP_RBR.register(1).unwrap().data, [0x05, 0x0a, 0x2a, 0x20]);
        assert_eq!(DP_HBR2.register(3).unwrap().data, [0x0a, 0x04, 0x81, 0xda]);
        assert_eq!(DP_HBR3.register(3).unwrap().data, [0x05, 0x04, 0x80, 0xa8]);
        assert_eq!(
            DP_UHBR10.register(2).unwrap().data,
            [0x6a, 0xaa, 0xaa, 0xab]
        );
        assert_eq!(
            DP_UHBR13_5.register(11).unwrap().data,
            [0x00, 0x57, 0xe0, 0x0c]
        );
        assert_eq!(DP_UHBR20.data, DP_UHBR10.data);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_dp_pll_images
    );

    fn smoke_nvl_lt_phy_edp_pll_images() -> TestResult {
        let expected = [
            (LtEdpRate::Rbr, 162_000, 0x83, 0x00),
            (LtEdpRate::Edp216, 216_000, 0xa3, 0x01),
            (LtEdpRate::Edp243, 243_000, 0xab, 0x01),
            (LtEdpRate::Hbr, 270_000, 0x8b, 0x00),
            (LtEdpRate::Edp324, 324_000, 0xb3, 0x01),
            (LtEdpRate::Edp432, 432_000, 0xbb, 0x01),
            (LtEdpRate::Hbr2, 540_000, 0x93, 0x00),
            (LtEdpRate::Edp675, 675_000, 0xdb, 0x01),
            (LtEdpRate::Hbr3, 810_000, 0x9b, 0x00),
        ];
        for (rate, clock, config0, config2) in expected {
            let state = edp_pll_state(rate);
            assert_eq!(rate.clock_khz(), clock);
            assert_eq!(state.clock_khz, clock);
            assert_eq!(state.config, [config0, 0x2d, config2]);
            assert_eq!(state.register(0).unwrap().address, 0x8710);
            assert_eq!(LtEdpRate::from_clock_khz(clock), Some(rate));
            assert!(pll_program_write(state, BOTH_LANES, LT_PLL_PROGRAM_WRITE_COUNT).is_none());
        }
        assert_eq!(LtEdpRate::from_clock_khz(1_000_000), None);
        // The four ordinary DP rates are shared by pointer, not copied into
        // subtly divergent eDP images.
        assert!(core::ptr::eq(edp_pll_state(LtEdpRate::Rbr), &DP_RBR));
        assert!(core::ptr::eq(edp_pll_state(LtEdpRate::Hbr), &DP_HBR));
        assert!(core::ptr::eq(edp_pll_state(LtEdpRate::Hbr2), &DP_HBR2));
        assert!(core::ptr::eq(edp_pll_state(LtEdpRate::Hbr3), &DP_HBR3));
        assert_eq!(EDP_216.register(1).unwrap().data, [0x03, 0xca, 0x2a, 0x20]);
        assert_eq!(EDP_243.register(8).unwrap().data, [0x47, 0x48, 0, 0]);
        assert_eq!(EDP_324.register(3).unwrap().data, [0x06, 0x04, 0x81, 0x28]);
        assert_eq!(EDP_432.register(1).unwrap().data, [0x01, 0x4d, 0x2a, 0x20]);
        assert_eq!(EDP_675.register(11).unwrap().data, [0x00, 0x57, 0xe0, 0x0c]);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_edp_pll_images
    );

    fn smoke_nvl_lt_phy_write_image_and_transmitters() -> TestResult {
        let first = pll_program_write(&DP_HBR3, BOTH_LANES, 0).unwrap();
        assert_eq!(
            first,
            LtVdrWrite {
                lane_mask: BOTH_LANES,
                address: 0x0c02,
                data: 0x9b,
            }
        );
        assert_eq!(
            pll_program_write(&DP_HBR3, BOTH_LANES, 3).unwrap(),
            LtVdrWrite {
                lane_mask: LANE0,
                address: 0x0c04,
                data: 0x87,
            }
        );
        assert_eq!(
            pll_program_write(&DP_HBR3, BOTH_LANES, 5).unwrap(),
            LtVdrWrite {
                lane_mask: LANE0,
                address: 0x0c06,
                data: 0,
            }
        );
        let last = pll_program_write(&DP_HBR3, LANE0, LT_PLL_PROGRAM_WRITE_COUNT - 1).unwrap();
        assert_eq!((last.address, last.data), (0x0c51, 0));
        assert!(pll_program_write(&DP_HBR3, 0, 0).is_none());
        assert!(pll_program_write(&DP_HBR3, BOTH_LANES, LT_PLL_PROGRAM_WRITE_COUNT).is_none());

        assert_eq!(transmitter_mask(1, false, true, true), Some(0b0001));
        assert_eq!(transmitter_mask(1, false, true, false), Some(0b0010));
        assert_eq!(transmitter_mask(2, true, false, false), Some(0b1100));
        assert_eq!(transmitter_mask(2, true, true, false), Some(0b0011));
        assert_eq!(transmitter_mask(4, true, true, false), Some(0b1111));
        assert_eq!(transmitter_mask(0, false, false, false), None);
        let writes = tx_enable_writes(0b0101).unwrap();
        assert_eq!(
            (writes[0].lane_mask, writes[0].address, writes[0].data),
            (LANE0, 0x040a, 1)
        );
        assert_eq!(
            (writes[1].lane_mask, writes[1].address, writes[1].data),
            (LANE0, 0x060a, 0)
        );
        assert_eq!(
            (writes[2].lane_mask, writes[2].address, writes[2].data),
            (LANE1, 0x040a, 1)
        );
        assert_eq!(
            (writes[3].lane_mask, writes[3].address, writes[3].data),
            (LANE1, 0x060a, 0)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_write_image_and_transmitters
    );

    fn smoke_nvl_lt_phy_signal_tables() -> TestResult {
        assert_eq!(DP14_LEVELS[0], level(1, 0, 0, 21, 0));
        assert_eq!(DP14_LEVELS[9], level(0, 3, 0, 48, 0));
        assert_eq!(UHBR_LEVELS[0], level(0, 0, 0, 48, 0));
        assert_eq!(UHBR_LEVELS[15], level(1, 0, 2, 26, 2));
        assert_eq!(
            signal_level(LtSignalProtocol::Dp14, 9),
            Some(DP14_LEVELS[9])
        );
        assert_eq!(signal_level(LtSignalProtocol::Dp14, 10), None);
        assert_eq!(
            signal_level(LtSignalProtocol::Uhbr, 15),
            Some(UHBR_LEVELS[15])
        );
        assert_eq!(signal_level(LtSignalProtocol::Uhbr, 16), None);
        assert_eq!(txy_ctl(0, 8), Some(0x0408));
        assert_eq!(txy_ctl(1, 4), Some(0x0604));
        assert_eq!(txy_ctl(2, 2), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_signal_tables
    );

    fn smoke_nvl_lt_phy_transport_programs_pll_and_p2p_tx() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, LtPort::Tc1, true, 4, false).unwrap();
        phy.program_dp_pll(LtDpRate::Hbr3).unwrap();
        let transactions = fake.transactions.borrow();
        // 81 logical writes: config 0 and 2 fan out to both owned lanes.
        assert_eq!(transactions.len(), LT_PLL_PROGRAM_WRITE_COUNT + 2);
        assert_eq!(
            transactions[0],
            Transaction {
                lane: 0,
                address: 0x0c02,
                data: 0x9b,
            }
        );
        assert_eq!(transactions[1].lane, 1);
        assert_eq!(
            (transactions[2].address, transactions[2].data),
            (0x0c03, 0x2d)
        );
        assert_eq!(
            (transactions[5].address, transactions[5].data),
            (0x0c04, 0x87)
        );
        assert_eq!(transactions.last().unwrap().address, 0x0c51);
        drop(transactions);

        fake.transactions.borrow_mut().clear();
        phy.program_transmitters(4, false).unwrap();
        assert_eq!(
            fake.transactions.borrow().as_slice(),
            &[
                Transaction {
                    lane: 0,
                    address: 0x040a,
                    data: 1,
                },
                Transaction {
                    lane: 0,
                    address: 0x060a,
                    data: 1,
                },
                Transaction {
                    lane: 1,
                    address: 0x040a,
                    data: 1,
                },
                Transaction {
                    lane: 1,
                    address: 0x060a,
                    data: 1,
                },
            ]
        );
        assert_eq!(fake.read32(0x16_f248), 0);
        assert_eq!(fake.read32(0x16_f24c), 0);
        assert_eq!(fake.read32(0x16_f2a0) & P2M_RESPONSE_READY, 0);
        assert_eq!(fake.read32(0x16_f2a4) & P2M_RESPONSE_READY, 0);

        let combo = FakeLtMmio::default();
        let combo_phy = LtPhy::new(&combo, LtPort::A, false, 4, false).unwrap();
        combo_phy.program_transmitters(4, false).unwrap();
        assert_eq!(combo.read32(0x64_0a0) & P2M_RESPONSE_READY, 0);
        assert_eq!(combo.read32(0x64_0a4) & P2M_RESPONSE_READY, 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_transport_programs_pll_and_p2p_tx
    );

    fn smoke_nvl_lt_phy_transport_rejects_family_and_bad_ack() -> TestResult {
        let wrong_family = FakeLtMmio {
            lt_phy: false,
            ..FakeLtMmio::default()
        };
        assert!(matches!(
            LtPhy::new(&wrong_family, LtPort::Tc1, true, 4, false),
            Err(Cx0Error::ProtocolMismatch)
        ));

        let fake = FakeLtMmio::default();
        fake.bad_ack.set(true);
        let phy = LtPhy::new(&fake, LtPort::Tc2, true, 2, false).unwrap();
        assert_eq!(
            phy.program_transmitters(2, false),
            Err(Cx0Error::ProtocolMismatch)
        );
        assert_eq!(fake.resets.get(), u32::from(MSGBUS_ATTEMPTS));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_transport_rejects_family_and_bad_ack
    );

    fn smoke_nvl_lt_phy_transport_programs_signal_levels() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, LtPort::Tc1, true, 4, false).unwrap();
        phy.program_signal_levels(LtSignalProtocol::Dp14, &[1, 9, 0, 6])
            .unwrap();
        assert_eq!(fake.vdr.borrow().get(&(0, 0x0408)).copied(), Some(0x18));
        assert_eq!(fake.vdr.borrow().get(&(0, 0x0403)).copied(), Some(24));
        assert_eq!(fake.vdr.borrow().get(&(0, 0x0404)).copied(), Some(3));
        assert_eq!(fake.vdr.borrow().get(&(0, 0x0608)).copied(), Some(0x30));
        assert_eq!(fake.vdr.borrow().get(&(0, 0x0603)).copied(), Some(48));
        assert_eq!(fake.vdr.borrow().get(&(1, 0x0403)).copied(), Some(21));
        assert_eq!(fake.vdr.borrow().get(&(1, 0x0603)).copied(), Some(39));
        assert_eq!(
            phy.program_signal_levels(LtSignalProtocol::Dp14, &[10]),
            Err(Cx0Error::UnsupportedRate)
        );

        let alt2 = FakeLtMmio::default();
        let phy2 = LtPhy::new(&alt2, LtPort::Tc2, true, 2, false).unwrap();
        phy2.program_signal_levels(LtSignalProtocol::Uhbr, &[15, 0])
            .unwrap();
        assert_eq!(alt2.vdr.borrow().get(&(0, 0x0402)).copied(), Some(2));
        assert_eq!(alt2.vdr.borrow().get(&(0, 0x0403)).copied(), Some(26));
        assert_eq!(alt2.vdr.borrow().get(&(0, 0x0404)).copied(), Some(2));
        assert!(alt2.vdr.borrow().keys().all(|(lane, _)| *lane == 0));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_transport_programs_signal_levels
    );

    fn smoke_nvl_lt_phy_enable_disable_sequence() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, LtPort::Tc1, true, 4, false).unwrap();
        phy.enable_dp(LtDpEnable {
            rate: LtDpRate::Hbr3,
            lane_count: 4,
            pin_assignment_d: false,
            ssc_enabled: false,
        })
        .unwrap();

        let clock = fake.read32(0x16_f260);
        assert_eq!(clock & lane_pclk_pll_request(0), lane_pclk_pll_request(0));
        assert_eq!(clock & lane_pclk_pll_ack(0), lane_pclk_pll_ack(0));
        assert_eq!(clock & FORWARD_CLOCK_UNGATE, FORWARD_CLOCK_UNGATE);
        assert_eq!(clock & XE3_DDI_CLOCK_SELECT_MASK, DDI_CLOCK_SELECT_MAXPCLK);
        assert_eq!(clock & (SSC_ENABLE_PLLA | SSC_ENABLE_PLLB), 0);
        assert_eq!(fake.read32(0x6_4330), 810_000);
        assert_eq!(
            fake.read32(0x16_f234) & MACCLK_RATE_MASK,
            MACCLK_RATE_DEFAULT
        );
        assert_eq!(fake.read32(0x16_f234) & MACCLK_RESET_0, 0);
        assert_eq!(fake.read32(0x16_f200) & PHY_MODE_MASK, PHY_MODE_DP);
        assert_eq!(
            fake.vdr.borrow().get(&(0, LT_PHY_RATE_UPDATE)).copied(),
            Some(0)
        );
        assert_eq!(
            fake.vdr.borrow().get(&(1, LT_PHY_RATE_UPDATE)).copied(),
            Some(0)
        );
        assert_eq!(fake.vdr.borrow().get(&(0, 0x040a)).copied(), Some(1));
        assert_eq!(fake.vdr.borrow().get(&(1, 0x060a)).copied(), Some(1));
        let buf2 = fake.read32(0x16_f204);
        assert_eq!(
            buf2 & (lane_pipe_reset(0)
                | lane_pipe_reset(1)
                | lane_phy_current_status(0)
                | lane_phy_current_status(1)
                | phy_pulse_status(0)
                | phy_pulse_status(1)),
            0
        );

        phy.disable().unwrap();
        let clock = fake.read32(0x16_f260);
        assert_eq!(
            clock
                & (lane_pclk_pll_request(0)
                    | lane_pclk_pll_ack(0)
                    | FORWARD_CLOCK_UNGATE
                    | XE3_DDI_CLOCK_SELECT_MASK),
            0
        );
        assert_eq!(fake.read32(0x6_4330), 0);
        assert_eq!(fake.read32(0x16_f234) & MACCLK_RESET_0, MACCLK_RESET_0);
        assert_eq!(
            fake.read32(0x16_f204) & (lane_phy_current_status(0) | lane_phy_current_status(1)),
            lane_phy_current_status(0) | lane_phy_current_status(1)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_enable_disable_sequence
    );

    fn smoke_nvl_lt_phy_clock_selection_and_width_refusal() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, LtPort::Tc2, true, 2, false).unwrap();
        phy.program_port_clock(LtDpRate::Uhbr10, true).unwrap();
        assert_eq!(fake.read32(0x16_f460) & SSC_ENABLE_PLLA, SSC_ENABLE_PLLA);
        assert_eq!(fake.read32(0x16_f460) & SSC_ENABLE_PLLB, 0);
        phy.program_port_clock(LtDpRate::Hbr3, true).unwrap();
        assert_eq!(fake.read32(0x16_f460) & SSC_ENABLE_PLLA, 0);
        assert_eq!(fake.read32(0x16_f460) & SSC_ENABLE_PLLB, SSC_ENABLE_PLLB);
        assert_eq!(
            phy.enable_dp(LtDpEnable {
                rate: LtDpRate::Hbr3,
                lane_count: 4,
                pin_assignment_d: false,
                ssc_enabled: false,
            }),
            Err(Cx0Error::ProtocolMismatch)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_nvl_lt_phy_clock_selection_and_width_refusal
    );
}

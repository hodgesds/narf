//! Wildcat Lake display-30.02 LT-PHY protocol model.
//!
//! WCL's Type-C ports TC1/TC2 are LT PHYs, not the C20 PHYs used by
//! Meteor/Lunar/Panther Lake.  This module deliberately contains only the
//! pure, source-qualified portion of Linux's `intel_lt_phy.c` contract:
//! port/register selection, DP PLL images, VDR write-image construction,
//! transmitter ownership/masking and DP signal-level tables.  It performs no
//! MMIO, does not decode display 30.02 and grants no route authority.
//!
//! Pinned source: the local Linux tree's
//! `drivers/gpu/drm/i915/display/{intel_lt_phy.c,intel_lt_phy_regs.h,
//! intel_ddi_buf_trans.c}`.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_xelpg::{Cx0Error, Cx0Phy, PhyLaneConfig, XeLpgPort};

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

/// The two LT-PHY ports present in Linux's `wcl_display` descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WclLtPort {
    Tc1,
    Tc2,
}

impl WclLtPort {
    pub(crate) const fn from_xelpg(port: XeLpgPort) -> Option<Self> {
        match port {
            XeLpgPort::Tc1 => Some(Self::Tc1),
            XeLpgPort::Tc2 => Some(Self::Tc2),
            XeLpgPort::A | XeLpgPort::B | XeLpgPort::Tc3 | XeLpgPort::Tc4 => None,
        }
    }

    /// `XE3PLPD_PORT_BUF_CTL5(port)`.
    pub(crate) const fn buf_ctl5(self) -> u64 {
        match self {
            Self::Tc1 => 0x16_f234,
            Self::Tc2 => 0x16_f434,
        }
    }

    /// `XE3PLPD_PORT_P2M_MSGBUS_STATUS_P2P(port, lane)`.
    pub(crate) const fn p2m_status_p2p(self, lane: u8) -> Option<u64> {
        let base = match self {
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

// ── Disconnected WCL transport ──────────────────────────────────
//
// These fields are the shared Cx0 message-bus encoding.  The LT P2P flow
// differs after the committed write: it waits for the normal P2M write ACK,
// leaves 150 us for the PHY to settle, then clears both the normal response
// and the WCL-only P2P-ready latch.  Linux currently carries the expected MAC
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

/// WCL LT-PHY message-bus transport.  Construction is family-qualified but
/// this type is not reachable from any display route.
pub(crate) struct LtPhy<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    port: WclLtPort,
    lanes: PhyLaneConfig,
    dp_alt: bool,
}

impl<M: MmioWindow + ?Sized> core::fmt::Debug for LtPhy<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LtPhy")
            .field("port", &self.port)
            .field("lanes", &self.lanes)
            .field("dp_alt", &self.dp_alt)
            .finish()
    }
}

impl<'a, M: MmioWindow + ?Sized> LtPhy<'a, M> {
    pub(crate) fn new(
        mmio: &'a M,
        port: WclLtPort,
        dp_alt: bool,
        max_lanes: u8,
        reversed: bool,
    ) -> Result<Self, Cx0Error> {
        // LT PHY only exists on display 30.02.  A generic MTL/C20 window must
        // never receive these same-looking Cx0 transactions.
        if !mmio.cx0_xe3() {
            return Err(Cx0Error::ProtocolMismatch);
        }
        let lanes = PhyLaneConfig::for_route(dp_alt, max_lanes, reversed)?;
        Ok(Self {
            mmio,
            port,
            lanes,
            dp_alt,
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
        xe3: bool,
    }

    impl Default for FakeLtMmio {
        fn default() -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                vdr: RefCell::new(BTreeMap::new()),
                transactions: RefCell::new(Vec::new()),
                resets: Cell::new(0),
                bad_ack: Cell::new(false),
                xe3: true,
            }
        }
    }

    impl FakeLtMmio {
        fn ctl_lane(off: u64) -> Option<(WclLtPort, u8)> {
            for (port, base) in [(WclLtPort::Tc1, 0x16_f240), (WclLtPort::Tc2, 0x16_f440)] {
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
            matches!(off, 0x16_f248 | 0x16_f24c | 0x16_f448 | 0x16_f44c)
        }

        fn p2p_status(off: u64) -> bool {
            matches!(off, 0x16_f2a0 | 0x16_f2a4 | 0x16_f4a0 | 0x16_f4a4)
        }
    }

    impl MmioWindow for FakeLtMmio {
        fn display_access_ok(&self) -> bool {
            true
        }

        fn cx0_xe3(&self) -> bool {
            self.xe3
        }

        fn read32(&self, off: u64) -> u32 {
            *self.regs.borrow().get(&off).unwrap_or(&0)
        }

        fn write32(&self, off: u64, value: u32) {
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

    fn smoke_wcl_lt_phy_ports_and_ownership() -> TestResult {
        assert_eq!(WclLtPort::from_xelpg(XeLpgPort::Tc1), Some(WclLtPort::Tc1));
        assert_eq!(WclLtPort::from_xelpg(XeLpgPort::Tc2), Some(WclLtPort::Tc2));
        assert_eq!(WclLtPort::from_xelpg(XeLpgPort::Tc3), None);
        assert_eq!(WclLtPort::Tc1.buf_ctl5(), 0x16_f234);
        assert_eq!(WclLtPort::Tc2.p2m_status_p2p(1), Some(0x16_f4a4));
        assert_eq!(WclLtPort::Tc2.p2m_status_p2p(2), None);
        assert_eq!(owned_lane_mask(false, 2), Some(BOTH_LANES));
        assert_eq!(owned_lane_mask(true, 2), Some(LANE0));
        assert_eq!(owned_lane_mask(true, 4), Some(BOTH_LANES));
        assert_eq!(owned_lane_mask(true, 3), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_wcl_lt_phy_ports_and_ownership
    );

    fn smoke_wcl_lt_phy_dp_pll_images() -> TestResult {
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
        smoke_wcl_lt_phy_dp_pll_images
    );

    fn smoke_wcl_lt_phy_write_image_and_transmitters() -> TestResult {
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
        smoke_wcl_lt_phy_write_image_and_transmitters
    );

    fn smoke_wcl_lt_phy_signal_tables() -> TestResult {
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
        smoke_wcl_lt_phy_signal_tables
    );

    fn smoke_wcl_lt_phy_transport_programs_pll_and_p2p_tx() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, WclLtPort::Tc1, true, 4, false).unwrap();
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
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_wcl_lt_phy_transport_programs_pll_and_p2p_tx
    );

    fn smoke_wcl_lt_phy_transport_rejects_family_and_bad_ack() -> TestResult {
        let wrong_family = FakeLtMmio {
            xe3: false,
            ..FakeLtMmio::default()
        };
        assert!(matches!(
            LtPhy::new(&wrong_family, WclLtPort::Tc1, true, 4, false),
            Err(Cx0Error::ProtocolMismatch)
        ));

        let fake = FakeLtMmio::default();
        fake.bad_ack.set(true);
        let phy = LtPhy::new(&fake, WclLtPort::Tc2, true, 2, false).unwrap();
        assert_eq!(
            phy.program_transmitters(2, false),
            Err(Cx0Error::ProtocolMismatch)
        );
        assert_eq!(fake.resets.get(), u32::from(MSGBUS_ATTEMPTS));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_lt_phy",
        smoke_wcl_lt_phy_transport_rejects_family_and_bad_ack
    );

    fn smoke_wcl_lt_phy_transport_programs_signal_levels() -> TestResult {
        let fake = FakeLtMmio::default();
        let phy = LtPhy::new(&fake, WclLtPort::Tc1, true, 4, false).unwrap();
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
        let phy2 = LtPhy::new(&alt2, WclLtPort::Tc2, true, 2, false).unwrap();
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
        smoke_wcl_lt_phy_transport_programs_signal_levels
    );
}

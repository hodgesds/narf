//! Ice Lake Type-C (MG PHY) port: MG PLL, DDI clock routing,
//! signal levels, and DP link-training source.
//!
//! Reference: Linux `display/intel_dpll_mgr.c`
//! (`icl_mg_pll_find_divisors`, `icl_calc_mg_pll_state`,
//! `icl_mg_pll_write`, `mg_pll_enable`, `icl_pll_disable`,
//! `icl_ddi_tc_enable_clock`), `display/intel_ddi.c`
//! (`icl_mg_phy_set_signal_levels`,
//! `intel_ddi_enable_transcoder_clock`,
//! `icl_pll_to_ddi_clk_sel`),
//! `display/intel_ddi_buf_trans.c` (`icl_get_mg_buf_trans`),
//! `display/intel_mg_phy_regs.h`, and
//! `display/intel_display_regs.h`.
//!
//! The MG PHY is the Gen11 Type-C analog of the Gen12 Dekel
//! port (`intel_gpu_gen12_tc::DklPort`) — same public shape
//! (`enable` / `route_clock` / `start_training` /
//! `training_update` / `stop_transport` / `disable`), different
//! hardware:
//!
//! - The MG PLL state is computed by
//!   `intel_gpu_gen11_dpll::mg_pll_state` (the divisor search
//!   + ICL MG register packing) and written to direct MMIO at
//!     0x168xxx + (tc − 1) * 0x1000 — there is no HIP bank and
//!     no Type-C cold-reference machinery on this path.
//! - The FIA side (`icl_tc_phy_ops` in `intel_tc.c`) is `connect` /
//!   `disconnect` (the `DFLEXDPCSSS` ownership handshake, live mode from
//!   `DFLEXDPSP`) and `set_fia_lanes` (`DFLEXDPMLE1`), which the modeset
//!   programs before the PLL.
//! - The transcoder clock uses the display-11 encoding
//!   `TRANS_CLK_SEL_PORT(port) = (port + 1) << 29`
//!   (`intel_ddi_enable_transcoder_clock`, DISPLAY_VER < 12
//!   branch) — NOT the display-12 `(4 + tc) << 28` encoding the
//!   Dekel port uses.
//! - `DP_TP_CTL` is port-based on Gen11 (DDI base + 0x40),
//!   not transcoder-based (transcoder base + 0x540) as on
//!   Gen12.
//! - In TBT alt mode `icl_mg_phy_set_signal_levels` returns
//!   early — the MG levels path below is the DP/HDMI path
//!   only; alt-mode entry/exit is a separate remainder.
//!
//! ## Not in this module (remainders)
//!
//! - TCSS/FIA lane acquisition for Gen11 TC ports (see above).
//! - `CRI_LOADGEN_SEL` — Linux carries a FIXME ("Program
//!   CRI_LOADGEN_SEL after the spec is updated") and does not
//!   program it; neither do we.
//! - The VBT AFC-startup `div0` override (same remainder as
//!   the combo PLL in `intel_gpu_gen11_dpll`).

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gen11_ddi::{phy_for_port, Gen11Phy};
use crate::intel_gpu_gen11_dpll::{mg_pll_disable, mg_pll_enable, mg_pll_enable_reg, mg_pll_state};
use crate::intel_gpu_gen12_combo_phy::port_clock_khz;
use crate::intel_gpu_gt::Gen11Platform;
use crate::intel_gpu_modeset::ModesetError;
use crate::intel_gpu_pipes::Transcoder;
use crate::intel_gpu_pll::{LinkRate, DPCLKA_CFGCR0, DSSM};
use crate::intel_gpu_xelpg::preset_index;
use core::sync::atomic::{compiler_fence, Ordering};

// ── MG PHY registers (`display/intel_mg_phy_regs.h`) ─────────
//
// Per-TC-port stride is 0x1000 from the PORT1 (TC1) base;
// per-lane stride within a port is 0x400 (LN1 = LN0 + 0x400).
// `tc` is 0-based (TC1 = 0); `ln` is 0-based (0..2, one per
// lane pair); `tx` is 0-based (0 = TX1, 1 = TX2).

/// `MG_TX1_LINK_PARAMS(ln, tc_port)`: LN0 PORT1 0x16812C.
const fn mg_tx1_link_params(ln: u8, tc: u8) -> u64 {
    0x16812C + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX2_LINK_PARAMS(ln, tc_port)`: LN0 PORT1 0x1680AC.
const fn mg_tx2_link_params(ln: u8, tc: u8) -> u64 {
    0x1680AC + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX1_SWINGCTRL(ln, tc_port)`: LN0 PORT1 0x168148.
const fn mg_tx1_swingctrl(ln: u8, tc: u8) -> u64 {
    0x168148 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX2_SWINGCTRL(ln, tc_port)`: LN0 PORT1 0x1680C8.
const fn mg_tx2_swingctrl(ln: u8, tc: u8) -> u64 {
    0x1680C8 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX1_DRVCTRL(ln, tc_port)`: LN0 PORT1 0x168144.
const fn mg_tx1_drvctrl(ln: u8, tc: u8) -> u64 {
    0x168144 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX2_DRVCTRL(ln, tc_port)`: LN0 PORT1 0x1680C4.
const fn mg_tx2_drvctrl(ln: u8, tc: u8) -> u64 {
    0x1680C4 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_CLKHUB(ln, tc_port)`: LN0 PORT1 0x16839C.
const fn mg_clkhub(ln: u8, tc: u8) -> u64 {
    0x16839C + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX1_DCC(ln, tc_port)`: LN0 PORT1 0x168110.
const fn mg_tx1_dcc(ln: u8, tc: u8) -> u64 {
    0x168110 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX2_DCC(ln, tc_port)`: LN0 PORT1 0x168090.
const fn mg_tx2_dcc(ln: u8, tc: u8) -> u64 {
    0x168090 + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX1_PISO_READLOAD(ln, tc_port)`: LN0 PORT1 0x16814C.
const fn mg_tx1_piso_readload(ln: u8, tc: u8) -> u64 {
    0x16814C + ln as u64 * 0x400 + tc as u64 * 0x1000
}

/// `MG_TX2_PISO_READLOAD(ln, tc_port)`: LN0 PORT1 0x1680CC.
const fn mg_tx2_piso_readload(ln: u8, tc: u8) -> u64 {
    0x1680CC + ln as u64 * 0x400 + tc as u64 * 0x1000
}

fn mg_tx_swingctrl(tx: u8, ln: u8, tc: u8) -> u64 {
    if tx == 0 {
        mg_tx1_swingctrl(ln, tc)
    } else {
        mg_tx2_swingctrl(ln, tc)
    }
}

fn mg_tx_drvctrl(tx: u8, ln: u8, tc: u8) -> u64 {
    if tx == 0 {
        mg_tx1_drvctrl(ln, tc)
    } else {
        mg_tx2_drvctrl(ln, tc)
    }
}

fn mg_tx_dcc(tx: u8, ln: u8, tc: u8) -> u64 {
    if tx == 0 {
        mg_tx1_dcc(ln, tc)
    } else {
        mg_tx2_dcc(ln, tc)
    }
}

fn mg_tx_piso_readload(tx: u8, ln: u8, tc: u8) -> u64 {
    if tx == 0 {
        mg_tx1_piso_readload(ln, tc)
    } else {
        mg_tx2_piso_readload(ln, tc)
    }
}

/// `CRI_USE_FS32` — bit 5 of `MG_TXn_LINK_PARAMS`.
const MG_CRI_USE_FS32: u32 = 1 << 5;

/// `CRI_TXDEEMPH_OVERRIDE_17_12` field (bits [5:0]) and mask.
const MG_TXDEEMPH_OVERRIDE_17_12_MASK: u32 = 0x3F;

/// `CRI_TXDEEMPH_OVERRIDE_11_6` field (bits [29:24]) and mask.
const MG_TXDEEMPH_OVERRIDE_11_6_MASK: u32 = 0x3F << 24;

/// `CRI_TXDEEMPH_OVERRIDE_5_0` field (bits [21:16]) and mask.
const MG_TXDEEMPH_OVERRIDE_5_0_MASK: u32 = 0x3F << 16;

/// `CRI_TXDEEMPH_OVERRIDE_EN` — bit 22 of `MG_TXn_DRVCTRL`.
const MG_TXDEEMPH_OVERRIDE_EN: u32 = 1 << 22;

/// `CFG_LOW_RATE_LKREN_EN` — bit 11 of `MG_CLKHUB`.
const MG_CFG_LOW_RATE_LKREN_EN: u32 = 1 << 11;

/// `CFG_AMI_CK_DIV_OVERRIDE_VAL` mask (bits [26:25]) and
/// `CFG_AMI_CK_DIV_OVERRIDE_EN` (bit 24) of `MG_TXn_DCC`.
const MG_CFG_AMI_CK_DIV_OVERRIDE_VAL_MASK: u32 = 0x3 << 25;
const MG_CFG_AMI_CK_DIV_OVERRIDE_EN: u32 = 1 << 24;

/// `CRI_CALCINIT` — bit 1 of `MG_TXn_PISO_READLOAD`.
const MG_CRI_CALCINIT: u32 = 1 << 1;

/// `DDI_CLK_SEL(port)` (`display/intel_display_regs.h`):
/// `_PORT_CLK_SEL_A` 0x46100, stride 4.
const fn ddi_clk_sel(ddi: Ddi) -> u64 {
    0x46100 + ddi as u64 * 4
}

/// `DDI_CLK_SEL_MG` — `DDI_CLK_SEL` field value for an MG PLL
/// (`icl_pll_to_ddi_clk_sel`).
const DDI_CLK_SEL_MG: u32 = 0x8 << 28;

/// `TRANS_CLK_SEL(transcoder)` (`display/intel_display_regs.h`):
/// `_TRANS_CLK_SEL_A` 0x46140, stride 4.
const fn trans_clk_sel(trans: Transcoder) -> u64 {
    0x46140 + trans as u64 * 4
}

/// `DP_TP_CTL` offset from the DDI base on Gen11
/// (`_DP_TP_CTL_A` = 0x64040).
const DP_TP_CTL_OFFSET_GEN11: u64 = 0x40;

/// `DP_TP_CTL` enable / enhanced-frame / scramble-disable bits
/// (shared with the Gen12 programmer).
const DP_TP_CTL_ENABLE: u32 = 1 << 31;
const DP_TP_CTL_ENHANCED_FRAME_ENABLE: u32 = 1 << 18;
const DP_TP_CTL_LINK_TRAIN_MASK: u32 = 0x7 << 8;
const DP_TP_CTL_SCRAMBLE_DISABLE: u32 = 1 << 7;

/// One MG translation-table entry: the field order of Linux's
/// `intel_ddi_buf_trans_entry.mg`
/// (`display/intel_ddi_buf_trans.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgEntry {
    /// `cri_txdeemph_override_11_6`.
    pub deemph_11_6: u8,
    /// `cri_txdeemph_override_5_0`.
    pub deemph_5_0: u8,
    /// `cri_txdeemph_override_17_12`.
    pub deemph_17_12: u8,
}

const fn mg(deemph_11_6: u8, deemph_5_0: u8, deemph_17_12: u8) -> MgEntry {
    MgEntry {
        deemph_11_6,
        deemph_5_0,
        deemph_17_12,
    }
}

/// `icl_mg_phy_trans_rbr_hbr` — DP at port clock ≤ 270 MHz
/// (`display/intel_ddi_buf_trans.c`, transcribed verbatim).
pub static MG_DP_RBR_HBR: [MgEntry; 10] = [
    mg(0x18, 0x00, 0x00),
    mg(0x1D, 0x00, 0x05),
    mg(0x24, 0x00, 0x0C),
    mg(0x2B, 0x00, 0x14),
    mg(0x21, 0x00, 0x00),
    mg(0x2B, 0x00, 0x08),
    mg(0x30, 0x00, 0x0F),
    mg(0x31, 0x00, 0x03),
    mg(0x34, 0x00, 0x0B),
    mg(0x3F, 0x00, 0x00),
];

/// `icl_mg_phy_trans_hbr2_hbr3` — DP at port clock > 270 MHz.
pub static MG_DP_HBR2_HBR3: [MgEntry; 10] = [
    mg(0x18, 0x00, 0x00),
    mg(0x1D, 0x00, 0x05),
    mg(0x24, 0x00, 0x0C),
    mg(0x2B, 0x00, 0x14),
    mg(0x26, 0x00, 0x00),
    mg(0x2C, 0x00, 0x07),
    mg(0x33, 0x00, 0x0C),
    mg(0x2E, 0x00, 0x00),
    mg(0x36, 0x00, 0x09),
    mg(0x3F, 0x00, 0x00),
];

/// `icl_mg_phy_trans_hdmi` — HDMI (`hdmi_default_entry` is the
/// last entry, index 9).
pub static MG_HDMI: [MgEntry; 10] = [
    mg(0x1A, 0x00, 0x00),
    mg(0x20, 0x00, 0x00),
    mg(0x29, 0x00, 0x00),
    mg(0x32, 0x00, 0x00),
    mg(0x3F, 0x00, 0x00),
    mg(0x3A, 0x00, 0x05),
    mg(0x39, 0x00, 0x06),
    mg(0x38, 0x00, 0x07),
    mg(0x37, 0x00, 0x08),
    mg(0x36, 0x00, 0x09),
];

/// Default HDMI entry index (`hdmi_default_entry`).
pub const MG_HDMI_DEFAULT_ENTRY: usize = MG_HDMI.len() - 1;

/// One Ice Lake Type-C PHY: the DDI port and its 0-based TC index.
#[derive(Copy, Clone, Debug)]
pub struct MgPort {
    pub ddi: Ddi,
    pub tc: u8,
}

/// Ice Lake's one FIA (`tc_phy_load_fia_params(tc, false)`: not modular, so
/// every TC port sits in FIA1 at its own index).
const FIA1: u64 = 0x163000;
/// `PORT_TX_DFLEXDPSP`: live state and the pin (lane) assignment.
const PORT_TX_DFLEXDPSP: u64 = FIA1 + 0x8A0;
/// `PORT_TX_DFLEXDPPMS`: `DP_PHY_MODE_STATUS_COMPLETED(idx)`.
const PORT_TX_DFLEXDPPMS: u64 = FIA1 + 0x890;
/// `PORT_TX_DFLEXDPCSSS`: `DP_PHY_MODE_STATUS_NOT_SAFE(idx)`, display's
/// ownership claim.
const PORT_TX_DFLEXDPCSSS: u64 = FIA1 + 0x894;
/// `PORT_TX_DFLEXDPMLE1`: the main-link lanes display drives.
const PORT_TX_DFLEXDPMLE1: u64 = FIA1 + 0x8C0;
/// `SDEISR`: the ICP south hotplug status (`SDE_TC_HOTPLUG_ICP`, bit
/// 24 + TC index, is a legacy Type-C connector's live state).
const SDEISR: u64 = 0xC4000;

/// What drives a Type-C port (`enum tc_port_mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcMode {
    /// A native DP/HDMI connector wired to the Type-C PHY.
    Legacy,
    /// DisplayPort alternate mode over a USB-C cable.
    DpAlt,
    /// Thunderbolt alternate mode: the TBT controller owns the PHY.
    TbtAlt,
}

/// `icl_tc_phy_hpd_live_status`'s mask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcLive {
    pub legacy: bool,
    pub dp_alt: bool,
    pub tbt_alt: bool,
}

impl TcLive {
    /// `tc_phy_hpd_live_mode`: the one live mode, or `None` when nothing
    /// or more than one mode is live (Linux then keeps the port
    /// disconnected).
    pub fn mode(self) -> Option<TcMode> {
        match (self.legacy, self.dp_alt, self.tbt_alt) {
            (true, false, false) => Some(TcMode::Legacy),
            (false, true, false) => Some(TcMode::DpAlt),
            (false, false, true) => Some(TcMode::TbtAlt),
            _ => None,
        }
    }
}

impl MgPort {
    /// Qualify a DDI port as a Type-C port: IceLake DDI C–F
    /// only (TC1–TC4). Combo ports and EHL/JSL ports (which
    /// have no TC ports) refuse with `UnsupportedGeneration`.
    pub fn new(ddi: Ddi, platform: Gen11Platform) -> Result<Self, ModesetError> {
        match phy_for_port(platform, ddi) {
            Some(Gen11Phy::Mg { tc }) => Ok(Self { ddi, tc }),
            _ => Err(ModesetError::UnsupportedGeneration),
        }
    }

    /// `icl_tc_phy_hpd_live_status`: TBT-alt and DP-alt from the FIA,
    /// legacy from the ICP south ISR. `None` while the PHY is in TCCOLD
    /// (an all-ones FIA read: nothing connected).
    pub fn live_status(self, io: &(impl MmioWindow + ?Sized)) -> Option<TcLive> {
        let fia = io.read32(PORT_TX_DFLEXDPSP);
        if fia == u32::MAX {
            return None;
        }
        let idx = u32::from(self.tc);
        Some(TcLive {
            tbt_alt: fia & (1 << (idx * 8 + 6)) != 0,
            dp_alt: fia & (1 << (idx * 8 + 5)) != 0,
            legacy: io.read32(SDEISR) & (1 << (24 + idx)) != 0,
        })
    }

    /// `intel_tc_port_max_lane_count` for DP-alt: the pin assignment in
    /// `DFLEXDPSP` (`DP_LANE_ASSIGNMENT_MASK`) through
    /// `icl_get_max_lane_count`. Legacy ports have all four.
    fn max_lanes(self, io: &(impl MmioWindow + ?Sized), mode: TcMode) -> Result<u8, ModesetError> {
        if mode == TcMode::Legacy {
            return Ok(4);
        }
        let assigned = (io.read32(PORT_TX_DFLEXDPSP) >> (u32::from(self.tc) * 8)) & 0xF;
        match assigned {
            1 | 2 | 4 | 8 => Ok(1),
            3 | 12 => Ok(2),
            15 => Ok(4),
            _ => Err(ModesetError::PhyBusFailure),
        }
    }

    /// `icl_tc_phy_connect`: claim the PHY from the FIA for a legacy or
    /// DP-alt sink and return the lanes it can carry. The IOM must report
    /// the PHY ready (`DFLEXDPPMS`) before display sets its `NOT_SAFE`
    /// ownership bit in `DFLEXDPCSSS`; a DP-alt sink that went away or has
    /// fewer than `required_lanes` lanes releases it again. TBT-alt takes
    /// no ownership: the TBT controller keeps the PHY (`connect` returns
    /// the full width, which the TBT link itself bounds). Ice Lake has no
    /// TC-cold to block (no power well backs `TC_COLD_OFF`).
    pub fn connect(
        self,
        io: &(impl MmioWindow + ?Sized),
        mode: TcMode,
        required_lanes: u8,
    ) -> Result<u8, ModesetError> {
        if mode == TcMode::TbtAlt {
            return Ok(4);
        }
        let bit = 1u32 << self.tc;
        let ready = io.read32(PORT_TX_DFLEXDPPMS);
        let owned = io.read32(PORT_TX_DFLEXDPCSSS);
        if ready == u32::MAX || owned == u32::MAX || ready & bit == 0 {
            return Err(ModesetError::PhyBusFailure);
        }
        io.write32(PORT_TX_DFLEXDPCSSS, owned | bit);
        let verified = match mode {
            TcMode::Legacy => Ok(4),
            _ => match self.live_status(io) {
                Some(live) if live.dp_alt => self.max_lanes(io, mode).and_then(|max| {
                    (max >= required_lanes)
                        .then_some(max)
                        .ok_or(ModesetError::PhyBusFailure)
                }),
                _ => Err(ModesetError::PhyBusFailure),
            },
        };
        if verified.is_err() {
            self.release(io);
        }
        verified
    }

    /// Clear display's `NOT_SAFE` claim (`icl_tc_phy_take_ownership(tc,
    /// false)`).
    fn release(self, io: &(impl MmioWindow + ?Sized)) {
        let owned = io.read32(PORT_TX_DFLEXDPCSSS);
        if owned != u32::MAX {
            io.write32(PORT_TX_DFLEXDPCSSS, owned & !(1u32 << self.tc));
        }
    }

    /// `icl_tc_phy_disconnect`: legacy and DP-alt give the PHY back;
    /// TBT-alt never took it.
    pub fn disconnect(self, io: &(impl MmioWindow + ?Sized), mode: TcMode) {
        if mode != TcMode::TbtAlt {
            self.release(io);
        }
    }

    /// `intel_tc_port_set_fia_lane_count`: the main-link lanes in
    /// `DFLEXDPMLE1`, lane-reversed (ML3 / ML3_2) only on a legacy
    /// connector whose board reverses it (`dig_port->lane_reversal`; Linux
    /// warns on a reversed DP-alt port, whose orientation the FIA owns).
    pub fn set_fia_lanes(
        self,
        io: &(impl MmioWindow + ?Sized),
        width: u8,
        lane_reversal: bool,
    ) -> Result<(), ModesetError> {
        let idx = u32::from(self.tc) * 4;
        let lanes = match (width, lane_reversal) {
            (1, false) => 1,
            (1, true) => 8,
            (2, false) => 3,
            (2, true) => 12,
            (4, _) => 15,
            _ => return Err(ModesetError::PhyBusFailure),
        };
        let cur = io.read32(PORT_TX_DFLEXDPMLE1);
        if cur == u32::MAX {
            return Err(ModesetError::PhyBusFailure);
        }
        io.write32(PORT_TX_DFLEXDPMLE1, (cur & !(0xF << idx)) | (lanes << idx));
        Ok(())
    }

    /// `MG_PLL_ENABLE(tc_port)` for this port.
    pub fn pll_enable_register(self) -> u64 {
        mg_pll_enable_reg(self.tc)
    }

    fn check(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        if !io.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(())
    }

    fn read(self, io: &(impl MmioWindow + ?Sized), off: u64) -> Result<u32, ModesetError> {
        self.check(io)?;
        let value = io.read32(off);
        if value == u32::MAX {
            return Err(ModesetError::PhyBusFailure);
        }
        self.check(io)?;
        Ok(value)
    }

    fn rmw(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        clear: u32,
        set: u32,
    ) -> Result<(), ModesetError> {
        let old = self.read(io, off)?;
        io.write32(off, (old & !clear) | set);
        compiler_fence(Ordering::SeqCst);
        self.check(io)
    }

    fn wait_timeout(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        mask: u32,
        set: bool,
        ms: u64,
    ) -> Result<(), ModesetError> {
        let mut lost = false;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read(io, off) {
                Ok(v) => {
                    if set {
                        v & mask == mask
                    } else {
                        v & mask == 0
                    }
                }
                Err(_) => {
                    lost = true;
                    true
                }
            },
            narf_time::Deadline::after_ms(ms),
        );
        if !done || lost {
            return Err(ModesetError::PllLockTimeout);
        }
        Ok(())
    }

    /// `ICL_DPCLKA_CFGCR0_TC_CLK_OFF(tc_port)` — the clock-off
    /// bit for this TC port (1-based in Linux: TC1 → bit 13).
    /// Same mapping as the Dekel port's `clock_off`.
    fn clock_off(self) -> u32 {
        1 << if self.tc < 3 {
            self.tc + 12
        } else {
            self.tc - 3 + 21
        }
    }

    /// `mg_pll_enable` for this port's clock: compute the MG
    /// PLL state for `port_clock_khz` (`is_dp` selects the DP
    /// 8.1 GHz DCO rule vs the HDMI DCO range) at `refclk_khz`,
    /// then power-enable, write, and lock the PLL.
    /// `None` from the divisor search (unreachable clock or
    /// unknown refclk) is `PllLockTimeout`, matching the Dekel
    /// port's treatment of an uncomputable PLL state.
    pub fn enable(
        self,
        io: &(impl MmioWindow + ?Sized),
        port_clock_khz: u32,
        is_dp: bool,
        refclk_khz: u32,
    ) -> Result<(), ModesetError> {
        let state =
            mg_pll_state(port_clock_khz, is_dp, refclk_khz).ok_or(ModesetError::PllLockTimeout)?;
        mg_pll_enable(io, self.tc, &state).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// `mg_pll_disable` for this port.
    pub fn disable_pll(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        mg_pll_disable(io, self.tc).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// `icl_ddi_tc_enable_clock`: write `DDI_CLK_SEL(port)` =
    /// `DDI_CLK_SEL_MG`, then clear this port's
    /// `ICL_DPCLKA_CFGCR0_TC_CLK_OFF` bit.
    pub fn route_clock(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        self.rmw(io, ddi_clk_sel(self.ddi), 0xF << 28, DDI_CLK_SEL_MG)?;
        self.rmw(io, DPCLKA_CFGCR0, self.clock_off(), 0)
    }

    /// `icl_ddi_tc_enable_clock` on the TBT PLL (TBT-alt): `DDI_CLK_SEL`
    /// takes the TBT tap for the link clock (`icl_pll_to_ddi_clk_sel`:
    /// 162/270/540/810 MHz → 0xC..0xF), then the port's DPCLKA TC clock
    /// gate opens. The TBT PLL itself is `intel_gpu_gen11_dpll::
    /// tbt_pll_enable`'s; other link clocks have no TBT tap.
    pub fn route_tbt_clock(
        self,
        io: &(impl MmioWindow + ?Sized),
        port_clock_khz: u32,
    ) -> Result<(), ModesetError> {
        let select = match port_clock_khz {
            162_000 => 0xC,
            270_000 => 0xD,
            540_000 => 0xE,
            810_000 => 0xF,
            _ => return Err(ModesetError::PllLockTimeout),
        };
        self.rmw(io, ddi_clk_sel(self.ddi), 0xF << 28, select << 28)?;
        self.rmw(io, DPCLKA_CFGCR0, self.clock_off(), 0)
    }

    /// `icl_mg_phy_set_signal_levels` (`icl_get_mg_buf_trans`
    /// table selection + the per-lane-pair program).
    ///
    /// - HDMI → the MG HDMI table at the default entry
    ///   (`intel_ddi_hdmi_level` returns `hdmi_default_entry`);
    ///   `levels` is ignored.
    /// - DP → port clock > 270000 kHz takes the HBR2/HBR3
    ///   table, else the RBR/HBR table; per-lane entries come
    ///   from `preset_index(vswing, pre_emphasis)` (the same
    ///   (vs, pe) → index map the combo tables use).
    ///
    /// Per lane pair `ln` (lanes 2*ln, 2*ln+1 → TX1, TX2):
    /// clear `CRI_USE_FS32` on both LINK_PARAMS, program
    /// SWINGCTRL (17_12) and DRVCTRL (11_6 / 5_0 + override
    /// enable), set `CFG_LOW_RATE_LKREN_EN` on CLKHUB iff the
    /// port clock is < 300000 kHz, set the AMI clock-divider
    /// override on DCC iff the port clock is > 500000 kHz, and
    /// set `CRI_CALCINIT` on PISO_READLOAD.
    pub fn signal_levels(
        self,
        io: &(impl MmioWindow + ?Sized),
        port_clock_khz: u32,
        levels: &[(u8, u8); 4],
        is_hdmi: bool,
    ) -> Result<(), ModesetError> {
        let table: &[MgEntry] = if is_hdmi {
            &MG_HDMI
        } else if port_clock_khz > 270_000 {
            &MG_DP_HBR2_HBR3
        } else {
            &MG_DP_RBR_HBR
        };
        for ln in 0..2u8 {
            self.rmw(io, mg_tx1_link_params(ln, self.tc), MG_CRI_USE_FS32, 0)?;
            self.rmw(io, mg_tx2_link_params(ln, self.tc), MG_CRI_USE_FS32, 0)?;
            for tx in 0..2u8 {
                let lane = (2 * ln + tx) as usize;
                let idx = if is_hdmi {
                    MG_HDMI_DEFAULT_ENTRY
                } else {
                    preset_index(levels[lane].0, levels[lane].1)
                };
                let entry = table[idx];
                self.rmw(
                    io,
                    mg_tx_swingctrl(tx, ln, self.tc),
                    MG_TXDEEMPH_OVERRIDE_17_12_MASK,
                    u32::from(entry.deemph_17_12),
                )?;
                self.rmw(
                    io,
                    mg_tx_drvctrl(tx, ln, self.tc),
                    MG_TXDEEMPH_OVERRIDE_11_6_MASK | MG_TXDEEMPH_OVERRIDE_5_0_MASK,
                    (u32::from(entry.deemph_11_6) << 24)
                        | (u32::from(entry.deemph_5_0) << 16)
                        | MG_TXDEEMPH_OVERRIDE_EN,
                )?;
            }
            self.rmw(
                io,
                mg_clkhub(ln, self.tc),
                MG_CFG_LOW_RATE_LKREN_EN,
                if port_clock_khz < 300_000 {
                    MG_CFG_LOW_RATE_LKREN_EN
                } else {
                    0
                },
            )?;
            for tx in 0..2u8 {
                self.rmw(
                    io,
                    mg_tx_dcc(tx, ln, self.tc),
                    MG_CFG_AMI_CK_DIV_OVERRIDE_VAL_MASK | MG_CFG_AMI_CK_DIV_OVERRIDE_EN,
                    if port_clock_khz > 500_000 {
                        (1 << 25) | MG_CFG_AMI_CK_DIV_OVERRIDE_EN
                    } else {
                        0
                    },
                )?;
                self.rmw(io, mg_tx_piso_readload(tx, ln, self.tc), 0, MG_CRI_CALCINIT)?;
            }
        }
        Ok(())
    }

    /// HDMI default levels: the MG HDMI table's default entry
    /// on all four lanes (`icl_mg_phy_set_signal_levels` with
    /// the HDMI table — `intel_ddi_hdmi_level` returns
    /// `hdmi_default_entry` when there is no BIOS shift).
    pub fn set_hdmi_default_levels(
        self,
        io: &(impl MmioWindow + ?Sized),
        tmds_clock_khz: u32,
    ) -> Result<(), ModesetError> {
        self.signal_levels(io, tmds_clock_khz, &[(0, 0); 4], true)
    }

    /// Transcoder-clock select for this port
    /// (`intel_ddi_enable_transcoder_clock`, DISPLAY_VER < 12):
    /// `TRANS_CLK_SEL_PORT(port) = (port + 1) << 29` at
    /// `TRANS_CLK_SEL(transcoder)`.
    fn transcoder_clock(self, trans: Transcoder) -> Result<(u64, u32), ModesetError> {
        if trans == Transcoder::Edp {
            return Err(ModesetError::UnsupportedGeneration);
        }
        Ok((trans_clk_sel(trans), (u32::from(self.ddi as u8) + 1) << 29))
    }

    /// Start link training on a TC port: the Dekel
    /// `start_training` shape with Gen11 specifics — the
    /// transcoder clock uses the display-11 encoding and
    /// `DP_TP_CTL` is port-based (DDI base + 0x40).
    ///
    /// On retune (`retune = true`): stop the DDI buffer and
    /// TP_CTL, program the retry's FIA lane count, disable and
    /// re-enable the MG PLL at the new rate, and re-route the
    /// clock — then proceed as usual. The FIA lanes precede the
    /// PLL as in `intel_ddi_pre_pll_enable`; the first attempt's
    /// are the modeset's.
    pub(crate) fn start_training(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: Transcoder,
        rate: LinkRate,
        lanes: u8,
        retune: bool,
    ) -> Result<(), ModesetError> {
        let (clock, select) = self.transcoder_clock(trans)?;
        let tp = self.ddi.base() + DP_TP_CTL_OFFSET_GEN11;
        if retune {
            self.rmw(io, self.ddi.base(), 1 << 31, 0)?;
            self.wait_timeout(io, self.ddi.base(), 1 << 7, true, 10)?;
            self.rmw(io, tp, 1 << 31, 0)?;
            self.disable(io)?;
            self.set_fia_lanes(io, lanes, false)?;
            let refclk = crate::intel_gpu_pll::refclk_khz(self.read(io, DSSM)?);
            let port_clock = port_clock_khz(rate).ok_or(ModesetError::PllLockTimeout)?;
            self.enable(io, port_clock, true, refclk)?;
            self.route_clock(io)?;
        }
        self.signal_levels(
            io,
            port_clock_khz(rate).ok_or(ModesetError::PllLockTimeout)?,
            &[(0, 0); 4],
            false,
        )?;
        self.rmw(io, clock, 0xF << 28, select)?;
        self.rmw(
            io,
            tp,
            DP_TP_CTL_LINK_TRAIN_MASK | DP_TP_CTL_SCRAMBLE_DISABLE,
            DP_TP_CTL_ENABLE | DP_TP_CTL_ENHANCED_FRAME_ENABLE | DP_TP_CTL_SCRAMBLE_DISABLE,
        )?;
        self.rmw(
            io,
            self.ddi.base(),
            7 << 1,
            (1 << 31) | (u32::from(lanes) - 1) << 1,
        )?;
        self.wait_timeout(io, self.ddi.base(), 1 << 7, false, 10)
    }

    // Only the kernel-test lifecycle test calls this today
    // (the HPD / external-session lane will call it from
    // production once Gen11 TC ports are threaded through
    // `stop_pipeline`); cfg-gated, not deleted, so the
    // Dekel-port API shape stays intact for that lane.
    #[cfg(any(test, feature = "kernel-test"))]
    /// Stop the transport: clear `DP_TP_CTL` enable and the
    /// transcoder-clock route.
    pub(crate) fn stop_transport(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: Transcoder,
    ) -> Result<(), ModesetError> {
        let (clock, _) = self.transcoder_clock(trans)?;
        self.rmw(io, self.ddi.base() + DP_TP_CTL_OFFSET_GEN11, 1 << 31, 0)?;
        self.rmw(io, clock, 0xF << 28, 0)
    }

    /// Training source callback, mirroring the Dekel port's
    /// `training_update`: `Configure` is a no-op (the
    /// `TrainingAux` already programmed the DPCD), `Levels`
    /// re-programs the MG levels when the state is not dirty
    /// (a dirty state means the sink has not consumed the new
    /// levels yet), and `Pattern` retunes (disable + re-enable
    /// at the new rate) when TPS1 is re-entered dirty, then
    /// programs the pattern bits into `DP_TP_CTL` before the
    /// sink sees the new pattern.
    pub(crate) fn training_update(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: Transcoder,
        state: &crate::intel_gpu_modeset::training::State,
        change: crate::intel_gpu_modeset::training::Change,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_modeset::training::Change;
        match change {
            Change::Configure => Ok(()),
            Change::Levels if !state.dirty => self.signal_levels(
                io,
                port_clock_khz(state.rate).ok_or(ModesetError::PllLockTimeout)?,
                &state.levels,
                false,
            ),
            Change::Levels => Ok(()),
            Change::Pattern => {
                if state.pattern == 1 && state.dirty {
                    self.start_training(io, trans, state.rate, state.lanes, true)?;
                }
                self.rmw(
                    io,
                    self.ddi.base() + DP_TP_CTL_OFFSET_GEN11,
                    DP_TP_CTL_LINK_TRAIN_MASK | DP_TP_CTL_SCRAMBLE_DISABLE,
                    state
                        .pattern_bits()
                        .map_err(|_| ModesetError::PhyBusFailure)?,
                )
            }
        }
    }

    /// Stop the port: refuse while the DDI buffer is enabled,
    /// then clear the DPCLKA clock-off bit's inverse (set
    /// clock-off), clear the DDI clock select, and power the
    /// MG PLL down.
    pub fn disable(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        if self.read(io, self.ddi.base())? & (1 << 31) != 0 {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.rmw(io, DPCLKA_CFGCR0, 0, self.clock_off())?;
        self.rmw(io, ddi_clk_sel(self.ddi), 0xF << 28, 0)?;
        self.disable_pll(io)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::intel_gpu_gen11_dpll::{mg_pll_clktop2_hsclkctl, mg_pll_div0};
    use crate::intel_gpu_modeset::training::{State, TrainingAux};
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted MG endpoint: last-write-wins registers, MG
    /// enable registers whose LOCK follows ENABLE and whose
    /// POWER_STATE follows POWER_ENABLE, DDI_BUF_CTL IDLE that
    /// follows ENABLE, and a 19.2 MHz DSSM strap.
    struct MgModel {
        regs: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
        lost: Cell<bool>,
        no_lock: Cell<bool>,
    }

    impl MgModel {
        fn new() -> Self {
            Self {
                regs: RefCell::new(BTreeMap::from([(DSSM, 1 << 29)])),
                writes: Default::default(),
                lost: Cell::new(false),
                no_lock: Cell::new(false),
            }
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for MgModel {
        fn display_access_ok(&self) -> bool {
            !self.lost.get()
        }

        fn read32(&self, off: u64) -> u32 {
            if self.lost.get() {
                return u32::MAX;
            }
            let raw = self.regs.borrow().get(&off).copied().unwrap_or(0);
            match off {
                0x46030 | 0x46034 | 0x46038 | 0x4603C => {
                    (raw & !((1 << 26) | (1 << 30)))
                        | ((raw & (1 << 27)) >> 1)
                        | if !self.no_lock.get() {
                            (raw & (1 << 31)) >> 1
                        } else {
                            0
                        }
                }
                0x64000 | 0x64100 | 0x64200 | 0x64300 | 0x64400 | 0x64500 => {
                    (raw & !(1 << 7)) | if raw & (1 << 31) == 0 { 1 << 7 } else { 0 }
                }
                _ => raw,
            }
        }

        fn write32(&self, off: u64, value: u32) {
            self.writes.borrow_mut().push((off, value));
            self.regs.borrow_mut().insert(off, value);
        }
    }

    fn smoke_gen11_mg_tables() -> TestResult {
        // Spot-pin the transcribed Linux tables.
        if MG_DP_RBR_HBR.len() != 10
            || MG_DP_RBR_HBR[0] != mg(0x18, 0x00, 0x00)
            || MG_DP_RBR_HBR[9] != mg(0x3F, 0x00, 0x00)
        {
            return TestResult::Fail("MG RBR/HBR table values wrong");
        }
        if MG_DP_HBR2_HBR3[6] != mg(0x33, 0x00, 0x0C) || MG_DP_HBR2_HBR3[4] != mg(0x26, 0x00, 0x00)
        {
            return TestResult::Fail("MG HBR2/HBR3 table values wrong");
        }
        if MG_HDMI.len() != 10
            || MG_HDMI[0] != mg(0x1A, 0x00, 0x00)
            || MG_HDMI[MG_HDMI_DEFAULT_ENTRY] != mg(0x36, 0x00, 0x09)
        {
            return TestResult::Fail("MG HDMI table values or default entry wrong");
        }
        // The MG HDMI table is not the combo HDMI table (first
        // row 0x1A/0x00/0x00 vs the combo's 0x0A/0x60/0x3F).
        if MG_HDMI[0].deemph_5_0 != 0x00 {
            return TestResult::Fail("MG HDMI table must not be the combo table");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_mg_phy", smoke_gen11_mg_tables);

    /// Q8: the ICL Type-C connect/disconnect flow through FIA1. TC2
    /// (DDI D) is index 1 everywhere.
    fn smoke_icl_tc_fia_ownership() -> TestResult {
        let port = match MgPort::new(Ddi::D, Gen11Platform::IceLake) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ICL DDI D is TC2"),
        };
        let io = MgModel::new();
        let set = |off: u64, v: u32| {
            io.regs.borrow_mut().insert(off, v);
        };
        // TCCOLD: the FIA reads all-ones, nothing is connected.
        set(PORT_TX_DFLEXDPSP, u32::MAX);
        if port.live_status(&io).is_some() {
            return TestResult::Fail("an all-ones FIA is TCCOLD, not a live mode");
        }
        // DP-alt live (bit 8 + 5) with pin assignment ML1_0 (2 lanes),
        // the PHY ready (bit 1): ownership is taken, 2 lanes reported.
        set(PORT_TX_DFLEXDPSP, (1 << 13) | (3 << 8));
        set(PORT_TX_DFLEXDPPMS, 1 << 1);
        set(PORT_TX_DFLEXDPCSSS, 1 << 0);
        let live = port.live_status(&io).unwrap_or_default();
        if live.mode() != Some(TcMode::DpAlt) {
            return TestResult::Fail("bit 13 is TC2's DP-alt live state");
        }
        if port.connect(&io, TcMode::DpAlt, 2) != Ok(2) {
            return TestResult::Fail("a ready 2-lane DP-alt PHY must connect");
        }
        if io.writes_to(PORT_TX_DFLEXDPCSSS) != alloc::vec![(1 << 0) | (1 << 1)] {
            return TestResult::Fail("ownership must add NOT_SAFE(1) beside TC1's claim");
        }
        if port.set_fia_lanes(&io, 2, true).is_err()
            || io.writes_to(PORT_TX_DFLEXDPMLE1) != alloc::vec![12 << 4]
        {
            return TestResult::Fail("a reversed 2-lane link is ML3_2");
        }
        port.disconnect(&io, TcMode::DpAlt);
        if io.writes_to(PORT_TX_DFLEXDPCSSS).last() != Some(&(1 << 0)) {
            return TestResult::Fail("disconnect must clear only this port's claim");
        }
        // Needing 4 lanes on a 2-lane assignment releases the claim.
        let io = MgModel::new();
        io.regs
            .borrow_mut()
            .insert(PORT_TX_DFLEXDPSP, (1 << 13) | (3 << 8));
        io.regs.borrow_mut().insert(PORT_TX_DFLEXDPPMS, 1 << 1);
        if port.connect(&io, TcMode::DpAlt, 4).is_ok()
            || io.writes_to(PORT_TX_DFLEXDPCSSS) != alloc::vec![1 << 1, 0]
        {
            return TestResult::Fail("too few lanes must give the PHY back");
        }
        // Not ready: no ownership write at all.
        let io = MgModel::new();
        io.regs.borrow_mut().insert(PORT_TX_DFLEXDPSP, 1 << 13);
        if port.connect(&io, TcMode::DpAlt, 1).is_ok()
            || !io.writes_to(PORT_TX_DFLEXDPCSSS).is_empty()
        {
            return TestResult::Fail("an unready PHY must not be claimed");
        }
        // Legacy: the ICP ISR bit (24 + 1), four lanes; TBT-alt: no claim.
        let io = MgModel::new();
        io.regs.borrow_mut().insert(SDEISR, 1 << 25);
        io.regs.borrow_mut().insert(PORT_TX_DFLEXDPPMS, 1 << 1);
        if port.live_status(&io).and_then(TcLive::mode) != Some(TcMode::Legacy)
            || port.connect(&io, TcMode::Legacy, 4) != Ok(4)
        {
            return TestResult::Fail("a legacy connector connects with four lanes");
        }
        let io = MgModel::new();
        io.regs.borrow_mut().insert(PORT_TX_DFLEXDPSP, 1 << 14);
        if port.live_status(&io).and_then(TcLive::mode) != Some(TcMode::TbtAlt)
            || port.connect(&io, TcMode::TbtAlt, 4) != Ok(4)
            || !io.writes_to(PORT_TX_DFLEXDPCSSS).is_empty()
        {
            return TestResult::Fail("TBT-alt keeps the PHY with the TBT controller");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_icl_tc_fia_ownership
    );

    /// TBT-alt routes the port to the TBT PLL's tap for its link clock.
    fn smoke_icl_tbt_clock_routing() -> TestResult {
        let Ok(port) = MgPort::new(Ddi::E, Gen11Platform::IceLake) else {
            return TestResult::Fail("ICL DDI E is TC3");
        };
        for (clock, select) in [
            (162_000, 0xC),
            (270_000, 0xD),
            (540_000, 0xE),
            (810_000, 0xF),
        ] {
            let io = MgModel::new();
            if port.route_tbt_clock(&io, clock).is_err()
                || io.writes_to(ddi_clk_sel(Ddi::E)) != alloc::vec![select << 28]
            {
                return TestResult::Fail("DDI_CLK_SEL must take the TBT tap for the rate");
            }
        }
        if port.route_tbt_clock(&MgModel::new(), 216_000).is_ok() {
            return TestResult::Fail("a link clock without a TBT tap must refuse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_icl_tbt_clock_routing
    );

    fn smoke_gen11_mg_port_qualification() -> TestResult {
        let icl = Gen11Platform::IceLake;
        if MgPort::new(Ddi::C, icl).map(|p| (p.tc, p.pll_enable_register())) != Ok((0, 0x46030)) {
            return TestResult::Fail("ICL DDI C must be TC1 at 0x46030");
        }
        if MgPort::new(Ddi::F, icl).map(|p| (p.tc, p.pll_enable_register())) != Ok((3, 0x4603C)) {
            return TestResult::Fail("ICL DDI F must be TC4 at 0x4603C");
        }
        // Combo ports and EHL/JSL ports are not MG ports.
        if MgPort::new(Ddi::A, icl).is_ok()
            || MgPort::new(Ddi::B, icl).is_ok()
            || MgPort::new(Ddi::C, Gen11Platform::ElkhartLake).is_ok()
            || MgPort::new(Ddi::D, Gen11Platform::JasperLake).is_ok()
        {
            return TestResult::Fail("combo and EHL/JSL ports must not qualify as MG");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_gen11_mg_port_qualification
    );

    fn smoke_gen11_mg_pll_enable_route() -> TestResult {
        let io = MgModel::new();
        let port = MgPort::new(Ddi::C, Gen11Platform::IceLake).unwrap();
        if port.enable(&io, 540_000, true, 19_200).is_err() {
            return TestResult::Fail("MG PLL enable must succeed");
        }
        // Power-enable, then the state writes, then PLL enable.
        let enable_writes = io.writes_to(mg_pll_enable_reg(0));
        if enable_writes != alloc::vec![(1 << 27), (1 << 27) | (1 << 31)] {
            return TestResult::Fail("MG enable sequence must be power then PLL enable");
        }
        if io.writes_to(mg_pll_div0(0)) != alloc::vec![0x7C00_00D2] {
            return TestResult::Fail("MG DIV0 must carry the HBR2 state");
        }
        // Route: DDI_CLK_SEL_MG + clear the TC_CLK_OFF bit.
        io.regs.borrow_mut().insert(DPCLKA_CFGCR0, 1 << 12);
        if port.route_clock(&io).is_err() {
            return TestResult::Fail("MG route_clock must succeed");
        }
        if io.read32(ddi_clk_sel(Ddi::C)) & (0xF << 28) != 0x8 << 28 {
            return TestResult::Fail("route_clock must select the MG PLL");
        }
        if io.read32(DPCLKA_CFGCR0) & (1 << 12) != 0 {
            return TestResult::Fail("route_clock must clear the TC_CLK_OFF bit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_gen11_mg_pll_enable_route
    );

    fn smoke_gen11_mg_signal_levels() -> TestResult {
        let io = MgModel::new();
        let port = MgPort::new(Ddi::C, Gen11Platform::IceLake).unwrap();
        // HBR2 levels (1, 2) → index 6 → {0x33, 0x00, 0x0C}.
        // Preset the registers with every mask-relevant bit
        // set to prove the masks — but not all-ones: an
        // all-ones read is the device-gone sentinel
        // (`MgPort::read` returns `PhyBusFailure` on
        // `u32::MAX`), and bit 31 is in no mask below.
        for off in [
            mg_tx1_swingctrl(0, 0),
            mg_tx1_drvctrl(0, 0),
            mg_tx1_link_params(0, 0),
            mg_clkhub(0, 0),
            mg_tx1_dcc(0, 0),
        ] {
            io.regs.borrow_mut().insert(off, u32::MAX & !(1 << 31));
        }
        if port
            .signal_levels(&io, 540_000, &[(1, 2); 4], false)
            .is_err()
        {
            return TestResult::Fail("MG signal_levels must succeed");
        }
        if io.read32(mg_tx1_swingctrl(0, 0)) & 0x3F != 0x0C {
            return TestResult::Fail("MG SWINGCTRL must carry the 17_12 field");
        }
        let drv = io.read32(mg_tx1_drvctrl(0, 0));
        if drv >> 24 & 0x3F != 0x33 || drv >> 22 & 1 != 1 || drv >> 16 & 0x3F != 0x00 {
            return TestResult::Fail("MG DRVCTRL must carry 11_6 / 5_0 + override enable");
        }
        if io.read32(mg_tx1_link_params(0, 0)) & MG_CRI_USE_FS32 != 0 {
            return TestResult::Fail("MG LINK_PARAMS must clear CRI_USE_FS32");
        }
        // 540 MHz: CLKHUB low-rate off, DCC AMI override on.
        if io.read32(mg_clkhub(0, 0)) & MG_CFG_LOW_RATE_LKREN_EN != 0 {
            return TestResult::Fail("MG CLKHUB must not set low-rate above 300 MHz");
        }
        let dcc = io.read32(mg_tx1_dcc(0, 0));
        if dcc & (MG_CFG_AMI_CK_DIV_OVERRIDE_VAL_MASK | MG_CFG_AMI_CK_DIV_OVERRIDE_EN)
            != (1 << 25) | MG_CFG_AMI_CK_DIV_OVERRIDE_EN
        {
            return TestResult::Fail("MG DCC must set the AMI override above 500 MHz");
        }
        if io.read32(mg_tx1_piso_readload(0, 0)) & MG_CRI_CALCINIT == 0 {
            return TestResult::Fail("MG PISO_READLOAD must set CRI_CALCINIT");
        }
        // RBR (162 MHz) takes the RBR/HBR table: levels (1, 2)
        // → index 6 → {0x30, 0x00, 0x0F}, which differs from
        // the HBR2 entry 6 {0x33, 0x00, 0x0C}, so this check
        // actually pins the table selection. (Entry 0 is
        // byte-identical in both tables, so levels (0, 0)
        // could not distinguish them.)
        let io = MgModel::new();
        if port
            .signal_levels(&io, 162_000, &[(1, 2); 4], false)
            .is_err()
        {
            return TestResult::Fail("MG signal_levels must succeed");
        }
        if io.read32(mg_tx1_swingctrl(0, 0)) & 0x3F != 0x0F {
            return TestResult::Fail("MG SWINGCTRL must carry the 17_12 field");
        }
        let drv = io.read32(mg_tx1_drvctrl(0, 0));
        if drv >> 24 & 0x3F != 0x30 || drv >> 22 & 1 != 1 || drv >> 16 & 0x3F != 0x00 {
            return TestResult::Fail("MG DRVCTRL must carry 11_6 / 5_0 + override enable");
        }
        // HDMI takes the HDMI table at the default entry 9
        // {0x36, 0x00, 0x09} regardless of the levels input.
        let io = MgModel::new();
        if port.set_hdmi_default_levels(&io, 148_500).is_err()
            || io.read32(mg_tx1_swingctrl(0, 0)) & 0x3F != 0x09
            || io.read32(mg_tx1_drvctrl(0, 0)) >> 24 & 0x3F != 0x36
            || io.read32(mg_clkhub(0, 0)) & MG_CFG_LOW_RATE_LKREN_EN == 0
            || io.read32(mg_tx1_dcc(0, 0))
                & (MG_CFG_AMI_CK_DIV_OVERRIDE_VAL_MASK | MG_CFG_AMI_CK_DIV_OVERRIDE_EN)
                != 0
        {
            return TestResult::Fail("MG HDMI must use the default entry + low-rate clock");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_gen11_mg_signal_levels
    );

    fn smoke_gen11_mg_training_programs_source_before_sink_pattern() -> TestResult {
        struct Sink<'a>(&'a MgModel);
        impl AuxChannel for Sink<'_> {
            fn transact<'a>(
                &mut self,
                request: &AuxRequest<'_>,
                reply: &'a mut [u8],
            ) -> Result<AuxResponse<'a>, AuxError> {
                if request.cmd == AuxCommand::NativeWrite && request.address == 0x102 {
                    let bits = match request.data[0] & 7 {
                        0 => 3,
                        1 => 0,
                        2 => 1,
                        3 => 4,
                        7 => 5,
                        _ => return Err(AuxError::Nacked),
                    };
                    if self.0.read32(0x64200) & (1 << 31) == 0
                        || (self.0.read32(0x64240) >> 8) & 7 != bits
                    {
                        return Err(AuxError::Nacked);
                    }
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
        }
        let io = MgModel::new();
        let port = MgPort::new(Ddi::C, Gen11Platform::IceLake).unwrap();
        if port.enable(&io, 540_000, true, 19_200).is_err()
            || port.route_clock(&io).is_err()
            || port
                .start_training(&io, Transcoder::A, LinkRate::DpHbr2, 2, false)
                .is_err()
        {
            return TestResult::Fail("source must enable its DDI before sink CR/EQ");
        }
        // Display-11 transcoder clock: (port + 1) << 29 at
        // TRANS_CLK_SEL(A) — DDI C is port index 2.
        if io.read32(0x46140) != (2 + 1) << 29 {
            return TestResult::Fail("source must route the ICL transcoder clock");
        }
        // DDI_BUF_CTL enabled at 2 lanes; DP_TP_CTL enabled.
        if io.read32(0x64200) & (1 << 31) == 0
            || io.read32(0x64200) & (7 << 1) != (2 - 1) << 1
            || io.read32(0x64240) & (1 << 31) == 0
        {
            return TestResult::Fail("source must enable the DDI buffer and TP_CTL");
        }
        let mut aux = TrainingAux::new(
            Sink(&io),
            State::new(LinkRate::DpHbr2, 2),
            |state: &State, change| {
                port.training_update(&io, Transcoder::A, state, change)
                    .map_err(|_| AuxError::Nacked)
            },
        );
        // Levels (1, 0) → index 4 → HBR2 entry {0x26, 0x00, 0x00}:
        // DRVCTRL = 0x26 << 24 | override enable. The lane-set
        // byte is swing in bits[1:0], pre-emphasis in bits[4:3],
        // so (1, 0) is 0x01 — not 0x09, which is (1, 1).
        if aux.dpcd_write(0x103, &[0x01, 0]).is_err()
            || io.read32(mg_tx1_drvctrl(0, 0)) != (0x26 << 24) | MG_TXDEEMPH_OVERRIDE_EN
        {
            return TestResult::Fail("source drive must follow sink's per-lane request");
        }
        for pattern in [1, 2, 3, 7, 0] {
            if aux.dpcd_write(0x102, &[pattern]).is_err() {
                return TestResult::Fail("source pattern must precede sink pattern");
            }
        }
        // Fallback: HBR at one lane — retunes through the MG PLL
        // (HBR hsclk 0x9200) and the DDI drops to X1.
        if aux.dpcd_write(0x100, &[0x0A, 1]).is_err()
            || aux.dpcd_write(0x102, &[1]).is_err()
            || io.read32(0x64200) & (7 << 1) != 0
            || io.writes_to(mg_pll_clktop2_hsclkctl(0)).last() != Some(&0x9200)
        {
            return TestResult::Fail("fallback must retune at one lane through the MG PLL");
        }
        io.write32(0x64200, io.read32(0x64200) & !(1 << 31));
        if port.stop_transport(&io, Transcoder::A).is_err() || port.disable(&io).is_err() {
            return TestResult::Fail("trained source must stop and release");
        }
        if io.read32(0x46140) != 0
            || io.read32(mg_pll_enable_reg(0)) & ((1 << 31) | (1 << 27)) != 0
            || io.read32(ddi_clk_sel(Ddi::C)) & (0xF << 28) != 0
        {
            return TestResult::Fail("stop must remove the transcoder clock, PLL, and route");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_mg_phy",
        smoke_gen11_mg_training_programs_source_before_sink_pattern
    );
}

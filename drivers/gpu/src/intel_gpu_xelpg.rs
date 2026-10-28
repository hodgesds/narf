//! Intel Xe-LPG display PHY layer — Meteor Lake (MTL).
//!
//! The Xe-LPG display engine replaces Gen12's combo-PHY + DPLL
//! model with two SerDes PHYs hanging off a per-port message bus:
//!
//! - **C10 PHY** — behind DDI A and DDI B (the "combo" ports).
//! - **C20 PHY** — behind the Type-C ports TC1 / TC2.
//!
//! Both PHYs are programmed the same way at the transport level:
//! the display engine issues 8-bit reads/writes to PHY-internal
//! "VDR" (vendor-defined register) addresses through the port's
//! **M2P message bus** registers and collects ACKs from the P2M
//! status register. Above the transport the PHYs diverge:
//!
//! - C10 keeps its PLL state as 20 bytes of VDR PLL registers
//!   plus one CMN and one TX byte, written directly.
//! - C20 keeps its PLL state as 16-bit words in a SRAM context
//!   (two contexts, A and B; the driver writes the inactive one
//!   and toggles), reached through a VDR address/data window.
//!
//! This module is the codec + transport layer: the port register
//! map, the message-bus conversation, the PRM PLL state tables,
//! the port-PLL enable sequence, and the TX signal-level
//! programming. The modeset orchestration that consumes it lives
//! in [`crate::intel_gpu_modeset_xelpg`].
//!
//! ## Sources
//!
//! Register substance is transcribed from the Intel Meteor Lake
//! display PRM as implemented by the authoritative Linux i915
//! sources (GPL-2.0-or-later; NARF is GPL-2.0-or-later):
//!
//! - `drivers/gpu/drm/i915/display/intel_cx0_phy_regs.h` — port
//!   register offsets, message-bus fields, C10/C20 VDR map.
//! - `drivers/gpu/drm/i915/display/intel_cx0_phy.c` — message-bus
//!   transaction shape, C10/C20 PLL state tables, PLL enable
//!   sequence, signal-level programming.
//! - `drivers/gpu/drm/i915/display/intel_ddi_buf_trans.c` — the
//!   MTL C10/C20 DP 1.4 voltage-swing translation tables.
//!
//! Nothing here is derived from the Gen12 code in
//! [`crate::intel_gpu_pll`] / [`crate::intel_gpu_ddi`]: Xe-LPG
//! has no `DPCLKA_CFGCR0`, no `DPLL_CFGCR*`, and no
//! `DDI_BUF_TRANS` register file, and the fixtures in this module
//! pin that separation.
//!
//! ## Scope
//!
//! - DP 1.4 rates only (RBR/HBR/HBR2/HBR3 + the eDP intermediate
//!   rates on C10). DP 2.0 UHBR rates use the C20 MPLLA tables and
//!   128b/132b encoding, which the DP stack in this tree does not
//!   model yet.
//! - HDMI PLL states (C10/C20 carry separate HDMI tables) land
//!   with the HDMI lane; this module's lookups return `None` for
//!   non-DP rates.
//! - Lane reversal and DP-alt single-lane ownership are not
//!   modelled: both PHY lanes are always owned (the shape every
//!   MTL SKU's DDI A / TC1 wiring presents at boot).

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pll::LinkRate;

// ── Port model ───────────────────────────────────────────────────

/// Which SerDes PHY sits behind a port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyKind {
    /// C10 — DDI A / DDI B.
    C10,
    /// C20 — TC1 / TC2.
    C20,
}

/// An Xe-LPG display port. Register bases are absolute BAR0
/// offsets transcribed from `intel_cx0_phy_regs.h` /
/// `intel_dp_aux_regs.h`; the TC block is *not* a uniform stride
/// from the DDI A block (e.g. `PORT_MSGBUS_TIMER` sits at +0xD8
/// on DDI A but +0x58 on TC1), so each port carries its own row.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XeLpgPort {
    /// DDI A — the eDP panel port on mobile MTL (C10 PHY).
    A,
    /// DDI B — second combo port (C10 PHY).
    B,
    /// TC1 — first Type-C port (C20 PHY).
    Tc1,
    /// TC2 — second Type-C port (C20 PHY).
    Tc2,
}

impl XeLpgPort {
    /// `XELPDP_PORT_BUF_CTL1` absolute offset.
    pub const fn buf_ctl1(self) -> u64 {
        match self {
            XeLpgPort::A => 0x6_4004,
            XeLpgPort::B => 0x6_4104,
            XeLpgPort::Tc1 => 0x16_F200,
            XeLpgPort::Tc2 => 0x16_F400,
        }
    }
    /// `XELPDP_PORT_BUF_CTL2` (BUF_CTL1 + 4 on every port).
    pub const fn buf_ctl2(self) -> u64 {
        self.buf_ctl1() + 4
    }
    /// `XELPDP_PORT_BUF_CTL3` (BUF_CTL1 + 8 on every port).
    pub const fn buf_ctl3(self) -> u64 {
        self.buf_ctl1() + 8
    }
    /// `XELPDP_PORT_M2P_MSGBUS_CTL` for PHY lane 0; lane *n* is at
    /// `+ 4*n`, and the P2M status register for lane *n* is at
    /// `+ 4*n + 8`.
    pub const fn msgbus_ctl_ln0(self) -> u64 {
        match self {
            XeLpgPort::A => 0x6_4040,
            XeLpgPort::B => 0x6_4140,
            XeLpgPort::Tc1 => 0x16_F240,
            XeLpgPort::Tc2 => 0x16_F440,
        }
    }
    /// `XELPDP_PORT_MSGBUS_TIMER` for PHY lane 0 (+4 per lane).
    pub const fn msgbus_timer_ln0(self) -> u64 {
        match self {
            XeLpgPort::A => 0x6_40D8,
            XeLpgPort::B => 0x6_41D8,
            XeLpgPort::Tc1 => 0x16_F258,
            XeLpgPort::Tc2 => 0x16_F458,
        }
    }
    /// `XELPDP_PORT_CLOCK_CTL` absolute offset.
    pub const fn port_clock_ctl(self) -> u64 {
        match self {
            XeLpgPort::A => 0x6_40E0,
            XeLpgPort::B => 0x6_41E0,
            XeLpgPort::Tc1 => 0x16_F260,
            XeLpgPort::Tc2 => 0x16_F460,
        }
    }
    /// `XELPDP_DP_AUX_CH_CTL` absolute offset (DATA at +4). The TC
    /// AUX block follows the same +0x10/+0x14 layout from the TC
    /// port block base as DDI A does from 0x64000.
    pub const fn aux_ctl(self) -> u64 {
        match self {
            XeLpgPort::A => 0x6_4010,
            XeLpgPort::B => 0x6_4110,
            XeLpgPort::Tc1 => 0x16_F210,
            XeLpgPort::Tc2 => 0x16_F410,
        }
    }
    /// BAR0 base of this port's AUX register block (CTL at +0x10,
    /// DATA at +0x14) in the shape [`crate::intel_gpu_aux`] expects
    /// (the Gen12 DDI block layout, which Xe-LPG preserves).
    pub const fn aux_base(self) -> u64 {
        self.aux_ctl() - 0x10
    }
    /// `DDI_CLK_VALFREQ` — present on the combo (C10) ports only.
    /// The C20 ports carry their rate in the PHY's serdes-rate VDR
    /// instead, so there is no register to write.
    pub const fn clk_valfreq(self) -> Option<u64> {
        match self {
            XeLpgPort::A => Some(0x6_4030),
            XeLpgPort::B => Some(0x6_4130),
            XeLpgPort::Tc1 | XeLpgPort::Tc2 => None,
        }
    }
    /// The PHY behind this port.
    pub const fn phy(self) -> PhyKind {
        match self {
            XeLpgPort::A | XeLpgPort::B => PhyKind::C10,
            XeLpgPort::Tc1 | XeLpgPort::Tc2 => PhyKind::C20,
        }
    }
    /// PHY index for `TRANS_CLK_SEL` (i915 `enum phy`: A=0, B=1,
    /// TC1=C=2, TC2=D=3 on MTL).
    pub const fn phy_index(self) -> u32 {
        match self {
            XeLpgPort::A => 0,
            XeLpgPort::B => 1,
            XeLpgPort::Tc1 => 2,
            XeLpgPort::Tc2 => 3,
        }
    }
    /// Port index for `TRANS_DDI_FUNC_CTL`'s DDI-select field,
    /// which carries i915's `enum port` value (the shared builder
    /// adds the +1 the TGL field encoding wants): A=0, B=1,
    /// TC1=9, TC2=10.
    pub const fn func_ctl_index(self) -> u8 {
        match self {
            XeLpgPort::A => 0,
            XeLpgPort::B => 1,
            XeLpgPort::Tc1 => 9,
            XeLpgPort::Tc2 => 10,
        }
    }
    /// Index of this port's AUX power well inside
    /// `PWR_WELL_CTL_AUX2` (0x45444): AUX_A=0, AUX_B=1 (ICL
    /// numbering), AUX_USBC1=3, AUX_USBC2=4 (TGL TC numbering).
    pub const fn aux_well_index(self) -> u32 {
        match self {
            XeLpgPort::A => 0,
            XeLpgPort::B => 1,
            XeLpgPort::Tc1 => 3,
            XeLpgPort::Tc2 => 4,
        }
    }
    /// Whether this port can carry an eDP panel (DDI A only on
    /// MTL platforms this driver targets).
    pub const fn is_edp(self) -> bool {
        matches!(self, XeLpgPort::A)
    }
}

// ── PORT_BUF_CTL / PORT_CLOCK_CTL fields ─────────────────────────
//
// From `intel_cx0_phy_regs.h`. Only the fields this layer drives
// are named; the register headers carry the rest.

/// `XELPDP_PORT_BUF_D2D_LINK_ENABLE` (BUF_CTL1 bit 29) — the
/// die-to-die link between the SoC tile (display engine) and the
/// IO tile (PHYs). Every MTL port traverses it.
pub const PORT_BUF_D2D_LINK_ENABLE: u32 = 1 << 29;
/// `XELPDP_PORT_BUF_D2D_LINK_STATE` (BUF_CTL1 bit 28).
pub const PORT_BUF_D2D_LINK_STATE: u32 = 1 << 28;
/// `XELPDP_PORT_BUF_SOC_PHY_READY` (BUF_CTL1 bit 24).
pub const PORT_BUF_SOC_PHY_READY: u32 = 1 << 24;
/// `XELPDP_PORT_BUF_PORT_DATA_WIDTH` field (BUF_CTL1 bits 19:18);
/// 0 = 10-bit (DP 1.4 8b/10b), the only width this lane programs.
pub const PORT_BUF_PORT_DATA_WIDTH_MASK: u32 = 0x3 << 18;
/// `XELPDP_PORT_REVERSAL` (BUF_CTL1 bit 16).
pub const PORT_BUF_REVERSAL: u32 = 1 << 16;
/// `XELPDP_PORT_WIDTH` field (BUF_CTL1 bits 3:1).
pub const PORT_WIDTH_MASK: u32 = 0x7 << 1;
/// `XELPDP_PORT_WIDTH(width)`: 3 lanes encodes as 4, else width-1.
pub const fn port_width(lanes: u8) -> u32 {
    let w = if lanes == 3 {
        4
    } else {
        lanes.saturating_sub(1)
    };
    (w as u32) << 1
}

/// `XELPDP_LANE_PIPE_RESET(lane)` (BUF_CTL2 bits 31/30).
pub const fn lane_pipe_reset(lane: u32) -> u32 {
    1 << (31 - lane)
}
/// `XELPDP_LANE_PHY_CURRENT_STATUS(lane)` (BUF_CTL2 bits 29/28).
pub const fn lane_phy_current_status(lane: u32) -> u32 {
    1 << (29 - lane)
}
/// `XELPDP_LANE_POWERDOWN_UPDATE(lane)` (BUF_CTL2 bits 25/24).
pub const fn lane_powerdown_update(lane: u32) -> u32 {
    1 << (25 - lane)
}
/// Powerdown new-state field for `lane` in BUF_CTL2
/// (lane 0: bits 23:20, lane 1: bits 19:16).
pub const fn lane_powerdown_new_state(lane: u32, state: u32) -> u32 {
    (state & 0xF) << (20 - 4 * lane)
}
/// Mask covering both lanes' powerdown new-state fields.
pub const POWERDOWN_NEW_STATE_MASK_BOTH: u32 = 0xFF << 16;
/// `XELPDP_POWER_STATE_READY` field (BUF_CTL2 bits 7:4).
pub const POWER_STATE_READY_MASK: u32 = 0xF << 4;
/// `XELPDP_POWER_STATE_ACTIVE` field (BUF_CTL3 bits 3:0).
pub const POWER_STATE_ACTIVE_MASK: u32 = 0xF;
/// `XELPDP_PLL_LANE_STAGGERING_DELAY` field (BUF_CTL3 bits 15:8).
pub const PLL_LANE_STAGGERING_DELAY_MASK: u32 = 0xFF << 8;

/// Powerdown state: P2 = ready (PHY up, lanes held in reset-grade
/// readiness — the state PLL programming happens in).
pub const P2_STATE_READY: u32 = 0x2;
/// Powerdown state: P2 encoding reused for the reset phase of the
/// lane-reset sequence (`XELPDP_P2_STATE_RESET` is also 0x2).
pub const P2_STATE_RESET: u32 = 0x2;
/// Powerdown state: P0 = fully active.
pub const P0_STATE_ACTIVE: u32 = 0x0;

/// `XELPDP_LANE_PCLK_PLL_REQUEST(lane)` (PORT_CLOCK_CTL
/// bits 31/27).
pub const fn lane_pclk_pll_request(lane: u32) -> u32 {
    1 << (31 - 4 * lane)
}
/// `XELPDP_LANE_PCLK_PLL_ACK(lane)` (PORT_CLOCK_CTL bits 30/26).
pub const fn lane_pclk_pll_ack(lane: u32) -> u32 {
    1 << (30 - 4 * lane)
}
/// `XELPDP_LANE_PCLK_REFCLK_REQUEST(lane)` (bits 29/25).
pub const fn lane_pclk_refclk_request(lane: u32) -> u32 {
    1 << (29 - 4 * lane)
}
/// `XELPDP_LANE_PCLK_REFCLK_ACK(lane)` (bits 28/24).
pub const fn lane_pclk_refclk_ack(lane: u32) -> u32 {
    1 << (28 - 4 * lane)
}
/// `XELPDP_DDI_CLOCK_SELECT` field (PORT_CLOCK_CTL bits 15:12).
pub const DDI_CLOCK_SELECT_MASK: u32 = 0xF << 12;
/// Clock select for a PHY PLL output (maxPCLK): the DP value.
pub const DDI_CLOCK_SELECT_MAXPCLK: u32 = 0x8 << 12;
/// `XELPDP_FORWARD_CLOCK_UNGATE` (PORT_CLOCK_CTL bit 10).
pub const FORWARD_CLOCK_UNGATE: u32 = 1 << 10;
/// `XELPDP_LANE1_PHY_CLOCK_SELECT` (PORT_CLOCK_CTL bit 8).
pub const LANE1_PHY_CLOCK_SELECT: u32 = 1 << 8;
/// `XELPDP_SSC_ENABLE_PLLA` (PORT_CLOCK_CTL bit 1).
pub const SSC_ENABLE_PLLA: u32 = 1 << 1;
/// `XELPDP_SSC_ENABLE_PLLB` (PORT_CLOCK_CTL bit 0).
pub const SSC_ENABLE_PLLB: u32 = 1;

// ── Message bus (M2P / P2M) ──────────────────────────────────────
//
// One transaction (from `intel_cx0_phy.c::__intel_cx0_write_once`):
//
//   1. Wait for M2P TRANSACTION_PENDING to clear.
//   2. Clear the P2M response-ready flag (write-1-to-clear).
//   3. Write M2P ctl = PENDING | command | data<<16 | address.
//   4. Wait for TRANSACTION_PENDING to clear.
//   5. Committed writes and all reads: poll P2M status for
//      RESPONSE_READY, reject ERROR_SET, verify the ACK command
//      type matches the request.
//   6. Clear the response flag, then reset the bus
//      (TRANSACTION_RESET write + wait-clear) — the pre-Xe3
//      hardware settle workaround i915 applies on MTL.

const M2P_TRANSACTION_PENDING: u32 = 1 << 31;
const M2P_COMMAND_SHIFT: u32 = 27;
const M2P_COMMAND_WRITE_UNCOMMITTED: u32 = 0x1 << M2P_COMMAND_SHIFT;
const M2P_COMMAND_WRITE_COMMITTED: u32 = 0x2 << M2P_COMMAND_SHIFT;
const M2P_COMMAND_READ: u32 = 0x3 << M2P_COMMAND_SHIFT;
const M2P_DATA_SHIFT: u32 = 16;
const M2P_TRANSACTION_RESET: u32 = 1 << 15;

const P2M_RESPONSE_READY: u32 = 1 << 31;
const P2M_COMMAND_MASK: u32 = 0xF << M2P_COMMAND_SHIFT;
const P2M_COMMAND_READ_ACK: u32 = 0x4 << M2P_COMMAND_SHIFT;
const P2M_COMMAND_WRITE_ACK: u32 = 0x5 << M2P_COMMAND_SHIFT;
const P2M_DATA_MASK: u32 = 0xFF << M2P_DATA_SHIFT;
const P2M_ERROR_SET: u32 = 1 << 15;

/// Message-bus timeout: `XELPDP_MSGBUS_TIMEOUT_MS` = 1 ms.
const MSGBUS_TIMEOUT_NS: u64 = 1_000_000;
/// Transaction attempts before giving up (`__intel_cx0_write` /
/// `__intel_cx0_read` retry 3 times).
const MSGBUS_ATTEMPTS: u32 = 3;

/// PHY-layer failure. The modeset maps these onto its own error
/// type; the variants stay distinct here so fixtures can pin
/// *why* a conversation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cx0Error {
    /// A poll (transaction pending, ACK, PLL lock, power state)
    /// did not complete inside its PRM budget.
    Timeout,
    /// The PHY answered with `P2M_ERROR_SET`.
    PhyError,
    /// The PHY answered with an ACK whose command type does not
    /// match the request (e.g. a read ACK to a write) — the
    /// signature of a wrong-generation register model answering
    /// the bus.
    ProtocolMismatch,
    /// No PLL state table exists for the requested rate on this
    /// PHY (e.g. an HDMI rate, or an eDP-only rate on a DP port).
    UnsupportedRate,
}

/// Poll `off` until `mask` is set (`want_set`) or clear, within
/// `timeout_ns`. Same discipline as the Gen12 modeset's `wait_bit`.
fn wait_for<M: MmioWindow + ?Sized>(
    mmio: &M,
    off: u64,
    mask: u32,
    want_set: bool,
    timeout_ns: u64,
) -> bool {
    let budget = narf_time::wall::ns_to_cycles(timeout_ns);
    let start = narf_time::now_cycles();
    loop {
        let v = mmio.read32(off);
        if (v & mask != 0) == want_set {
            return true;
        }
        if narf_time::now_cycles().wrapping_sub(start) > budget {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Read-modify-write one MMIO register.
fn rmw<M: MmioWindow + ?Sized>(mmio: &M, off: u64, clear: u32, set: u32) {
    let cur = mmio.read32(off);
    mmio.write32(off, (cur & !clear) | set);
    compiler_fence(Ordering::SeqCst);
}

/// The C10/C20 message-bus transport for one port. Stateless: the
/// PHY keeps the state, this type just runs the conversation.
pub struct Cx0Phy<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    /// The port this transport talks to.
    pub port: XeLpgPort,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for Cx0Phy<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cx0Phy").field("port", &self.port).finish()
    }
}

/// Both PHY lanes owned — the only ownership shape this lane
/// programs (see module scope notes).
pub const BOTH_LANES: u8 = 0b11;
/// Lane mask bit for PHY lane 0.
pub const LANE0: u8 = 0b01;
/// Lane mask bit for PHY lane 1.
pub const LANE1: u8 = 0b10;

impl<'a, M: MmioWindow + ?Sized> Cx0Phy<'a, M> {
    /// Create a transport for `port` over the BAR0 window `mmio`.
    pub fn new(mmio: &'a M, port: XeLpgPort) -> Self {
        Self { mmio, port }
    }

    fn m2p_ctl(&self, lane: u32) -> u64 {
        self.port.msgbus_ctl_ln0() + (lane as u64) * 4
    }
    fn p2m_status(&self, lane: u32) -> u64 {
        self.port.msgbus_ctl_ln0() + (lane as u64) * 4 + 8
    }

    /// Clear the P2M response-ready / error flags. The bits are
    /// write-1-to-clear, so this writes them back set.
    fn clear_response_ready(&self, lane: u32) {
        let off = self.p2m_status(lane);
        let cur = self.mmio.read32(off);
        self.mmio
            .write32(off, cur | P2M_RESPONSE_READY | P2M_ERROR_SET);
        compiler_fence(Ordering::SeqCst);
    }

    /// Reset one lane's message bus and wait for it to idle
    /// (`intel_cx0_bus_reset`).
    fn bus_reset(&self, lane: u32) {
        let ctl = self.m2p_ctl(lane);
        self.mmio.write32(ctl, M2P_TRANSACTION_RESET);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_for(
            self.mmio,
            ctl,
            M2P_TRANSACTION_RESET,
            false,
            MSGBUS_TIMEOUT_NS,
        );
        self.clear_response_ready(lane);
    }

    /// Wait for the PHY's ACK to a transaction expecting command
    /// type `expect` in the P2M status.
    fn wait_for_ack(&self, lane: u32, expect: u32) -> Result<u32, Cx0Error> {
        let status_off = self.p2m_status(lane);
        let budget = narf_time::wall::ns_to_cycles(MSGBUS_TIMEOUT_NS);
        let start = narf_time::now_cycles();
        let val = loop {
            let v = self.mmio.read32(status_off);
            if v & P2M_RESPONSE_READY != 0 {
                break v;
            }
            if narf_time::now_cycles().wrapping_sub(start) > budget {
                self.bus_reset(lane);
                return Err(Cx0Error::Timeout);
            }
            core::hint::spin_loop();
        };
        if val & P2M_ERROR_SET != 0 {
            self.bus_reset(lane);
            return Err(Cx0Error::PhyError);
        }
        if val & P2M_COMMAND_MASK != expect {
            self.bus_reset(lane);
            return Err(Cx0Error::ProtocolMismatch);
        }
        Ok(val)
    }

    fn write_once(&self, lane: u32, addr: u16, data: u8, committed: bool) -> Result<(), Cx0Error> {
        let ctl = self.m2p_ctl(lane);
        if !wait_for(
            self.mmio,
            ctl,
            M2P_TRANSACTION_PENDING,
            false,
            MSGBUS_TIMEOUT_NS,
        ) {
            self.bus_reset(lane);
            return Err(Cx0Error::Timeout);
        }
        self.clear_response_ready(lane);
        let cmd = if committed {
            M2P_COMMAND_WRITE_COMMITTED
        } else {
            M2P_COMMAND_WRITE_UNCOMMITTED
        };
        self.mmio.write32(
            ctl,
            M2P_TRANSACTION_PENDING
                | cmd
                | ((data as u32) << M2P_DATA_SHIFT)
                | (addr as u32 & 0xFFF),
        );
        compiler_fence(Ordering::SeqCst);
        if !wait_for(
            self.mmio,
            ctl,
            M2P_TRANSACTION_PENDING,
            false,
            MSGBUS_TIMEOUT_NS,
        ) {
            self.bus_reset(lane);
            return Err(Cx0Error::Timeout);
        }
        if committed {
            self.wait_for_ack(lane, P2M_COMMAND_WRITE_ACK)?;
        } else if self.mmio.read32(self.p2m_status(lane)) & P2M_ERROR_SET != 0 {
            self.bus_reset(lane);
            return Err(Cx0Error::PhyError);
        }
        self.clear_response_ready(lane);
        // Pre-Xe3 settle workaround (DISPLAY_VER < 30 covers MTL):
        // reset the bus after every transaction.
        self.bus_reset(lane);
        Ok(())
    }

    fn read_once(&self, lane: u32, addr: u16) -> Result<u8, Cx0Error> {
        let ctl = self.m2p_ctl(lane);
        if !wait_for(
            self.mmio,
            ctl,
            M2P_TRANSACTION_PENDING,
            false,
            MSGBUS_TIMEOUT_NS,
        ) {
            self.bus_reset(lane);
            return Err(Cx0Error::Timeout);
        }
        self.clear_response_ready(lane);
        self.mmio.write32(
            ctl,
            M2P_TRANSACTION_PENDING | M2P_COMMAND_READ | (addr as u32 & 0xFFF),
        );
        compiler_fence(Ordering::SeqCst);
        let val = self.wait_for_ack(lane, P2M_COMMAND_READ_ACK)?;
        self.clear_response_ready(lane);
        self.bus_reset(lane);
        Ok(((val & P2M_DATA_MASK) >> M2P_DATA_SHIFT) as u8)
    }

    /// Write one VDR byte on every lane in `lane_mask`, with the
    /// i915 retry budget (3 attempts per lane).
    pub fn write(
        &self,
        lane_mask: u8,
        addr: u16,
        data: u8,
        committed: bool,
    ) -> Result<(), Cx0Error> {
        for lane in 0..2u32 {
            if lane_mask & (1 << lane) == 0 {
                continue;
            }
            let mut result = Err(Cx0Error::Timeout);
            for _ in 0..MSGBUS_ATTEMPTS {
                result = self.write_once(lane, addr, data, committed);
                if result.is_ok() {
                    break;
                }
            }
            result?;
        }
        Ok(())
    }

    /// Read one VDR byte (from the first lane in `lane_mask` —
    /// PLL state lives on the master lane).
    pub fn read(&self, lane_mask: u8, addr: u16) -> Result<u8, Cx0Error> {
        let lane = lane_mask.trailing_zeros();
        if lane >= 2 {
            return Err(Cx0Error::ProtocolMismatch);
        }
        let mut result = Err(Cx0Error::Timeout);
        for _ in 0..MSGBUS_ATTEMPTS {
            result = self.read_once(lane, addr);
            if result.is_ok() {
                break;
            }
        }
        result
    }

    /// Read-modify-write one VDR byte on every lane in
    /// `lane_mask`; writes only when the value changes (i915
    /// `__intel_cx0_rmw`).
    pub fn rmw(
        &self,
        lane_mask: u8,
        addr: u16,
        clear: u8,
        set: u8,
        committed: bool,
    ) -> Result<(), Cx0Error> {
        for lane in 0..2u32 {
            if lane_mask & (1 << lane) == 0 {
                continue;
            }
            let old = self.read(1 << lane, addr)?;
            let val = (old & !clear) | set;
            if val != old {
                self.write(1 << lane, addr, val, committed)?;
            }
        }
        Ok(())
    }

    /// C20 SRAM write: a 16-bit word at a 16-bit context address,
    /// staged through the VDR address/data window on one lane
    /// (`intel_c20_sram_write`). The data-low byte write is the
    /// committed one — it is what latches the word.
    pub fn sram_write(&self, lane_mask: u8, addr: u16, data: u16) -> Result<(), Cx0Error> {
        self.write(lane_mask, C20_WR_ADDRESS_H, (addr >> 8) as u8, false)?;
        self.write(lane_mask, C20_WR_ADDRESS_L, (addr & 0xFF) as u8, false)?;
        self.write(lane_mask, C20_WR_DATA_H, (data >> 8) as u8, false)?;
        self.write(lane_mask, C20_WR_DATA_L, (data & 0xFF) as u8, true)?;
        Ok(())
    }

    /// Program the message-bus timeout timer on both lanes
    /// (`intel_cx0_program_msgbus_timer`, run at the head of every
    /// PHY transaction batch): timer field = 0xA000.
    pub fn program_msgbus_timer(&self) {
        for lane in 0..2u64 {
            rmw(
                self.mmio,
                self.port.msgbus_timer_ln0() + lane * 4,
                MSGBUS_TIMER_VAL_MASK,
                MSGBUS_TIMER_VAL,
            );
        }
    }

    /// Begin a C10 VDR programming batch: set the message-bus
    /// access bit in `PHY_C10_VDR_CONTROL(1)` on the given lanes.
    /// C20 has no such gate — i915's helper early-returns for
    /// non-C10 PHYs — so this is a no-op on TC ports.
    pub fn msgbus_access_begin(&self, lane_mask: u8) -> Result<(), Cx0Error> {
        if self.port.phy() != PhyKind::C10 {
            return Ok(());
        }
        self.rmw(
            lane_mask,
            C10_VDR_CONTROL_1,
            0,
            C10_VDR_CTRL_MSGBUS_ACCESS,
            true,
        )
    }

    /// Commit a C10 VDR programming batch: set UPDATE_CFG (and
    /// MASTER_LANE for PLL programming) in the control register.
    /// No-op on C20, mirroring `msgbus_access_begin`.
    pub fn msgbus_access_commit(&self, lane_mask: u8, master_lane: bool) -> Result<(), Cx0Error> {
        if self.port.phy() != PhyKind::C10 {
            return Ok(());
        }
        let mut val = C10_VDR_CTRL_UPDATE_CFG;
        if master_lane {
            val |= C10_VDR_CTRL_MASTER_LANE;
        }
        self.rmw(lane_mask, C10_VDR_CONTROL_1, 0, val, true)
    }
}

/// `XELPDP_PORT_MSGBUS_TIMER_VAL` field mask (bits 23:0).
const MSGBUS_TIMER_VAL_MASK: u32 = 0x00FF_FFFF;
/// Timer field value the PRM sequence programs: 0xA000.
const MSGBUS_TIMER_VAL: u32 = 0xA000;

// ── C10/C20 VDR register map ─────────────────────────────────────
//
// From `intel_cx0_phy_regs.h`. VDR addresses are 12-bit PHY-local
// addresses carried in the message-bus transaction, not MMIO
// offsets.

/// `PHY_C10_VDR_PLL(idx)` — C10 PLL byte registers, 0xC00 + idx.
pub const fn c10_vdr_pll(idx: u16) -> u16 {
    0xC00 + idx
}
/// `PHY_C10_VDR_CMN(idx)` — C10 common byte registers, 0xC20 + idx.
pub const fn c10_vdr_cmn(idx: u16) -> u16 {
    0xC20 + idx
}
/// `PHY_C10_VDR_TX(idx)` — C10 TX byte registers, 0xC30 + idx.
pub const fn c10_vdr_tx(idx: u16) -> u16 {
    0xC30 + idx
}
/// `PHY_C10_VDR_CONTROL(1)` — batch control register.
pub const C10_VDR_CONTROL_1: u16 = 0xC70;
/// `C10_VDR_CTRL_MSGBUS_ACCESS` (bit 2).
pub const C10_VDR_CTRL_MSGBUS_ACCESS: u8 = 1 << 2;
/// `C10_VDR_CTRL_MASTER_LANE` (bit 1).
pub const C10_VDR_CTRL_MASTER_LANE: u8 = 1 << 1;
/// `C10_VDR_CTRL_UPDATE_CFG` (bit 0).
pub const C10_VDR_CTRL_UPDATE_CFG: u8 = 1;
/// `PHY_C10_VDR_CUSTOM_WIDTH` — 8/10-bit width select; DP 1.4
/// programs `C10_VDR_CUSTOM_WIDTH_8_10` = 0.
pub const C10_VDR_CUSTOM_WIDTH: u16 = 0xD02;
/// `PHY_C10_VDR_OVRD` — TX override enables.
pub const C10_VDR_OVRD: u16 = 0xD71;
/// `PHY_C10_VDR_OVRD_TX1` (bit 0).
pub const C10_VDR_OVRD_TX1: u8 = 1;
/// `PHY_C10_VDR_OVRD_TX2` (bit 2).
pub const C10_VDR_OVRD_TX2: u8 = 1 << 2;
/// `PHY_CX0_VDROVRD_CTL(lane, tx, control)` — per-TX override
/// level registers. The (lane ^ tx) swizzle is the PRM's; the
/// lane's own message bus disambiguates the physical register.
pub const fn cx0_vdrovrd_ctl(lane: u16, tx: u16, control: u16) -> u16 {
    0xD80 + ((lane ^ tx) * 0x10) + control
}
/// `C10_PHY_OVRD_LEVEL` field mask (bits 5:0).
pub const CX0_OVRD_LEVEL_MASK: u8 = 0x3F;
/// `PHY_CX0_TX_CONTROL(tx, control)` — per-TX control registers.
pub const fn cx0_tx_control(tx: u16, control: u16) -> u16 {
    0x400 + (tx - 1) * 0x200 + control
}
/// `CONTROL2_DISABLE_SINGLE_TX` (bit 6).
pub const TX_CONTROL2_DISABLE_SINGLE_TX: u8 = 1 << 6;

/// `PHY_C20_WR_ADDRESS_L/H`, `PHY_C20_WR_DATA_L/H` — the C20
/// SRAM staging window.
pub const C20_WR_ADDRESS_L: u16 = 0xC02;
pub const C20_WR_ADDRESS_H: u16 = 0xC03;
pub const C20_WR_DATA_L: u16 = 0xC04;
pub const C20_WR_DATA_H: u16 = 0xC05;
/// `PHY_C20_VDR_CUSTOM_SERDES_RATE` — protocol/rate byte; also
/// carries the context toggle (bit 0).
pub const C20_VDR_CUSTOM_SERDES_RATE: u16 = 0xD00;
/// `PHY_C20_IS_DP` (bit 6 of the serdes-rate byte).
pub const C20_SERDES_IS_DP: u8 = 1 << 6;
/// `PHY_C20_DP_RATE` field (bits 4:1 of the serdes-rate byte).
pub const C20_SERDES_DP_RATE_MASK: u8 = 0xF << 1;
/// `PHY_C20_CONTEXT_TOGGLE` (bit 0 of the serdes-rate byte).
pub const C20_CONTEXT_TOGGLE: u8 = 1;
/// Serdes-rate byte fields `intel_c20_program_vdr_params` masks:
/// IS_DP | DP_RATE | IS_HDMI_FRL.
pub const C20_SERDES_RATE_MASK: u8 = 0xDE;
/// `PHY_C20_VDR_CUSTOM_WIDTH` (0xD02, shared address with C10);
/// DP 1.4 width = 0 (8/10-bit), DP 2.0 = 2.
pub const C20_VDR_CUSTOM_WIDTH: u16 = 0xD02;
/// `PHY_C20_CUSTOM_WIDTH` field mask (bits 1:0).
pub const C20_CUSTOM_WIDTH_MASK: u8 = 0x3;

// ── PLL state tables ─────────────────────────────────────────────
//
// Transcribed from `intel_cx0_phy.c` (MTL tables, 38.4 MHz
// reference, SSC enabled — in non-SSC form PLL bytes 4..8 would
// be zeroed; the tables below are the SSC form i915 ships and
// the PORT_CLOCK_CTL SSC bit programmed alongside them matches).

/// C10 PLL state: one TX byte, one CMN byte, twenty PLL bytes
/// written to VDR addresses 0xC30 / 0xC20 / 0xC00..0xC13.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct C10PllState {
    /// `pll_state->tx` — VDR TX(0).
    pub tx: u8,
    /// `pll_state->cmn` — VDR CMN(0).
    pub cmn: u8,
    /// `pll_state->pll[0..20]` — VDR PLL(0..20).
    pub pll: [u8; 20],
}

/// C20 PLL state: 16-bit SRAM context words — TX(3), CMN(4),
/// MPLLB(11). DP 1.4 always uses MPLLB on C20 (UHBR 10G/20G use
/// MPLLA and are out of scope).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct C20PllState {
    /// TX context words.
    pub tx: [u16; 3],
    /// Common context words.
    pub cmn: [u16; 4],
    /// MPLLB context words.
    pub mpllb: [u16; 11],
}

/// Port clock (kHz) for a DP link rate — the PLL tables are keyed
/// by it. `None` for the HDMI rates the shared enum carries.
pub const fn dp_port_clock_khz(rate: LinkRate) -> Option<u32> {
    match rate {
        LinkRate::DpRbr => Some(162_000),
        LinkRate::DpHbr => Some(270_000),
        LinkRate::DpHbr2 => Some(540_000),
        LinkRate::DpHbr3 => Some(810_000),
        LinkRate::Hdmi594 | LinkRate::Hdmi297 => None,
    }
}

/// C20 serdes-rate index for a DP port clock
/// (`intel_c20_get_dp_rate`, DP 1.4 range).
fn c20_dp_rate_index(port_clock_khz: u32) -> Option<u8> {
    match port_clock_khz {
        162_000 => Some(0),
        270_000 => Some(1),
        540_000 => Some(2),
        810_000 => Some(3),
        _ => None,
    }
}

const C10_DP_RBR: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0xB4, 0x00, 0x30, 0x01, 0x26, 0x0C, 0x98, 0x46, 0x01, 0x01, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x02, 0x84, 0x4F, 0xE5, 0x23,
    ],
};
const C10_EDP_R216: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0x04, 0x00, 0xA2, 0x01, 0x33, 0x10, 0x75, 0xB3, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x85, 0x0F, 0xE6, 0x23,
    ],
};
const C10_EDP_R243: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0x34, 0x00, 0xDA, 0x01, 0x39, 0x12, 0xE3, 0xE9, 0x01, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00,
        0x02, 0x85, 0x8F, 0xE6, 0x23,
    ],
};
const C10_DP_HBR: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0xF4, 0x00, 0xF8, 0x00, 0x20, 0x0A, 0x29, 0x10, 0x01, 0x01, 0x00, 0x00, 0xA0, 0x00, 0x00,
        0x01, 0x84, 0x4F, 0xE5, 0x23,
    ],
};
const C10_EDP_R324: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0xB4, 0x00, 0x30, 0x01, 0x26, 0x0C, 0x98, 0x46, 0x01, 0x01, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x01, 0x85, 0x4F, 0xE6, 0x23,
    ],
};
const C10_EDP_R432: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0x04, 0x00, 0xA2, 0x01, 0x33, 0x10, 0x75, 0xB3, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x85, 0x0F, 0xE6, 0x23,
    ],
};
const C10_DP_HBR2: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0xF4, 0x00, 0xF8, 0x00, 0x20, 0x0A, 0x29, 0x10, 0x01, 0x01, 0x00, 0x00, 0xA0, 0x00, 0x00,
        0x00, 0x84, 0x4F, 0xE5, 0x23,
    ],
};
const C10_EDP_R675: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0xB4, 0x00, 0x3E, 0x01, 0xA8, 0x0C, 0x33, 0x54, 0x01, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00,
        0x00, 0x85, 0x8F, 0xE6, 0x23,
    ],
};
const C10_DP_HBR3: C10PllState = C10PllState {
    tx: 0x10,
    cmn: 0x21,
    pll: [
        0x34, 0x00, 0x84, 0x01, 0x30, 0x0F, 0x3D, 0x98, 0x01, 0x01, 0x00, 0x00, 0xF0, 0x00, 0x00,
        0x00, 0x84, 0x0F, 0xE5, 0x23,
    ],
};

/// Resolve the C10 PLL state for a DP port clock. `edp` selects
/// the eDP table, which adds the intermediate panel rates
/// (216/243/324/432/675 MHz); the four DP rates exist in both.
pub fn c10_pll_state(port_clock_khz: u32, edp: bool) -> Option<&'static C10PllState> {
    match port_clock_khz {
        162_000 => Some(&C10_DP_RBR),
        270_000 => Some(&C10_DP_HBR),
        540_000 => Some(&C10_DP_HBR2),
        810_000 => Some(&C10_DP_HBR3),
        216_000 if edp => Some(&C10_EDP_R216),
        243_000 if edp => Some(&C10_EDP_R243),
        324_000 if edp => Some(&C10_EDP_R324),
        432_000 if edp => Some(&C10_EDP_R432),
        675_000 if edp => Some(&C10_EDP_R675),
        _ => None,
    }
}

const C20_CMN_DP14: [u16; 4] = [0x0500, 0x0005, 0x0000, 0x0000];
const C20_DP_RBR: C20PllState = C20PllState {
    tx: [0xBE88, 0x5800, 0x0000],
    cmn: C20_CMN_DP14,
    mpllb: [
        0x50A8, 0x2120, 0xCD9A, 0xBFC1, 0x5AB8, 0x4C34, 0x2000, 0x0001, 0x6000, 0x0000, 0x0000,
    ],
};
const C20_DP_HBR: C20PllState = C20PllState {
    tx: [0xBE88, 0x4800, 0x0000],
    cmn: C20_CMN_DP14,
    mpllb: [
        0x308C, 0x2110, 0xCC9C, 0xBFC1, 0x4B9A, 0x3F81, 0x2000, 0x0001, 0x5000, 0x0000, 0x0000,
    ],
};
const C20_DP_HBR2: C20PllState = C20PllState {
    tx: [0xBE88, 0x4800, 0x0000],
    cmn: C20_CMN_DP14,
    mpllb: [
        0x108C, 0x2108, 0xCC9C, 0xBFC1, 0x4B9A, 0x3F81, 0x2000, 0x0001, 0x5000, 0x0000, 0x0000,
    ],
};
const C20_DP_HBR3: C20PllState = C20PllState {
    tx: [0xBE88, 0x4800, 0x0000],
    cmn: C20_CMN_DP14,
    mpllb: [
        0x10D2, 0x2108, 0x8D98, 0xBFC1, 0x7166, 0x5F42, 0x2000, 0x0001, 0x7800, 0x0000, 0x0000,
    ],
};

/// Resolve the C20 PLL state for a DP 1.4 port clock.
pub fn c20_pll_state(port_clock_khz: u32) -> Option<&'static C20PllState> {
    match port_clock_khz {
        162_000 => Some(&C20_DP_RBR),
        270_000 => Some(&C20_DP_HBR),
        540_000 => Some(&C20_DP_HBR2),
        810_000 => Some(&C20_DP_HBR3),
        _ => None,
    }
}

// ── C20 SRAM context addresses ───────────────────────────────────
//
// `PHY_C20_{A,B}_{TX,CMN,MPLLB}_CNTX_CFG(idx)` — MTL values from
// `intel_cx0_phy_regs.h`; each context block counts *down* from
// its base as idx grows.

const C20_A_TX_CNTX_CFG: u16 = 0xCF2E;
const C20_B_TX_CNTX_CFG: u16 = 0xCF2A;
const C20_A_CMN_CNTX_CFG: u16 = 0xCDAA;
const C20_B_CMN_CNTX_CFG: u16 = 0xCDA5;
const C20_A_MPLLB_CNTX_CFG: u16 = 0xCB5A;
const C20_B_MPLLB_CNTX_CFG: u16 = 0xCB4E;

// ── PLL programming ──────────────────────────────────────────────

/// Program a C10 PLL state (`intel_c10_pll_program`): batch-open
/// on both lanes, the twenty PLL bytes on the master lane only
/// (committed every fourth byte, per the VDR programming
/// sequence), CMN + TX bytes, custom width 8/10 on both lanes,
/// batch-commit as master.
fn c10_pll_program<M: MmioWindow + ?Sized>(
    phy: &Cx0Phy<'_, M>,
    state: &C10PllState,
) -> Result<(), Cx0Error> {
    phy.msgbus_access_begin(BOTH_LANES)?;
    for (i, byte) in state.pll.iter().enumerate() {
        phy.write(LANE0, c10_vdr_pll(i as u16), *byte, i % 4 == 0)?;
    }
    phy.write(LANE0, c10_vdr_cmn(0), state.cmn, true)?;
    phy.write(LANE0, c10_vdr_tx(0), state.tx, true)?;
    phy.rmw(BOTH_LANES, C10_VDR_CUSTOM_WIDTH, 0x3, 0, true)?;
    phy.msgbus_access_commit(LANE0, true)?;
    Ok(())
}

/// Program a C20 PLL state (`intel_c20_pll_program`): read the
/// live context selection, write TX/CMN/MPLLB words into the
/// *inactive* context's SRAM, program the VDR rate parameters,
/// then toggle the context bit to make the new state live.
///
/// The HDMI↔DP protocol-switch SRAM invalidation in i915's step
/// 2 does not apply: this lane only ever programs DP states.
fn c20_pll_program<M: MmioWindow + ?Sized>(
    phy: &Cx0Phy<'_, M>,
    state: &C20PllState,
    port_clock_khz: u32,
) -> Result<(), Cx0Error> {
    let rate_idx = c20_dp_rate_index(port_clock_khz).ok_or(Cx0Error::UnsupportedRate)?;
    // Step 1: current context selection (toggle bit of the
    // serdes-rate byte, read on lane 0).
    let serdes = phy.read(LANE0, C20_VDR_CUSTOM_SERDES_RATE)?;
    let cntx = serdes & C20_CONTEXT_TOGGLE != 0;
    // Step 3: write the context the toggle bit does *not*
    // currently select (i915 writes context A when the bit reads
    // set, context B when it reads clear), then flip the bit in
    // step 7 to make the freshly written context live.
    let (tx_base, cmn_base, mpllb_base) = if cntx {
        (C20_A_TX_CNTX_CFG, C20_A_CMN_CNTX_CFG, C20_A_MPLLB_CNTX_CFG)
    } else {
        (C20_B_TX_CNTX_CFG, C20_B_CMN_CNTX_CFG, C20_B_MPLLB_CNTX_CFG)
    };
    for (i, word) in state.tx.iter().enumerate() {
        phy.sram_write(LANE0, tx_base - i as u16, *word)?;
    }
    for (i, word) in state.cmn.iter().enumerate() {
        phy.sram_write(LANE0, cmn_base - i as u16, *word)?;
    }
    for (i, word) in state.mpllb.iter().enumerate() {
        phy.sram_write(LANE0, mpllb_base - i as u16, *word)?;
    }
    // Steps 4-6: VDR parameters — custom width 0 (DP 1.4) and the
    // serdes rate byte (IS_DP | rate index), both lanes.
    phy.rmw(
        BOTH_LANES,
        C20_VDR_CUSTOM_WIDTH,
        C20_CUSTOM_WIDTH_MASK,
        0,
        true,
    )?;
    phy.rmw(
        BOTH_LANES,
        C20_VDR_CUSTOM_SERDES_RATE,
        C20_SERDES_RATE_MASK,
        C20_SERDES_IS_DP | (rate_idx << 1),
        true,
    )?;
    // Step 7: toggle the context selection to load the new state.
    phy.rmw(
        BOTH_LANES,
        C20_VDR_CUSTOM_SERDES_RATE,
        C20_CONTEXT_TOGGLE,
        if cntx { 0 } else { C20_CONTEXT_TOGGLE },
        true,
    )?;
    Ok(())
}

/// Change the PHY powerdown state (`intel_cx0_powerdown_change_
/// sequence`): stage the new state for the lanes in `lane_mask`,
/// wait for the message bus to drain, raise the update bits, and
/// wait for the hardware to consume them.
fn powerdown_change<M: MmioWindow + ?Sized>(
    mmio: &M,
    port: XeLpgPort,
    lane_mask: u8,
    state: u32,
) -> Result<(), Cx0Error> {
    let buf_ctl2 = port.buf_ctl2();
    let mut set = 0u32;
    let mut update = 0u32;
    for lane in 0..2u32 {
        if lane_mask & (1 << lane) != 0 {
            set |= lane_powerdown_new_state(lane, state);
            update |= lane_powerdown_update(lane);
        }
    }
    rmw(mmio, buf_ctl2, POWERDOWN_NEW_STATE_MASK_BOTH, set);
    for lane in 0..2u32 {
        if lane_mask & (1 << lane) != 0
            && !wait_for(
                mmio,
                port.msgbus_ctl_ln0() + (lane as u64) * 4,
                M2P_TRANSACTION_PENDING,
                false,
                MSGBUS_TIMEOUT_NS,
            )
        {
            return Err(Cx0Error::Timeout);
        }
    }
    rmw(mmio, buf_ctl2, update, update);
    if !wait_for(
        mmio,
        buf_ctl2,
        update,
        false,
        XELPDP_PORT_POWERDOWN_UPDATE_TIMEOUT_NS,
    ) {
        return Err(Cx0Error::Timeout);
    }
    Ok(())
}

/// `XELPDP_PORT_POWERDOWN_UPDATE_TIMEOUT_MS` = 2 ms.
const XELPDP_PORT_POWERDOWN_UPDATE_TIMEOUT_NS: u64 = 2_000_000;
/// `XELPDP_PCLK_PLL_ENABLE_TIMEOUT_US` = 3200 µs.
const PCLK_PLL_ENABLE_TIMEOUT_NS: u64 = 3_200_000;
/// `XELPDP_PORT_BUF_SOC_READY_TIMEOUT_US` = 100 µs.
const SOC_READY_TIMEOUT_NS: u64 = 100_000;
/// `XELPDP_PORT_RESET_START_TIMEOUT_US` = 10 µs.
const RESET_START_TIMEOUT_NS: u64 = 10_000;
/// `XELPDP_PORT_RESET_END_TIMEOUT_MS` = 15 ms.
const RESET_END_TIMEOUT_NS: u64 = 15_000_000;
/// `XELPDP_REFCLK_ENABLE_TIMEOUT_US` = 10 µs.
const REFCLK_TIMEOUT_NS: u64 = 10_000;

/// Bring the PHY lanes out of reset (`intel_cx0_phy_lane_reset`,
/// no lane reversal): wait for SoC PHY ready, assert the lane
/// pipe resets, request refclk on lane 0, run the reset-grade
/// powerdown transition, set up the steady-state power fields,
/// and release the resets.
fn phy_lane_reset<M: MmioWindow + ?Sized>(mmio: &M, port: XeLpgPort) -> Result<(), Cx0Error> {
    let buf_ctl1 = port.buf_ctl1();
    let buf_ctl2 = port.buf_ctl2();
    let resets = lane_pipe_reset(0) | lane_pipe_reset(1);
    let status = lane_phy_current_status(0) | lane_phy_current_status(1);
    if !wait_for(
        mmio,
        buf_ctl1,
        PORT_BUF_SOC_PHY_READY,
        true,
        SOC_READY_TIMEOUT_NS,
    ) {
        return Err(Cx0Error::Timeout);
    }
    rmw(mmio, buf_ctl2, resets, resets);
    if !wait_for(mmio, buf_ctl2, status, true, RESET_START_TIMEOUT_NS) {
        return Err(Cx0Error::Timeout);
    }
    let clock_ctl = port.port_clock_ctl();
    let refclk_req_both = lane_pclk_refclk_request(0) | lane_pclk_refclk_request(1);
    rmw(
        mmio,
        clock_ctl,
        refclk_req_both,
        lane_pclk_refclk_request(0),
    );
    if !wait_for(
        mmio,
        clock_ctl,
        lane_pclk_refclk_ack(0),
        true,
        REFCLK_TIMEOUT_NS,
    ) {
        return Err(Cx0Error::Timeout);
    }
    powerdown_change(mmio, port, BOTH_LANES, P2_STATE_RESET)?;
    // `intel_cx0_setup_powerdown`: ready state P2 in BUF_CTL2,
    // active state P0 + zero lane staggering in BUF_CTL3.
    rmw(mmio, buf_ctl2, POWER_STATE_READY_MASK, P2_STATE_READY << 4);
    rmw(
        mmio,
        port.buf_ctl3(),
        POWER_STATE_ACTIVE_MASK | PLL_LANE_STAGGERING_DELAY_MASK,
        P0_STATE_ACTIVE,
    );
    rmw(mmio, buf_ctl2, resets, 0);
    if !wait_for(mmio, buf_ctl2, status, false, RESET_END_TIMEOUT_NS) {
        return Err(Cx0Error::Timeout);
    }
    Ok(())
}

/// Program the enabled/disabled state of the four TXes from the
/// active lane count (`intel_cx0_program_phy_lane`, non-reversed,
/// non-DP-alt): TXes past `lane_count` are disabled via
/// `PHY_CX0_TX_CONTROL(tx, 2)`.
fn program_phy_lane<M: MmioWindow + ?Sized>(
    phy: &Cx0Phy<'_, M>,
    lane_count: u8,
) -> Result<(), Cx0Error> {
    // GENMASK8(3, 0) << lane_count, per-TX bit i.
    let disables: u8 = 0x0F << lane_count;
    phy.msgbus_access_begin(BOTH_LANES)?;
    for i in 0..4u16 {
        let tx = i % 2 + 1;
        let lane_mask = if i < 2 { LANE0 } else { LANE1 };
        let set = if disables & (1 << i) != 0 {
            TX_CONTROL2_DISABLE_SINGLE_TX
        } else {
            0
        };
        phy.rmw(
            lane_mask,
            cx0_tx_control(tx, 2),
            TX_CONTROL2_DISABLE_SINGLE_TX,
            set,
            true,
        )?;
    }
    phy.msgbus_access_commit(BOTH_LANES, false)?;
    Ok(())
}

/// Set (or clear) the PCLK PLL request for lane 0 — the maxPCLK
/// lane in the non-reversed wiring — and, when setting, poll its
/// ACK (`intel_cx0pll_enable` steps 9-10).
fn set_pclk_pll_request<M: MmioWindow + ?Sized>(
    mmio: &M,
    port: XeLpgPort,
    on: bool,
) -> Result<(), Cx0Error> {
    let clock_ctl = port.port_clock_ctl();
    let req_both = lane_pclk_pll_request(0) | lane_pclk_pll_request(1);
    if on {
        rmw(mmio, clock_ctl, req_both, lane_pclk_pll_request(0));
        if !wait_for(
            mmio,
            clock_ctl,
            lane_pclk_pll_ack(0),
            true,
            PCLK_PLL_ENABLE_TIMEOUT_NS,
        ) {
            return Err(Cx0Error::Timeout);
        }
    } else {
        rmw(mmio, clock_ctl, req_both, 0);
        if !wait_for(
            mmio,
            clock_ctl,
            lane_pclk_pll_ack(0),
            false,
            PCLK_PLL_ENABLE_TIMEOUT_NS,
        ) {
            return Err(Cx0Error::Timeout);
        }
    }
    Ok(())
}

/// Enable the port PLL for a DP rate — the full
/// `intel_cx0pll_enable` sequence:
///
/// 1. Program PORT_CLOCK_CTL muxes/gating/SSC (and clear the
///    BUF_CTL1 reversal bit — no lane reversal).
/// 2. Bring the PHY out of reset.
/// 3. Powerdown state → P2 (ready).
/// 4. Program the message-bus timer (transaction head).
/// 5. Program the PLL state (C10 bytes / C20 SRAM context).
/// 6. Program the per-TX lane enables for `lane_count`.
/// 7. Write DDI_CLK_VALFREQ on combo ports (symbol clock = port
///    clock for DP 8b/10b).
/// 8. Raise the PCLK PLL request on lane 0 and poll its ACK.
///
/// DVFS voltage switching around the frequency change (steps
/// 7/11 in i915) is handled by the CDCLK path in the modeset
/// module, as it is in i915 (`bxt_set_cdclk`).
pub fn enable_port_pll<M: MmioWindow + ?Sized>(
    mmio: &M,
    port: XeLpgPort,
    rate: LinkRate,
    lane_count: u8,
) -> Result<(), Cx0Error> {
    let port_clock_khz = dp_port_clock_khz(rate).ok_or(Cx0Error::UnsupportedRate)?;
    let phy = Cx0Phy::new(mmio, port);
    // 1. Port clock control: forward-clock ungate + maxPCLK clock
    //    select + SSC on PLLB (the MPLLB tables are SSC tables).
    rmw(mmio, port.buf_ctl1(), PORT_BUF_REVERSAL, 0);
    rmw(
        mmio,
        port.port_clock_ctl(),
        LANE1_PHY_CLOCK_SELECT
            | FORWARD_CLOCK_UNGATE
            | DDI_CLOCK_SELECT_MASK
            | SSC_ENABLE_PLLA
            | SSC_ENABLE_PLLB,
        FORWARD_CLOCK_UNGATE | DDI_CLOCK_SELECT_MAXPCLK | SSC_ENABLE_PLLB,
    );
    // 2-3. Lane reset, then power state ready.
    phy_lane_reset(mmio, port)?;
    powerdown_change(mmio, port, BOTH_LANES, P2_STATE_READY)?;
    // 4-6. Timer, PLL state, TX enables.
    phy.program_msgbus_timer();
    program_pll_state(&phy, port_clock_khz)?;
    program_phy_lane(&phy, lane_count)?;
    // 7. DDI_CLK_VALFREQ (combo ports only).
    if let Some(off) = port.clk_valfreq() {
        mmio.write32(off, port_clock_khz);
        compiler_fence(Ordering::SeqCst);
    }
    // 8. PLL request + ACK poll.
    set_pclk_pll_request(mmio, port, true)?;
    Ok(())
}

/// Program just the PLL state for `rate` (step 5 of the enable
/// sequence), dispatching on the port's PHY kind.
fn program_pll_state<M: MmioWindow + ?Sized>(
    phy: &Cx0Phy<'_, M>,
    port_clock_khz: u32,
) -> Result<(), Cx0Error> {
    match phy.port.phy() {
        PhyKind::C10 => {
            let state = c10_pll_state(port_clock_khz, phy.port.is_edp())
                .ok_or(Cx0Error::UnsupportedRate)?;
            c10_pll_program(phy, state)
        }
        PhyKind::C20 => {
            let state = c20_pll_state(port_clock_khz).ok_or(Cx0Error::UnsupportedRate)?;
            c20_pll_program(phy, state, port_clock_khz)
        }
    }
}

/// Re-program the port PLL for a new rate after link training
/// settled below the rate the PLL was first enabled at: drop the
/// PCLK request, swap the PLL state, raise the request again.
/// The PHY lanes stay in the P2-ready state throughout (the
/// link-retrain shape, not a fresh enable).
pub fn reprogram_pll_rate<M: MmioWindow + ?Sized>(
    mmio: &M,
    port: XeLpgPort,
    rate: LinkRate,
) -> Result<(), Cx0Error> {
    let port_clock_khz = dp_port_clock_khz(rate).ok_or(Cx0Error::UnsupportedRate)?;
    let phy = Cx0Phy::new(mmio, port);
    set_pclk_pll_request(mmio, port, false)?;
    phy.program_msgbus_timer();
    program_pll_state(&phy, port_clock_khz)?;
    if let Some(off) = port.clk_valfreq() {
        mmio.write32(off, port_clock_khz);
        compiler_fence(Ordering::SeqCst);
    }
    set_pclk_pll_request(mmio, port, true)?;
    Ok(())
}

/// Disable the port PLL (drop the PCLK PLL request and wait for
/// the ACK to clear). Used by the modeset's pipeline-disable
/// step; the PHY power state is left for the next enable.
pub fn disable_port_pll<M: MmioWindow + ?Sized>(mmio: &M, port: XeLpgPort) -> Result<(), Cx0Error> {
    set_pclk_pll_request(mmio, port, false)
}

// ── TX translation tables + signal levels ────────────────────────
//
// The MTL DP 1.4 swing tables from `intel_ddi_buf_trans.c`
// (`mtl_c10_trans_dp14` / `mtl_c20_trans_dp14`). Entries are the
// SNPS PHY triple `{ vswing, pre_cursor, post_cursor }` in the
// DP preset order: index = preset for (swing, pre-emphasis)
// (0,0) (0,1) (0,2) (0,3) (1,0) (1,1) (1,2) (2,0) (2,1) (3,0).

/// One SNPS translation-table entry (raw PHY level codes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnpsTrans {
    /// Voltage swing level code.
    pub vswing: u8,
    /// Pre-cursor (pre-emphasis) level code.
    pub pre_cursor: u8,
    /// Post-cursor level code.
    pub post_cursor: u8,
}

const fn snps(vswing: u8, pre_cursor: u8, post_cursor: u8) -> SnpsTrans {
    SnpsTrans {
        vswing,
        pre_cursor,
        post_cursor,
    }
}

/// C10 DP 1.4 translation table (10 presets).
pub const C10_TRANS_DP14: [SnpsTrans; 10] = [
    snps(26, 0, 0),
    snps(33, 0, 6),
    snps(38, 0, 11),
    snps(43, 0, 19),
    snps(39, 0, 0),
    snps(45, 0, 7),
    snps(46, 0, 13),
    snps(46, 0, 0),
    snps(55, 0, 7),
    snps(62, 0, 0),
];

/// C20 DP 1.4 translation table (10 presets).
pub const C20_TRANS_DP14: [SnpsTrans; 10] = [
    snps(20, 0, 0),
    snps(24, 0, 4),
    snps(30, 0, 9),
    snps(34, 0, 14),
    snps(29, 0, 0),
    snps(34, 0, 5),
    snps(38, 0, 10),
    snps(36, 0, 0),
    snps(40, 0, 6),
    snps(48, 0, 0),
];

/// The translation table for a PHY kind.
pub const fn trans_table(phy: PhyKind) -> &'static [SnpsTrans; 10] {
    match phy {
        PhyKind::C10 => &C10_TRANS_DP14,
        PhyKind::C20 => &C20_TRANS_DP14,
    }
}

/// Map a (voltage swing, pre-emphasis) pair to its DP preset
/// index in the translation tables. Combinations the DP spec
/// does not define (swing + pre-emphasis > 3) clamp to the
/// maximum-drive preset.
pub const fn preset_index(swing: u8, pre_emph: u8) -> usize {
    match (swing, pre_emph) {
        (0, 0) => 0,
        (0, 1) => 1,
        (0, 2) => 2,
        (0, 3) => 3,
        (1, 0) => 4,
        (1, 1) => 5,
        (1, 2) => 6,
        (2, 0) => 7,
        (2, 1) => 8,
        (3, 0) => 9,
        _ => 9,
    }
}

/// `C10_CMN3_TXVBOOST` field (VDR CMN(3) bits 7:5).
const C10_CMN3_TXVBOOST_MASK: u8 = 0x7 << 5;
/// `C10_TX1_TERMCTL` field (VDR TX(1) bits 7:5).
const C10_TX1_TERMCTL_MASK: u8 = 0x7 << 5;

/// Program the TX signal levels for all active lanes
/// (`intel_cx0_phy_set_signal_levels`): on C10, first stage the
/// TX boost / termination bytes for the rate; then write each
/// main-link lane's preset (pre-cursor, swing, post-cursor) into
/// its VDROVRD registers and enable the overrides.
///
/// `levels` carries one (swing, pre-emphasis) pair per main-link
/// lane — the initial all-zero drive at training start, or the
/// levels link training converged on.
pub fn set_signal_levels<M: MmioWindow + ?Sized>(
    phy: &Cx0Phy<'_, M>,
    rate: LinkRate,
    lane_count: u8,
    levels: &[(u8, u8); 4],
) -> Result<(), Cx0Error> {
    let port_clock_khz = dp_port_clock_khz(rate).ok_or(Cx0Error::UnsupportedRate)?;
    let table = trans_table(phy.port.phy());
    phy.program_msgbus_timer();
    phy.msgbus_access_begin(BOTH_LANES)?;
    if phy.port.phy() == PhyKind::C10 {
        // `intel_c10_get_tx_vboost_lvl` / `..._term_ctl`, DP
        // branch: external (non-eDP) HBR2/HBR3 links get the
        // hotter settings.
        let hot = !phy.port.is_edp() && matches!(port_clock_khz, 540_000 | 810_000);
        let vboost: u8 = if hot { 5 } else { 4 };
        let term_ctl: u8 = if hot { 5 } else { 2 };
        phy.rmw(
            BOTH_LANES,
            c10_vdr_cmn(3),
            C10_CMN3_TXVBOOST_MASK,
            vboost << 5,
            false,
        )?;
        phy.rmw(
            BOTH_LANES,
            c10_vdr_tx(1),
            C10_TX1_TERMCTL_MASK,
            term_ctl << 5,
            true,
        )?;
    }
    for ln in 0..lane_count {
        let (swing, pre_emph) = levels[ln as usize];
        let entry = table[preset_index(swing, pre_emph)];
        let lane = (ln / 2) as u16;
        let tx = (ln % 2) as u16;
        let lane_mask = 1u8 << lane;
        phy.rmw(
            lane_mask,
            cx0_vdrovrd_ctl(lane, tx, 0),
            CX0_OVRD_LEVEL_MASK,
            entry.pre_cursor,
            true,
        )?;
        phy.rmw(
            lane_mask,
            cx0_vdrovrd_ctl(lane, tx, 1),
            CX0_OVRD_LEVEL_MASK,
            entry.vswing,
            true,
        )?;
        phy.rmw(
            lane_mask,
            cx0_vdrovrd_ctl(lane, tx, 2),
            CX0_OVRD_LEVEL_MASK,
            entry.post_cursor,
            true,
        )?;
    }
    phy.rmw(
        BOTH_LANES,
        C10_VDR_OVRD,
        0,
        C10_VDR_OVRD_TX1 | C10_VDR_OVRD_TX2,
        true,
    )?;
    phy.msgbus_access_commit(BOTH_LANES, false)?;
    Ok(())
}

// ── D2D link + port buffer configuration ─────────────────────────

/// Enable the die-to-die link for this port and wait for it to
/// report up (`mtl_ddi_enable_d2d`, 100 µs budget). Every MTL
/// port needs it — the display engine and the PHYs sit on
/// different tiles.
pub fn enable_d2d<M: MmioWindow + ?Sized>(mmio: &M, port: XeLpgPort) -> Result<(), Cx0Error> {
    rmw(mmio, port.buf_ctl1(), 0, PORT_BUF_D2D_LINK_ENABLE);
    if !wait_for(
        mmio,
        port.buf_ctl1(),
        PORT_BUF_D2D_LINK_STATE,
        true,
        SOC_READY_TIMEOUT_NS,
    ) {
        return Err(Cx0Error::Timeout);
    }
    Ok(())
}

/// Program PORT_BUF_CTL1's lane-count and data-width fields
/// (`mtl_port_buf_ctl_program`): `lane_count` main-link lanes,
/// 10-bit port data width (DP 1.4), no reversal.
pub fn program_port_buf_ctl<M: MmioWindow + ?Sized>(mmio: &M, port: XeLpgPort, lane_count: u8) {
    rmw(
        mmio,
        port.buf_ctl1(),
        PORT_WIDTH_MASK | PORT_BUF_PORT_DATA_WIDTH_MASK,
        port_width(lane_count),
    );
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the Xe-LPG PHY layer. `FakePhy` models the
    //! message bus faithfully (transaction framing, ACK command
    //! types, the VDR byte file, the C20 SRAM window) and the
    //! handful of direct-MMIO status mirrors the sequences poll,
    //! so a wrong offset, a wrong command encoding, or a
    //! wrong-generation ACK all fail the fixture.

    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Failure injection for the ACK path.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum Fail {
        None,
        /// ACKs carry P2M_ERROR_SET.
        ErrorBit,
        /// Writes are answered with a READ ack (wrong generation
        /// answering the bus).
        WrongAck,
    }

    #[derive(Debug)]
    pub struct FakePhy {
        pub port: XeLpgPort,
        pub writes: RefCell<Vec<(u64, u32)>>,
        regs: RefCell<Vec<(u64, u32)>>,
        vdr: RefCell<Vec<(u8, u16, u8)>>,
        sram: RefCell<Vec<(u16, u16)>>,
        p2m: RefCell<[u32; 2]>,
        fail: Cell<u8>,
        /// When set, PORT_CLOCK_CTL reads never mirror ACKs.
        pub no_clock_ack: Cell<bool>,
    }

    impl FakePhy {
        pub fn new(port: XeLpgPort) -> Self {
            Self {
                port,
                writes: RefCell::new(Vec::new()),
                regs: RefCell::new(Vec::new()),
                vdr: RefCell::new(Vec::new()),
                sram: RefCell::new(Vec::new()),
                p2m: RefCell::new([0; 2]),
                fail: Cell::new(0),
                no_clock_ack: Cell::new(false),
            }
        }
        pub fn set_fail(&self, f: Fail) {
            self.fail.set(match f {
                Fail::None => 0,
                Fail::ErrorBit => 1,
                Fail::WrongAck => 2,
            });
        }
        fn stored(&self, off: u64) -> u32 {
            let mut v = 0;
            for (o, val) in self.regs.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
        }
        fn store(&self, off: u64, val: u32) {
            let mut regs = self.regs.borrow_mut();
            for e in regs.iter_mut() {
                if e.0 == off {
                    e.1 = val;
                    return;
                }
            }
            regs.push((off, val));
        }
        pub fn vdr_get(&self, lane: u8, addr: u16) -> u8 {
            for (l, a, v) in self.vdr.borrow().iter() {
                if *l == lane && *a == addr {
                    return *v;
                }
            }
            0
        }
        fn vdr_set(&self, lane: u8, addr: u16, val: u8) {
            let mut vdr = self.vdr.borrow_mut();
            for e in vdr.iter_mut() {
                if e.0 == lane && e.1 == addr {
                    e.2 = val;
                    return;
                }
            }
            vdr.push((lane, addr, val));
        }
        pub fn sram_get(&self, addr: u16) -> u16 {
            for (a, v) in self.sram.borrow().iter() {
                if *a == addr {
                    return *v;
                }
            }
            0
        }
        fn sram_set(&self, addr: u16, val: u16) {
            let mut sram = self.sram.borrow_mut();
            for e in sram.iter_mut() {
                if e.0 == addr {
                    e.1 = val;
                    return;
                }
            }
            sram.push((addr, val));
        }
        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
        /// All message-bus transactions issued on `lane`, decoded
        /// as (command, address, data) from the M2P ctl writes.
        pub fn msgbus_txns(&self, lane: u32) -> Vec<(u32, u16, u8)> {
            let ctl = self.port.msgbus_ctl_ln0() + (lane as u64) * 4;
            self.writes_to(ctl)
                .into_iter()
                .filter(|w| w & M2P_TRANSACTION_PENDING != 0)
                .map(|w| {
                    (
                        (w & P2M_COMMAND_MASK) >> M2P_COMMAND_SHIFT,
                        (w & 0xFFF) as u16,
                        ((w & P2M_DATA_MASK) >> M2P_DATA_SHIFT) as u8,
                    )
                })
                .collect()
        }
    }

    impl MmioWindow for FakePhy {
        fn read32(&self, off: u64) -> u32 {
            let ln0 = self.port.msgbus_ctl_ln0();
            for lane in 0..2u64 {
                if off == ln0 + lane * 4 {
                    return 0; // pending/reset always read clear
                }
                if off == ln0 + lane * 4 + 8 {
                    return self.p2m.borrow()[lane as usize];
                }
            }
            if off == self.port.port_clock_ctl() {
                let s = self.stored(off);
                // ACK bits mirror their REQUEST bits (bit n-1):
                // refclk requests (bits 29/25) always ACK; the
                // injection switch withholds the PLL ACKs
                // (bits 31/27 → 30/26).
                let mut v = s | ((s & 0x2200_0000) >> 1);
                if !self.no_clock_ack.get() {
                    v |= (s & 0x8800_0000) >> 1;
                }
                return v;
            }
            if off == self.port.buf_ctl1() {
                return self.stored(off) | PORT_BUF_SOC_PHY_READY | PORT_BUF_D2D_LINK_STATE;
            }
            if off == self.port.buf_ctl2() {
                let s = self.stored(off);
                // Powerdown-update bits self-clear; lane PHY status
                // mirrors the pipe-reset bits (>>2).
                return (s & !0x0300_0000) | ((s & 0xC000_0000) >> 2);
            }
            self.stored(off)
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            let ln0 = self.port.msgbus_ctl_ln0();
            for lane in 0..2u64 {
                if off == ln0 + lane * 4 + 8 {
                    // P2M status write: the production clear writes
                    // the flag bits set (W1C) — model as cleared.
                    self.p2m.borrow_mut()[lane as usize] =
                        val & !(P2M_RESPONSE_READY | P2M_ERROR_SET);
                    return;
                }
                if off == ln0 + lane * 4 {
                    if val & M2P_TRANSACTION_RESET != 0 {
                        return;
                    }
                    if val & M2P_TRANSACTION_PENDING == 0 {
                        return;
                    }
                    let cmd = val & P2M_COMMAND_MASK;
                    let addr = (val & 0xFFF) as u16;
                    let data = ((val & P2M_DATA_MASK) >> M2P_DATA_SHIFT) as u8;
                    let fail = self.fail.get();
                    if cmd == M2P_COMMAND_READ {
                        let byte = self.vdr_get(lane as u8, addr);
                        self.p2m.borrow_mut()[lane as usize] = if fail == 1 {
                            P2M_RESPONSE_READY | P2M_ERROR_SET
                        } else {
                            P2M_RESPONSE_READY
                                | P2M_COMMAND_READ_ACK
                                | ((byte as u32) << M2P_DATA_SHIFT)
                        };
                    } else {
                        // Write transaction: apply the byte. The
                        // SRAM staging window only exists on C20
                        // (on C10, 0xC04 is an ordinary PLL byte).
                        if addr == C20_WR_DATA_L && self.port.phy() == PhyKind::C20 {
                            let a = ((self.vdr_get(lane as u8, C20_WR_ADDRESS_H) as u16) << 8)
                                | self.vdr_get(lane as u8, C20_WR_ADDRESS_L) as u16;
                            let d = ((self.vdr_get(lane as u8, C20_WR_DATA_H) as u16) << 8)
                                | data as u16;
                            self.sram_set(a, d);
                        } else {
                            self.vdr_set(lane as u8, addr, data);
                        }
                        if cmd == M2P_COMMAND_WRITE_COMMITTED {
                            self.p2m.borrow_mut()[lane as usize] = if fail == 1 {
                                P2M_RESPONSE_READY | P2M_ERROR_SET
                            } else if fail == 2 {
                                P2M_RESPONSE_READY | P2M_COMMAND_READ_ACK
                            } else {
                                P2M_RESPONSE_READY | P2M_COMMAND_WRITE_ACK
                            };
                        } else if fail == 1 {
                            self.p2m.borrow_mut()[lane as usize] = P2M_ERROR_SET;
                        }
                    }
                    return;
                }
            }
            self.store(off, val);
        }
    }

    fn smoke_port_register_map() -> TestResult {
        let a = XeLpgPort::A;
        if a.buf_ctl1() != 0x6_4004
            || a.msgbus_ctl_ln0() != 0x6_4040
            || a.port_clock_ctl() != 0x6_40E0
        {
            return TestResult::Fail("DDI A port block offsets wrong");
        }
        if a.msgbus_timer_ln0() != 0x6_40D8
            || a.aux_ctl() != 0x6_4010
            || a.clk_valfreq() != Some(0x6_4030)
        {
            return TestResult::Fail("DDI A timer/aux/valfreq offsets wrong");
        }
        let tc = XeLpgPort::Tc1;
        if tc.buf_ctl1() != 0x16_F200
            || tc.msgbus_ctl_ln0() != 0x16_F240
            || tc.port_clock_ctl() != 0x16_F260
        {
            return TestResult::Fail("TC1 port block offsets wrong");
        }
        if tc.msgbus_timer_ln0() != 0x16_F258
            || tc.aux_ctl() != 0x16_F210
            || tc.clk_valfreq().is_some()
        {
            return TestResult::Fail("TC1 timer/aux/valfreq wrong (TC has no VALFREQ)");
        }
        if a.phy() != PhyKind::C10 || tc.phy() != PhyKind::C20 {
            return TestResult::Fail("PHY mapping wrong");
        }
        if tc.phy_index() != 2 || tc.func_ctl_index() != 9 || tc.aux_well_index() != 3 {
            return TestResult::Fail("TC1 indices wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_port_register_map);

    fn smoke_pll_state_tables() -> TestResult {
        let hbr2 = match c10_pll_state(540_000, true) {
            Some(s) => s,
            None => return TestResult::Fail("C10 HBR2 state missing"),
        };
        if hbr2.pll[0] != 0xF4
            || hbr2.pll[15] != 0x00
            || hbr2.pll[16] != 0x84
            || hbr2.cmn != 0x21
            || hbr2.tx != 0x10
        {
            return TestResult::Fail("C10 HBR2 state bytes wrong");
        }
        // eDP-only rates must not resolve on the DP table.
        if c10_pll_state(216_000, false).is_some() {
            return TestResult::Fail("eDP 216 MHz state leaked into the DP table");
        }
        if c10_pll_state(216_000, true).map(|s| s.pll[2]) != Some(0xA2) {
            return TestResult::Fail("C10 eDP 216 MHz state wrong");
        }
        if c10_pll_state(123_456, true).is_some() {
            return TestResult::Fail("unknown rate must not resolve");
        }
        let c20 = match c20_pll_state(810_000) {
            Some(s) => s,
            None => return TestResult::Fail("C20 HBR3 state missing"),
        };
        if c20.mpllb[0] != 0x10D2
            || c20.mpllb[4] != 0x7166
            || c20.tx[0] != 0xBE88
            || c20.cmn[0] != 0x0500
        {
            return TestResult::Fail("C20 HBR3 state words wrong");
        }
        if c20_pll_state(216_000).is_some() {
            return TestResult::Fail("C20 has no eDP intermediate rates");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_pll_state_tables);

    fn smoke_msgbus_framing() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::A);
        let phy = Cx0Phy::new(&fake, XeLpgPort::A);
        if phy.write(LANE0, 0xC00, 0xF4, true).is_err() {
            return TestResult::Fail("committed write failed against healthy PHY");
        }
        let txns = fake.msgbus_txns(0);
        // Exactly one data transaction: PENDING | WRITE_COMMITTED
        // (cmd 2) | data 0xF4 | addr 0xC00.
        if txns != alloc::vec![(2, 0xC00, 0xF4)] {
            return TestResult::Fail("committed write framing wrong");
        }
        // Followed by a bus-reset write (TRANSACTION_RESET only).
        let resets = fake
            .writes_to(XeLpgPort::A.msgbus_ctl_ln0())
            .into_iter()
            .filter(|w| *w == M2P_TRANSACTION_RESET)
            .count();
        if resets == 0 {
            return TestResult::Fail("bus reset must follow the transaction");
        }
        // Uncommitted write: command field 1.
        if phy.write(LANE0, 0xC01, 0x00, false).is_err() {
            return TestResult::Fail("uncommitted write failed");
        }
        let txns = fake.msgbus_txns(0);
        if txns[txns.len() - 1] != (1, 0xC01, 0x00) {
            return TestResult::Fail("uncommitted write framing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_msgbus_framing);

    fn smoke_msgbus_rejects_bad_phy_answers() -> TestResult {
        // Wrong-ACK: a PHY answering writes with READ acks is not
        // speaking this generation's protocol — must fail.
        let fake = FakePhy::new(XeLpgPort::A);
        fake.set_fail(Fail::WrongAck);
        let phy = Cx0Phy::new(&fake, XeLpgPort::A);
        match phy.write(LANE0, 0xC00, 0xF4, true) {
            Err(Cx0Error::ProtocolMismatch) => {}
            _ => return TestResult::Fail("wrong ACK command must be ProtocolMismatch"),
        }
        // Error bit set: must fail as PhyError.
        let fake2 = FakePhy::new(XeLpgPort::A);
        fake2.set_fail(Fail::ErrorBit);
        let phy2 = Cx0Phy::new(&fake2, XeLpgPort::A);
        match phy2.write(LANE0, 0xC00, 0xF4, true) {
            Err(Cx0Error::PhyError) => {}
            _ => return TestResult::Fail("P2M_ERROR_SET must be PhyError"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg",
        smoke_msgbus_rejects_bad_phy_answers
    );

    fn smoke_c10_pll_program_sequence() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::A);
        // Seed custom width non-zero so its RMW writes.
        fake.vdr_set(0, C10_VDR_CUSTOM_WIDTH, 0x3);
        fake.vdr_set(1, C10_VDR_CUSTOM_WIDTH, 0x3);
        let phy = Cx0Phy::new(&fake, XeLpgPort::A);
        let state = c10_pll_state(540_000, true).expect("HBR2");
        if c10_pll_program(&phy, state).is_err() {
            return TestResult::Fail("C10 PLL program failed");
        }
        let txns = fake.msgbus_txns(0);
        // Collect the PLL byte writes (addr 0xC00..0xC14).
        let pll_writes: Vec<(u32, u16, u8)> = txns
            .iter()
            .copied()
            .filter(|(_, a, _)| (0xC00..0xC14).contains(a))
            .collect();
        if pll_writes.len() != 20 {
            return TestResult::Fail("expected 20 PLL byte writes on lane 0");
        }
        for (i, (cmd, addr, data)) in pll_writes.iter().enumerate() {
            if *addr != 0xC00 + i as u16 || *data != state.pll[i] {
                return TestResult::Fail("PLL byte write wrong addr/data");
            }
            let committed = *cmd == 2;
            if committed != (i % 4 == 0) {
                return TestResult::Fail("PLL byte commit pattern must be every 4th");
            }
        }
        // CMN + TX committed writes present.
        if !txns.contains(&(2, 0xC20, 0x21)) || !txns.contains(&(2, 0xC30, 0x10)) {
            return TestResult::Fail("CMN/TX writes missing");
        }
        // Batch control: begin wrote MSGBUS_ACCESS (0x04) and the
        // commit wrote UPDATE_CFG|MASTER_LANE — with the access
        // bit still set from the read-modify-write, data is 0x07.
        if !txns.contains(&(2, C10_VDR_CONTROL_1, 0x04)) {
            return TestResult::Fail("msgbus access begin write missing");
        }
        if txns.last() != Some(&(2, C10_VDR_CONTROL_1, 0x07)) {
            return TestResult::Fail("final transaction must be the master commit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg",
        smoke_c10_pll_program_sequence
    );

    fn smoke_c20_pll_program_context() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::Tc1);
        let phy = Cx0Phy::new(&fake, XeLpgPort::Tc1);
        let state = c20_pll_state(540_000).expect("HBR2");
        if c20_pll_program(&phy, state, 540_000).is_err() {
            return TestResult::Fail("C20 PLL program failed");
        }
        // Serdes toggle starts clear, so per the i915 sequence
        // the new state lands in context B and the toggle flips
        // to set in step 7; context A stays untouched.
        if fake.sram_get(C20_B_TX_CNTX_CFG) != 0xBE88 {
            return TestResult::Fail("C20 TX cfg0 not in context B SRAM");
        }
        if fake.sram_get(C20_B_MPLLB_CNTX_CFG) != state.mpllb[0]
            || fake.sram_get(C20_B_MPLLB_CNTX_CFG - 10) != state.mpllb[10]
        {
            return TestResult::Fail("C20 MPLLB context B words wrong");
        }
        if fake.sram_get(C20_A_MPLLB_CNTX_CFG) != 0 {
            return TestResult::Fail("context A must stay untouched");
        }
        let serdes = fake.vdr_get(0, C20_VDR_CUSTOM_SERDES_RATE);
        if serdes & C20_SERDES_IS_DP == 0
            || (serdes >> 1) & 0xF != 2
            || serdes & C20_CONTEXT_TOGGLE == 0
        {
            return TestResult::Fail("serdes rate byte must be IS_DP | rate 2 | toggle set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_c20_pll_program_context);

    fn smoke_enable_port_pll_c10() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::A);
        if enable_port_pll(&fake, XeLpgPort::A, LinkRate::DpHbr2, 4).is_err() {
            return TestResult::Fail("C10 PLL enable failed against healthy PHY");
        }
        let clock = fake.stored(XeLpgPort::A.port_clock_ctl());
        if clock & DDI_CLOCK_SELECT_MAXPCLK != DDI_CLOCK_SELECT_MAXPCLK
            || clock & FORWARD_CLOCK_UNGATE == 0
            || clock & SSC_ENABLE_PLLB == 0
        {
            return TestResult::Fail("PORT_CLOCK_CTL mux/ungate/SSC wrong");
        }
        if clock & lane_pclk_pll_request(0) == 0 {
            return TestResult::Fail("PCLK PLL request never raised");
        }
        // DDI_CLK_VALFREQ carries the symbol clock (= port clock).
        if fake.writes_to(0x6_4030) != alloc::vec![540_000] {
            return TestResult::Fail("DDI_CLK_VALFREQ must be written once with 540000");
        }
        // Powerdown P2 staging reached BUF_CTL2.
        let p2 = lane_powerdown_new_state(0, P2_STATE_READY)
            | lane_powerdown_new_state(1, P2_STATE_READY);
        if !fake
            .writes_to(XeLpgPort::A.buf_ctl2())
            .iter()
            .any(|w| w & p2 == p2)
        {
            return TestResult::Fail("P2 powerdown state never staged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_enable_port_pll_c10);

    fn smoke_enable_port_pll_c20() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::Tc1);
        if enable_port_pll(&fake, XeLpgPort::Tc1, LinkRate::DpHbr3, 4).is_err() {
            return TestResult::Fail("C20 PLL enable failed against healthy PHY");
        }
        // Message bus traffic went to the TC1 block, not DDI A.
        if fake.msgbus_txns(0).is_empty() || !fake.writes_to(0x6_4040).is_empty() {
            return TestResult::Fail("C20 traffic must use the TC1 msgbus block");
        }
        // No VALFREQ register exists on TC ports: the only write
        // to the DDI A valfreq offset would be a Gen12-ism.
        if !fake.writes_to(0x6_4030).is_empty() {
            return TestResult::Fail("VALFREQ must not be written for TC ports");
        }
        if fake.sram_get(C20_B_MPLLB_CNTX_CFG) != 0x10D2 {
            return TestResult::Fail("HBR3 MPLLB cfg0 not programmed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_enable_port_pll_c20);

    fn smoke_pll_enable_times_out_without_ack() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::A);
        fake.no_clock_ack.set(true);
        match enable_port_pll(&fake, XeLpgPort::A, LinkRate::DpHbr2, 4) {
            Err(Cx0Error::Timeout) => TestResult::Pass,
            _ => TestResult::Fail("missing PCLK ACK must surface as Timeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg",
        smoke_pll_enable_times_out_without_ack
    );

    fn smoke_set_signal_levels_c10() -> TestResult {
        let fake = FakePhy::new(XeLpgPort::A);
        let phy = Cx0Phy::new(&fake, XeLpgPort::A);
        let levels = [(0u8, 0u8); 4];
        if set_signal_levels(&phy, LinkRate::DpHbr2, 4, &levels).is_err() {
            return TestResult::Fail("set_signal_levels failed");
        }
        // C10 preset 0 = (vswing 26, pre 0, post 0). VDR writes:
        // lane0/tx0 → 0xD80.., lane0/tx1 → 0xD90.., lane1/tx0 →
        // 0xD90.. (lane1 bus), lane1/tx1 → 0xD80.. (lane1 bus).
        // The swing byte lands at control offset 1.
        if fake.vdr_get(0, 0xD81) != 26 || fake.vdr_get(0, 0xD91) != 26 {
            return TestResult::Fail("lane0 swing overrides wrong");
        }
        if fake.vdr_get(1, 0xD91) != 26 || fake.vdr_get(1, 0xD81) != 26 {
            return TestResult::Fail("lane1 swing overrides wrong");
        }
        // eDP HBR2 staging bytes: vboost 4 → CMN(3) = 4<<5,
        // termctl 2 → TX(1) = 2<<5.
        if fake.vdr_get(0, c10_vdr_cmn(3)) != 0x80 || fake.vdr_get(0, c10_vdr_tx(1)) != 0x40 {
            return TestResult::Fail("eDP vboost/termctl staging wrong");
        }
        // Override enable bits set.
        if fake.vdr_get(0, C10_VDR_OVRD) & (C10_VDR_OVRD_TX1 | C10_VDR_OVRD_TX2) != 0x5 {
            return TestResult::Fail("override enables not set");
        }
        // External DP (port B) at HBR2 gets the hot staging.
        let fake_b = FakePhy::new(XeLpgPort::B);
        let phy_b = Cx0Phy::new(&fake_b, XeLpgPort::B);
        if set_signal_levels(&phy_b, LinkRate::DpHbr2, 4, &levels).is_err() {
            return TestResult::Fail("port B set_signal_levels failed");
        }
        if fake_b.vdr_get(0, c10_vdr_cmn(3)) != 0xA0 || fake_b.vdr_get(0, c10_vdr_tx(1)) != 0xA0 {
            return TestResult::Fail("external DP vboost/termctl must be 5/5 at HBR2");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_set_signal_levels_c10);

    fn smoke_preset_index_map() -> TestResult {
        let cases = [
            ((0, 0), 0usize),
            ((0, 3), 3),
            ((1, 0), 4),
            ((1, 2), 6),
            ((2, 0), 7),
            ((2, 1), 8),
            ((3, 0), 9),
            ((3, 3), 9), // undefined combo clamps to max drive
        ];
        for ((s, p), want) in cases {
            if preset_index(s, p) != want {
                return TestResult::Fail("preset index mapping wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_xelpg", smoke_preset_index_map);
}

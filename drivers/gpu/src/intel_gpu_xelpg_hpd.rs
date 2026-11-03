//! Intel Xe-LPDP (Meteor Lake / Arrow Lake) owned hotplug detection.
//!
//! Display version 14 moves Type-C hotplug out of the GEN11 DE HPD block
//! into the **PICA** interrupt block on the IO die and keeps the combo
//! ports' hotplug on the on-die south display ("MTP", a fake PCH type:
//! `intel_pch.c::intel_pch_fake_for_south_display` selects `PCH_MTL` from
//! the platform, so no ISA-bridge identity is involved).
//!
//! | Pin    | Live level                   | Pulse latch                    |
//! | ------ | ---------------------------- | ------------------------------ |
//! | DDI B  | `SDEISR` bit 17              | `SHOTPLUG_CTL_DDI` nibble 1    |
//! | TCn    | `PICAINTERRUPT_ISR` DP-alt bit 16+n-1, TBT bit n-1 | `XELPDP_PORT_HOTPLUG_CTL(TCn)` |
//! | TCn legacy | `SDEISR` bit 24+n-1 (only for a declared legacy port) | `SHOTPLUG_CTL_TC` nibble n-1 |
//!
//! DDI A is the internal eDP port on mobile MTL and is never owned here.
//!
//! ## Sources (Linux b90c984d)
//!
//! - `intel_hotplug_irq.c`: `hpd_xelpdp` / `hpd_mtp` pin tables,
//!   `xelpdp_pica_irq_handler` (read + write-back of the per-port
//!   hotplug control, long = DP-alt/TBT LONG_DETECT),
//!   `icp_irq_handler` + `icp_ddi_port_hotplug_long_detect` /
//!   `icp_tc_port_hotplug_long_detect`, `xelpdp_hpd_irq_setup`,
//!   `_xelpdp_pica_hpd_detection_setup`, `mtp_hpd_irq_setup`
//!   (SHPD_FILTER_CNT_250, `mtp_hpd_invert`, DDI/TC detection setup).
//! - `intel_display_irq.c`: `mtp_irq_postinstall` (PICA IER carries
//!   the DP-alt/TBT hotplug sources), `gen8_read_and_ack_pch_irqs`
//!   (PICA IIR acknowledged before SDEIIR), `gen11_display_irq_reset`
//!   (PICA/SDE IMR all-ones, IER 0, IIR cleared).
//! - `intel_tc.c::xelpdp_tc_phy_hpd_live_status` and
//!   `intel_ddi.c::lpt_digital_port_connected` for the live levels.
//! - `intel_hotplug.c::intel_hpd_irq_handler`: a long pulse requests full
//!   detection; a short pulse goes to the DP `hpd_pulse` handler.
//!
//! ## Ownership posture
//!
//! There is no display interrupt consumer, so — like the Gen12 combo-B
//! monitor — the owned IER sources are enabled while their IMR bits are
//! installed masked first and read back; the per-port hotplug status
//! latches (which latch with detection enabled regardless of IMR) carry
//! the long/short decode. Owned IIR bits are acknowledged PICA before
//! SDE, as the source handler does. Foreign W1C status in the shared
//! `SHOTPLUG_CTL_DDI` / `SHOTPLUG_CTL_TC` registers is never cleared. A
//! single low level never proves unplug: only a latched long pulse with a
//! low live level does. Lost register authority or an all-ones status read
//! makes the monitor uncertain (no events) until [`MtlHpdMonitor::teardown`]
//! and a fresh initialization. Hardware latches coalesce pulses; one
//! pending event per pin is retained, status changes dominating pulses.

use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_xelpg::XeLpgPort;

// ── PICA (Type-C) interrupt block — intel_display_regs.h ─────────

/// `PICAINTERRUPT_ISR`.
pub const PICA_ISR: u64 = 0x16_FE50;
/// `PICAINTERRUPT_IMR`.
pub const PICA_IMR: u64 = 0x16_FE54;
/// `PICAINTERRUPT_IIR`.
pub const PICA_IIR: u64 = 0x16_FE58;
/// `PICAINTERRUPT_IER`.
pub const PICA_IER: u64 = 0x16_FE5C;
/// `XELPDP_DP_ALT_HOTPLUG(TCn)` = bit 16 + (n - 1).
pub const fn pica_dp_alt_hotplug(tc: u8) -> u32 {
    1 << (16 + tc as u32)
}
/// `XELPDP_TBT_HOTPLUG(TCn)` = bit (n - 1).
pub const fn pica_tbt_hotplug(tc: u8) -> u32 {
    1 << tc as u32
}
/// `XELPDP_PORT_HOTPLUG_CTL(TCn)` = 0x16F270 + (n - 1) * 0x200.
pub const fn port_hotplug_ctl(tc: u8) -> u64 {
    0x16_F270 + 0x200 * tc as u64
}
/// `XELPDP_TBT_HOTPLUG_ENABLE`.
pub const TBT_HOTPLUG_ENABLE: u32 = 1 << 6;
/// `XELPDP_TBT_HPD_LONG_DETECT`.
pub const TBT_HPD_LONG_DETECT: u32 = 1 << 5;
/// `XELPDP_TBT_HPD_SHORT_DETECT`.
pub const TBT_HPD_SHORT_DETECT: u32 = 1 << 4;
/// `XELPDP_DP_ALT_HOTPLUG_ENABLE`.
pub const DP_ALT_HOTPLUG_ENABLE: u32 = 1 << 2;
/// `XELPDP_DP_ALT_HPD_LONG_DETECT`.
pub const DP_ALT_HPD_LONG_DETECT: u32 = 1 << 1;
/// `XELPDP_DP_ALT_HPD_SHORT_DETECT`.
pub const DP_ALT_HPD_SHORT_DETECT: u32 = 1;
const PORT_HOTPLUG_ENABLES: u32 = TBT_HOTPLUG_ENABLE | DP_ALT_HOTPLUG_ENABLE;
const PORT_HOTPLUG_LONG: u32 = TBT_HPD_LONG_DETECT | DP_ALT_HPD_LONG_DETECT;
const PORT_HOTPLUG_SHORT: u32 = TBT_HPD_SHORT_DETECT | DP_ALT_HPD_SHORT_DETECT;

// ── South display (MTP) — i915_reg.h / intel_display_regs.h ──────

/// `SDEISR`.
pub const SDE_ISR: u64 = 0xC_4000;
/// `SDEIMR`.
pub const SDE_IMR: u64 = 0xC_4004;
/// `SDEIIR`.
pub const SDE_IIR: u64 = 0xC_4008;
/// `SDEIER`.
pub const SDE_IER: u64 = 0xC_400C;
/// `SDE_DDI_HOTPLUG_ICP(HPD_PORT_A + ddi)` = bit 16 + ddi.
pub const fn sde_ddi_hotplug(ddi: u8) -> u32 {
    1 << (16 + ddi as u32)
}
/// `SDE_TC_HOTPLUG_ICP(TCn)` = bit 24 + (n - 1).
pub const fn sde_tc_hotplug(tc: u8) -> u32 {
    1 << (24 + tc as u32)
}
/// `SHOTPLUG_CTL_DDI`.
pub const SHOTPLUG_CTL_DDI: u64 = 0xC_4030;
/// `SHOTPLUG_CTL_TC`.
pub const SHOTPLUG_CTL_TC: u64 = 0xC_4034;
/// `SHPD_FILTER_CNT`.
pub const SHPD_FILTER_CNT: u64 = 0xC_4038;
/// `SHPD_FILTER_CNT_250` — the DP 1.4a 250 µs filter `mtp_hpd_irq_setup`
/// programs.
pub const SHPD_FILTER_CNT_250: u32 = 0xF8;
/// `SOUTH_CHICKEN1`.
pub const SOUTH_CHICKEN1: u64 = 0xC_2000;
/// `mtp_hpd_invert`: INVERT_DDIA/B/C_HPD (15..17), INVERT_TC1..4_HPD
/// (23..26), INVERT_DDID_HPD_MTP (27), INVERT_DDIE_HPD (28).
pub const MTP_HPD_INVERT: u32 = (1 << 15)
    | (1 << 16)
    | (1 << 17)
    | (1 << 23)
    | (1 << 24)
    | (1 << 25)
    | (1 << 26)
    | (1 << 27)
    | (1 << 28);
/// `SHOTPLUG_CTL_DDI_HPD_ENABLE(HPD_PORT_A + ddi)`.
pub const fn shotplug_ddi_enable(ddi: u8) -> u32 {
    0x8 << (4 * ddi as u32)
}
/// `SHOTPLUG_CTL_DDI_HPD_LONG_DETECT(HPD_PORT_A + ddi)`.
pub const fn shotplug_ddi_long(ddi: u8) -> u32 {
    0x2 << (4 * ddi as u32)
}
/// `SHOTPLUG_CTL_DDI_HPD_SHORT_DETECT(HPD_PORT_A + ddi)`.
pub const fn shotplug_ddi_short(ddi: u8) -> u32 {
    0x1 << (4 * ddi as u32)
}
/// `ICP_TC_HPD_ENABLE(TCn)`.
pub const fn icp_tc_hpd_enable(tc: u8) -> u32 {
    0x8 << (4 * tc as u32)
}
/// `ICP_TC_HPD_LONG_DETECT(TCn)`.
pub const fn icp_tc_hpd_long(tc: u8) -> u32 {
    0x2 << (4 * tc as u32)
}
/// `ICP_TC_HPD_SHORT_DETECT(TCn)`.
pub const fn icp_tc_hpd_short(tc: u8) -> u32 {
    0x1 << (4 * tc as u32)
}
/// Every pin's two status bits in `SHOTPLUG_CTL_DDI` (A..D).
const SHOTPLUG_DDI_ALL_STATUS: u32 = 0x3333;
/// Every pin's two status bits in `SHOTPLUG_CTL_TC` (TC1..TC6).
const SHOTPLUG_TC_ALL_STATUS: u32 = 0x33_3333;
/// DDI B in the south-display DDI numbering.
const DDI_B: u8 = 1;

// ── Pins, modes and events ───────────────────────────────────────

/// A hotplug pin this monitor owns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtlHpdPin {
    /// Combo DDI B (C10 PHY), native DP/HDMI connector.
    DdiB,
    /// Type-C port 1.
    Tc1,
    /// Type-C port 2.
    Tc2,
    /// Type-C port 3.
    Tc3,
    /// Type-C port 4.
    Tc4,
}

impl MtlHpdPin {
    /// Every owned pin, in poll order.
    pub const ALL: [MtlHpdPin; 5] = [
        MtlHpdPin::DdiB,
        MtlHpdPin::Tc1,
        MtlHpdPin::Tc2,
        MtlHpdPin::Tc3,
        MtlHpdPin::Tc4,
    ];
    /// Dense index (0 = DDI B, 1..=4 = TC1..TC4).
    pub const fn index(self) -> usize {
        match self {
            MtlHpdPin::DdiB => 0,
            MtlHpdPin::Tc1 => 1,
            MtlHpdPin::Tc2 => 2,
            MtlHpdPin::Tc3 => 3,
            MtlHpdPin::Tc4 => 4,
        }
    }
    /// Type-C index (`enum tc_port`, TC1 = 0).
    pub const fn tc(self) -> Option<u8> {
        match self {
            MtlHpdPin::DdiB => None,
            MtlHpdPin::Tc1 => Some(0),
            MtlHpdPin::Tc2 => Some(1),
            MtlHpdPin::Tc3 => Some(2),
            MtlHpdPin::Tc4 => Some(3),
        }
    }
    /// The display port behind the pin.
    pub const fn port(self) -> XeLpgPort {
        match self {
            MtlHpdPin::DdiB => XeLpgPort::B,
            MtlHpdPin::Tc1 => XeLpgPort::Tc1,
            MtlHpdPin::Tc2 => XeLpgPort::Tc2,
            MtlHpdPin::Tc3 => XeLpgPort::Tc3,
            MtlHpdPin::Tc4 => XeLpgPort::Tc4,
        }
    }
    /// The owned pin for an external port (`None` for internal DDI A).
    pub const fn from_port(port: XeLpgPort) -> Option<Self> {
        match port {
            XeLpgPort::A => None,
            XeLpgPort::B => Some(MtlHpdPin::DdiB),
            XeLpgPort::Tc1 => Some(MtlHpdPin::Tc1),
            XeLpgPort::Tc2 => Some(MtlHpdPin::Tc2),
            XeLpgPort::Tc3 => Some(MtlHpdPin::Tc3),
            XeLpgPort::Tc4 => Some(MtlHpdPin::Tc4),
        }
    }
}

/// How a live sink is attached.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LiveMode {
    /// Native combo-port sink (DDI B).
    Native,
    /// Type-C Thunderbolt-alt (`TC_PORT_TBT_ALT`).
    TbtAlt,
    /// Type-C DisplayPort-alt (`TC_PORT_DP_ALT`).
    DpAlt,
    /// Type-C port wired as a legacy DP/HDMI connector (`TC_PORT_LEGACY`).
    Legacy,
}

/// Published connector status for one pin.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectorStatus {
    /// No current-incarnation detection yet (or monitor uncertain).
    Unknown,
    /// A sink is present in the given mode.
    Connected(LiveMode),
    /// No sink.
    Disconnected,
}

/// What happened on a pin.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtlHpdKind {
    /// Status became connected (initial detection or long pulse + high).
    Connected(LiveMode),
    /// Long pulse with a low live level on a connected pin.
    Disconnected,
    /// Short pulse (DP IRQ_HPD) on a connected pin: check link status.
    ShortPulse,
    /// Long pulse on a pin that stays connected: the sink may have been
    /// replaced; full detection must re-run.
    Redetect,
}

/// One hotplug event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlHpdEvent {
    /// The pin.
    pub pin: MtlHpdPin,
    /// What happened.
    pub kind: MtlHpdKind,
}

/// Board facts the monitor cannot discover from registers. Without a VBT
/// parser in this tree the production configuration declares no legacy
/// Type-C ports, so legacy SDE TC sources stay unowned and a legacy sink is
/// not reported (exactly the source behavior for `legacy_port == false`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlHpdConfig {
    /// `intel_tc_port::legacy_port` per Type-C port.
    pub legacy_tc: [bool; 4],
}

impl MtlHpdConfig {
    /// All four Type-C ports are USB-C connectors (no legacy wiring).
    pub const TYPE_C: Self = Self {
        legacy_tc: [false; 4],
    };
}

/// Decode a pin's live mode from the two ISR snapshots —
/// `xelpdp_tc_phy_hpd_live_status` (TC; LEGACY only for a declared legacy
/// port; the highest set mode wins as `hpd_mask_to_tc_mode`'s `fls`) and
/// `lpt_digital_port_connected` (DDI B).
pub const fn live_mode(
    pin: MtlHpdPin,
    legacy_tc: bool,
    pica_isr: u32,
    sde_isr: u32,
) -> Option<LiveMode> {
    match pin.tc() {
        None => {
            if sde_isr & sde_ddi_hotplug(DDI_B) != 0 {
                Some(LiveMode::Native)
            } else {
                None
            }
        }
        Some(tc) => {
            if legacy_tc && sde_isr & sde_tc_hotplug(tc) != 0 {
                Some(LiveMode::Legacy)
            } else if pica_isr & pica_dp_alt_hotplug(tc) != 0 {
                Some(LiveMode::DpAlt)
            } else if pica_isr & pica_tbt_hotplug(tc) != 0 {
                Some(LiveMode::TbtAlt)
            } else {
                None
            }
        }
    }
}

// ── Monitor ──────────────────────────────────────────────────────

/// Poll-driven owner of the MTL external hotplug sources.
#[derive(Debug)]
pub struct MtlHpdMonitor {
    config: MtlHpdConfig,
    status: [ConnectorStatus; 5],
    pending: [Option<MtlHpdKind>; 5],
    initialized: bool,
    uncertain: bool,
}

impl MtlHpdMonitor {
    /// A fresh, uninitialized monitor.
    pub const fn new(config: MtlHpdConfig) -> Self {
        Self {
            config,
            status: [ConnectorStatus::Unknown; 5],
            pending: [None; 5],
            initialized: false,
            uncertain: false,
        }
    }

    /// Owned PICA sources: DP-alt + TBT hotplug of all four TC pins.
    pub const fn owned_pica() -> u32 {
        0xF_0000 | 0xF
    }

    /// Owned south-display sources: DDI B plus declared legacy TC pins.
    pub fn owned_sde(&self) -> u32 {
        let mut bits = sde_ddi_hotplug(DDI_B);
        for tc in 0..4u8 {
            if self.config.legacy_tc[tc as usize] {
                bits |= sde_tc_hotplug(tc);
            }
        }
        bits
    }

    fn legacy_tc_enables(&self) -> u32 {
        let mut bits = 0;
        for tc in 0..4u8 {
            if self.config.legacy_tc[tc as usize] {
                bits |= icp_tc_hpd_enable(tc);
            }
        }
        bits
    }

    fn legacy_tc_status(&self) -> u32 {
        let mut bits = 0;
        for tc in 0..4u8 {
            if self.config.legacy_tc[tc as usize] {
                bits |= icp_tc_hpd_long(tc) | icp_tc_hpd_short(tc);
            }
        }
        bits
    }

    /// Whether current authority was lost since initialization.
    pub fn uncertain(&self) -> bool {
        self.uncertain
    }

    /// Whether the owned sources have a current baseline.
    pub fn initialized(&self) -> bool {
        self.initialized
    }

    /// The published status of `pin`.
    pub fn status(&self, pin: MtlHpdPin) -> ConnectorStatus {
        if self.uncertain {
            ConnectorStatus::Unknown
        } else {
            self.status[pin.index()]
        }
    }

    fn lose(&mut self) {
        self.uncertain = true;
        self.pending = [None; 5];
    }

    fn queue(&mut self, pin: MtlHpdPin, kind: MtlHpdKind) {
        let slot = &mut self.pending[pin.index()];
        let status_change =
            |k: MtlHpdKind| matches!(k, MtlHpdKind::Connected(_) | MtlHpdKind::Disconnected);
        match *slot {
            Some(old) if status_change(old) && !status_change(kind) => {}
            _ => *slot = Some(kind),
        }
    }

    fn pop(&mut self) -> Option<MtlHpdEvent> {
        for pin in MtlHpdPin::ALL {
            if let Some(kind) = self.pending[pin.index()].take() {
                return Some(MtlHpdEvent { pin, kind });
            }
        }
        None
    }

    /// Establish the owned sources and the first detection baseline:
    /// install/read-verify IMR masks before IER, ACK owned stale IIR,
    /// enable per-port detection (write-back clears latched owned
    /// status), program the source filter and HPD inversion, then sample
    /// live levels. Connected pins queue `Connected`.
    pub fn enable<M: MmioWindow + ?Sized>(&mut self, io: &M) {
        if self.initialized || self.uncertain {
            return;
        }
        if !io.display_access_ok() {
            self.lose();
            return;
        }
        let pica = Self::owned_pica();
        let sde = self.owned_sde();
        // PICA: mask first, verify, then enable the latch sources.
        let imr = io.read32(PICA_IMR);
        io.write32(PICA_IMR, imr | pica);
        if !io.display_access_ok() || io.read32(PICA_IMR) & pica != pica {
            self.lose();
            return;
        }
        let ier = io.read32(PICA_IER);
        io.write32(PICA_IER, ier | pica);
        let iir = io.read32(PICA_IIR);
        if iir == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        if iir & pica != 0 {
            io.write32(PICA_IIR, iir & pica);
        }
        // `_xelpdp_pica_hpd_detection_setup`: rmw(enables, enables). The
        // write-back of read status clears the pin's latched pulses.
        for tc in 0..4u8 {
            let ctl = io.read32(port_hotplug_ctl(tc));
            if ctl == u32::MAX || !io.display_access_ok() {
                self.lose();
                return;
            }
            io.write32(port_hotplug_ctl(tc), ctl | PORT_HOTPLUG_ENABLES);
        }
        // South display: `mtp_hpd_irq_setup`.
        io.write32(SHPD_FILTER_CNT, SHPD_FILTER_CNT_250);
        let chicken = io.read32(SOUTH_CHICKEN1);
        if chicken == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        io.write32(SOUTH_CHICKEN1, chicken | MTP_HPD_INVERT);
        let simr = io.read32(SDE_IMR);
        io.write32(SDE_IMR, simr | sde);
        if !io.display_access_ok() || io.read32(SDE_IMR) & sde != sde {
            self.lose();
            return;
        }
        let sier = io.read32(SDE_IER);
        io.write32(SDE_IER, sier | sde);
        let siir = io.read32(SDE_IIR);
        if siir == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        if siir & sde != 0 {
            io.write32(SDE_IIR, siir & sde);
        }
        // Owned status cleared, foreign W1C status preserved (written 0).
        let ddi = io.read32(SHOTPLUG_CTL_DDI);
        if ddi == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        let ddi_owned = shotplug_ddi_long(DDI_B) | shotplug_ddi_short(DDI_B);
        io.write32(
            SHOTPLUG_CTL_DDI,
            (ddi & !SHOTPLUG_DDI_ALL_STATUS) | (ddi & ddi_owned) | shotplug_ddi_enable(DDI_B),
        );
        let legacy_en = self.legacy_tc_enables();
        if legacy_en != 0 {
            let tcctl = io.read32(SHOTPLUG_CTL_TC);
            if tcctl == u32::MAX || !io.display_access_ok() {
                self.lose();
                return;
            }
            io.write32(
                SHOTPLUG_CTL_TC,
                (tcctl & !SHOTPLUG_TC_ALL_STATUS) | (tcctl & self.legacy_tc_status()) | legacy_en,
            );
        }
        // Read back every owned setting.
        let mut ok = io.read32(PICA_IMR) & pica == pica
            && io.read32(PICA_IER) & pica == pica
            && io.read32(SHPD_FILTER_CNT) == SHPD_FILTER_CNT_250
            && io.read32(SOUTH_CHICKEN1) & MTP_HPD_INVERT == MTP_HPD_INVERT
            && io.read32(SDE_IMR) & sde == sde
            && io.read32(SDE_IER) & sde == sde;
        for tc in 0..4u8 {
            let ctl = io.read32(port_hotplug_ctl(tc));
            ok &= ctl != u32::MAX && ctl & PORT_HOTPLUG_ENABLES == PORT_HOTPLUG_ENABLES;
        }
        let ddi = io.read32(SHOTPLUG_CTL_DDI);
        ok &= ddi != u32::MAX && ddi & shotplug_ddi_enable(DDI_B) != 0;
        if legacy_en != 0 {
            let tcctl = io.read32(SHOTPLUG_CTL_TC);
            ok &= tcctl != u32::MAX && tcctl & legacy_en == legacy_en;
        }
        let pica_isr = io.read32(PICA_ISR);
        let sde_isr = io.read32(SDE_ISR);
        if !ok || pica_isr == u32::MAX || sde_isr == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        for pin in MtlHpdPin::ALL {
            let legacy = pin
                .tc()
                .is_some_and(|tc| self.config.legacy_tc[tc as usize]);
            match live_mode(pin, legacy, pica_isr, sde_isr) {
                Some(mode) => {
                    self.status[pin.index()] = ConnectorStatus::Connected(mode);
                    self.queue(pin, MtlHpdKind::Connected(mode));
                }
                None => self.status[pin.index()] = ConnectorStatus::Disconnected,
            }
        }
        self.initialized = true;
    }

    /// Return the next pending event, sampling the latches once when none
    /// is queued. Initializes on first use. Uncertain monitors return
    /// `None` until torn down.
    pub fn poll<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Option<MtlHpdEvent> {
        if !self.initialized {
            self.enable(io);
        }
        if self.uncertain || !self.initialized {
            return None;
        }
        if let Some(event) = self.pop() {
            return Some(event);
        }
        self.sample(io);
        if self.uncertain {
            return None;
        }
        self.pop()
    }

    fn sample<M: MmioWindow + ?Sized>(&mut self, io: &M) {
        if !io.display_access_ok() {
            self.lose();
            return;
        }
        let pica = Self::owned_pica();
        let sde = self.owned_sde();
        // Source order: PICA IIR, then SDEIIR, then the per-port status.
        let pica_iir = io.read32(PICA_IIR);
        let sde_iir = io.read32(SDE_IIR);
        if pica_iir == u32::MAX || sde_iir == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        if pica_iir & pica != 0 {
            io.write32(PICA_IIR, pica_iir & pica);
        }
        if sde_iir & sde != 0 {
            io.write32(SDE_IIR, sde_iir & sde);
        }
        let mut long = [false; 5];
        let mut short = [false; 5];
        for tc in 0..4u8 {
            let ctl = io.read32(port_hotplug_ctl(tc));
            if ctl == u32::MAX || !io.display_access_ok() {
                self.lose();
                return;
            }
            let status = ctl & (PORT_HOTPLUG_LONG | PORT_HOTPLUG_SHORT);
            if status != 0 {
                // `xelpdp_pica_irq_handler`: val = read; write(val).
                io.write32(port_hotplug_ctl(tc), ctl);
                long[1 + tc as usize] |= status & PORT_HOTPLUG_LONG != 0;
                short[1 + tc as usize] |= status & PORT_HOTPLUG_SHORT != 0;
            }
        }
        let ddi = io.read32(SHOTPLUG_CTL_DDI);
        if ddi == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        let ddi_status = ddi & (shotplug_ddi_long(DDI_B) | shotplug_ddi_short(DDI_B));
        if ddi_status != 0 {
            io.write32(
                SHOTPLUG_CTL_DDI,
                (ddi & !SHOTPLUG_DDI_ALL_STATUS) | ddi_status,
            );
            long[0] = ddi_status & shotplug_ddi_long(DDI_B) != 0;
            short[0] = ddi_status & shotplug_ddi_short(DDI_B) != 0;
        }
        let legacy_status = self.legacy_tc_status();
        if legacy_status != 0 {
            let tcctl = io.read32(SHOTPLUG_CTL_TC);
            if tcctl == u32::MAX || !io.display_access_ok() {
                self.lose();
                return;
            }
            let owned = tcctl & legacy_status;
            if owned != 0 {
                io.write32(SHOTPLUG_CTL_TC, (tcctl & !SHOTPLUG_TC_ALL_STATUS) | owned);
                for tc in 0..4u8 {
                    long[1 + tc as usize] |= owned & icp_tc_hpd_long(tc) != 0;
                    short[1 + tc as usize] |= owned & icp_tc_hpd_short(tc) != 0;
                }
            }
        }
        let pica_isr = io.read32(PICA_ISR);
        let sde_isr = io.read32(SDE_ISR);
        if pica_isr == u32::MAX || sde_isr == u32::MAX || !io.display_access_ok() {
            self.lose();
            return;
        }
        for pin in MtlHpdPin::ALL {
            let i = pin.index();
            if !long[i] && !short[i] {
                continue;
            }
            let legacy = pin
                .tc()
                .is_some_and(|tc| self.config.legacy_tc[tc as usize]);
            let live = live_mode(pin, legacy, pica_isr, sde_isr);
            let was = self.status[i];
            if long[i] {
                match (was, live) {
                    (ConnectorStatus::Connected(old), Some(mode)) if old == mode => {
                        self.queue(pin, MtlHpdKind::Redetect);
                    }
                    (_, Some(mode)) => {
                        self.status[i] = ConnectorStatus::Connected(mode);
                        self.queue(pin, MtlHpdKind::Connected(mode));
                    }
                    (ConnectorStatus::Connected(_), None) => {
                        self.status[i] = ConnectorStatus::Disconnected;
                        self.queue(pin, MtlHpdKind::Disconnected);
                    }
                    (_, None) => self.status[i] = ConnectorStatus::Disconnected,
                }
            } else if matches!(was, ConnectorStatus::Connected(_)) {
                // Short pulse: the level may legally be low during it.
                self.queue(pin, MtlHpdKind::ShortPulse);
            }
        }
    }

    /// Withdraw the owned sources (reset/suspend): IER cleared, IMR
    /// masked, owned IIR acknowledged, detection disabled with owned
    /// latches cleared — `gen11_display_irq_reset` restricted to owned
    /// bits plus `_xelpdp_pica_hpd_detection_setup(.., false)`. The state
    /// always returns to a fresh, uninitialized incarnation; the return
    /// value reports whether every owned source was provably withdrawn.
    pub fn teardown<M: MmioWindow + ?Sized>(&mut self, io: &M) -> bool {
        let pica = Self::owned_pica();
        let sde = self.owned_sde();
        let legacy_en = self.legacy_tc_enables();
        let legacy_status = self.legacy_tc_status();
        let config = self.config;
        // A fresh incarnation never touched a source: nothing to withdraw.
        let touched = self.initialized || self.uncertain;
        *self = Self::new(config);
        if !touched {
            return true;
        }
        if !io.display_access_ok() {
            return false;
        }
        let imr = io.read32(PICA_IMR);
        io.write32(PICA_IMR, imr | pica);
        let ier = io.read32(PICA_IER);
        io.write32(PICA_IER, ier & !pica);
        io.write32(PICA_IIR, pica);
        for tc in 0..4u8 {
            let ctl = io.read32(port_hotplug_ctl(tc));
            if ctl != u32::MAX {
                io.write32(port_hotplug_ctl(tc), ctl & !PORT_HOTPLUG_ENABLES);
            }
        }
        let simr = io.read32(SDE_IMR);
        io.write32(SDE_IMR, simr | sde);
        let sier = io.read32(SDE_IER);
        io.write32(SDE_IER, sier & !sde);
        io.write32(SDE_IIR, sde);
        let ddi = io.read32(SHOTPLUG_CTL_DDI);
        let ddi_owned = shotplug_ddi_long(DDI_B) | shotplug_ddi_short(DDI_B);
        if ddi != u32::MAX {
            io.write32(
                SHOTPLUG_CTL_DDI,
                (ddi & !SHOTPLUG_DDI_ALL_STATUS & !shotplug_ddi_enable(DDI_B)) | (ddi & ddi_owned),
            );
        }
        if legacy_en != 0 {
            let tcctl = io.read32(SHOTPLUG_CTL_TC);
            if tcctl != u32::MAX {
                io.write32(
                    SHOTPLUG_CTL_TC,
                    (tcctl & !SHOTPLUG_TC_ALL_STATUS & !legacy_en) | (tcctl & legacy_status),
                );
            }
        }
        let mut ok = io.display_access_ok()
            && io.read32(PICA_IMR) & pica == pica
            && io.read32(PICA_IER) & pica == 0
            && io.read32(SDE_IMR) & sde == sde
            && io.read32(SDE_IER) & sde == 0;
        for tc in 0..4u8 {
            ok &= io.read32(port_hotplug_ctl(tc)) & (PORT_HOTPLUG_ENABLES | PORT_HOTPLUG_LONG) == 0;
        }
        let ddi = io.read32(SHOTPLUG_CTL_DDI);
        ok &= ddi != u32::MAX && ddi & (shotplug_ddi_enable(DDI_B) | ddi_owned) == 0;
        ok && io.display_access_ok()
    }
}

// ── Process-wide production owner ────────────────────────────────

static MTL_HPD: IrqSafeSpinLock<MtlHpdMonitor> =
    IrqSafeSpinLock::new(MtlHpdMonitor::new(MtlHpdConfig::TYPE_C));

/// Poll the process-wide MTL monitor once. Only Meteor Lake (display 14)
/// windows reach the registers; every other generation returns `None`
/// before any access.
pub fn poll_hpd_event<M: MmioWindow + ?Sized>(
    io: &M,
    generation: crate::intel_gpu::Generation,
) -> Option<MtlHpdEvent> {
    if generation != crate::intel_gpu::Generation::MeteorLake {
        return None;
    }
    MTL_HPD.lock().poll(io)
}

/// Withdraw the process-wide monitor's sources before a display reset or
/// system suspend; the next poll establishes a fresh baseline.
pub fn teardown_hpd<M: MmioWindow + ?Sized>(
    io: &M,
    generation: crate::intel_gpu::Generation,
) -> bool {
    if generation != crate::intel_gpu::Generation::MeteorLake {
        return true;
    }
    MTL_HPD.lock().teardown(io)
}

/// The process-wide published connector status for `pin`.
pub fn connector_status(pin: MtlHpdPin) -> ConnectorStatus {
    MTL_HPD.lock().status(pin)
}

/// Whether the process-wide monitor lost authority and awaits teardown.
pub fn hpd_uncertain() -> bool {
    MTL_HPD.lock().uncertain()
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_hpd_tests.rs"]
pub mod tests;

//! Intel Xe-LPDP (Meteor Lake) Type-C port ownership and AUX power.
//!
//! A Type-C PHY is shared between display, USB and Thunderbolt. Before
//! display may drive the C20 PHY behind TC1–TC4 it must block TC-cold,
//! power the TCSS, wait for the IOM firmware to report the PHY ready and
//! take PHY ownership; on disconnect it hands the PHY back. This module
//! is that handshake plus the per-port Xe-LPDP AUX power well.
//!
//! ## Sources (Linux b90c984d)
//!
//! - `intel_tc.c`: `xelpdp_tc_phy_ops` — `xelpdp_tc_phy_hpd_live_status`,
//!   `adlp_tc_phy_is_ready` (TCSS_DDI_STATUS.READY),
//!   `xelpdp_tc_phy_is_owned` / `_take_ownership` (PORT_BUF_CTL1 bit 6),
//!   `xelpdp_tc_phy_enable_tcss_power` / `_wait_for_tcss_power`
//!   (PORT_BUF_CTL1 bits 5/4, 5 ms), `xelpdp_tc_phy_connect` /
//!   `_disconnect`, `tc_phy_wait_for_ready` (500 ms), `get_pin_assignment`
//!   (`PORT_TX_DFLEXPA1` below display 20), `mtl_get_max_lane_count`,
//!   `tc_phy_verify_legacy_or_dp_alt_mode`, `tc_phy_get_current_mode`
//!   with `tc_phy_owned_by_display` (display < 20: ready && owned),
//!   `tc_port_fixup_legacy_flag`, `tc_phy_connect`'s default-mode retry
//!   and `adlp_tc_phy_init` (modular FIA: FIA = tc / 2, index = tc % 2).
//! - `intel_display_regs.h` / `intel_mg_phy_regs.h`: `TCSS_DDI_STATUS`
//!   (0x161500 + 4·tc), `_FIA` bases (FIA1 0x163000, FIA2 0x16E000),
//!   `PORT_TX_DFLEXPA1` (+0x880), `DP_PIN_ASSIGNMENT_MASK(idx)`.
//! - `intel_display_power_well.c::xelpdp_aux_power_well_enable` /
//!   `_disable` and `intel_display_power_map.c::xelpdp_power_wells_aux`:
//!   every MTL AUX well (A, B, TC1–TC4) is the
//!   `XELPDP_DP_AUX_CH_CTL_POWER_REQUEST` bit; without an LT PHY the status
//!   bit is not a completion signal and the source waits a fixed 600 µs
//!   after the request (10 µs after release).
//!
//! ## Qualified profile and refusals
//!
//! - DP-alt and VBT-declared legacy modes run the source connect sequence.
//! - Pin D retains a two-lane main-link ceiling and lends only PHY lane 0
//!   to display; PLL/TX/stop callers retain that ownership shape.
//! - Live TBT HPD admits a fabric-owned route without taking the PHY or
//!   requesting TCSS power. Missing live HPD returns TunnelUnavailable.
//! - The TC-cold block itself (`POWER_DOMAIN_TC_COLD_OFF`) maps to no
//!   Xe-LPDP power well; the TCSS power request below is the hardware
//!   side of the block.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::{MmioWindow, AUX_CTL_SEND_BUSY, XELPDP_AUX_CH_CTL_POWER_REQUEST};
use crate::intel_gpu_xelpg::{XeLpgPort, TCSS_POWER_REQUEST, TCSS_POWER_STATE, TC_PHY_OWNERSHIP};
use crate::intel_gpu_xelpg_hpd::{
    pica_dp_alt_hotplug, pica_tbt_hotplug, sde_tc_hotplug, PICA_ISR, SDE_ISR,
};

/// `TCSS_DDI_STATUS(tc)` = `_PICK_EVEN(tc, 0x161500, 0x161504)`.
pub const fn tcss_ddi_status(tc: u8) -> u64 {
    0x16_1500 + 4 * tc as u64
}
/// `TCSS_DDI_STATUS_READY`.
pub const TCSS_DDI_STATUS_READY: u32 = 1 << 2;
/// `_FIA(fia)` for the modular-FIA instance housing `tc`
/// (`tc_phy_load_fia_params(tc, true)`: FIA = tc / 2).
pub const fn fia_base(tc: u8) -> u64 {
    match tc / 2 {
        0 => 0x16_3000,
        1 => 0x16_E000,
        _ => 0x16_F000,
    }
}
/// `PORT_TX_DFLEXPA1(fia)` for `tc`.
pub const fn port_tx_dflexpa1(tc: u8) -> u64 {
    fia_base(tc) + 0x880
}
/// `DP_PIN_ASSIGNMENT_SHIFT(idx)` with idx = tc % 2.
pub const fn pin_assignment_shift(tc: u8) -> u32 {
    (tc as u32 % 2) * 4
}

/// `INTEL_TC_PIN_ASSIGNMENT_NONE`.
pub const PIN_ASSIGNMENT_NONE: u8 = 0;
/// `INTEL_TC_PIN_ASSIGNMENT_C` (4 DP lanes).
pub const PIN_ASSIGNMENT_C: u8 = 3;
/// `INTEL_TC_PIN_ASSIGNMENT_D` (2 DP lanes + USB).
pub const PIN_ASSIGNMENT_D: u8 = 4;
/// `INTEL_TC_PIN_ASSIGNMENT_E` (4 DP lanes, TC→DP cable).
pub const PIN_ASSIGNMENT_E: u8 = 5;

/// `tc_phy_wait_for_ready`: 500 ms.
const PHY_READY_TIMEOUT_NS: u64 = 500_000_000;
/// `xelpdp_tc_phy_wait_for_tcss_power`: 5 ms.
const TCSS_POWER_TIMEOUT_NS: u64 = 5_000_000;
/// `xelpdp_aux_power_well_enable`: fixed 600 µs after the request.
const AUX_POWER_UP_NS: u64 = 600_000;
/// `xelpdp_aux_power_well_disable`: 10 µs after the release.
const AUX_POWER_DOWN_NS: u64 = 10_000;

/// `enum tc_port_mode`, in source order (the HPD live mask uses
/// `BIT(mode)` and `fls` picks the highest).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TcMode {
    /// `TC_PORT_DISCONNECTED`.
    Disconnected = 0,
    /// `TC_PORT_TBT_ALT`.
    TbtAlt = 1,
    /// `TC_PORT_DP_ALT`.
    DpAlt = 2,
    /// `TC_PORT_LEGACY`.
    Legacy = 3,
}

impl TcMode {
    const fn bit(self) -> u32 {
        1 << self as u32
    }
    /// `hpd_mask_to_tc_mode`: the highest set mode, or disconnected.
    pub const fn from_live_mask(mask: u32) -> Self {
        if mask & TcMode::Legacy.bit() != 0 {
            TcMode::Legacy
        } else if mask & TcMode::DpAlt.bit() != 0 {
            TcMode::DpAlt
        } else if mask & TcMode::TbtAlt.bit() != 0 {
            TcMode::TbtAlt
        } else {
            TcMode::Disconnected
        }
    }
}

/// Typed Type-C refusal/failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcError {
    /// The port is not one of TC1–TC4.
    NotTypeC,
    /// Register authority was lost or a status read returned all-ones.
    AccessLost,
    /// No live fabric DP-IN route is present on the Type-C port.
    TunnelUnavailable,
    /// The IOM never reported the PHY ready for a display owner.
    PhyNotReady,
    /// TCSS power did not reach the requested state in 5 ms.
    TcssPowerTimeout,
    /// The DP-alt live status dropped during connect.
    SuddenDisconnect,
    /// The pin assignment carries fewer lanes than required.
    InsufficientLanes {
        /// Lanes the pin assignment provides.
        max: u8,
        /// Lanes the caller required.
        required: u8,
    },
    /// A foreign AUX transaction is in flight on this port.
    AuxBusy,
}

/// A connected (display-owned) Type-C PHY.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TcConnection {
    /// The display port.
    pub port: XeLpgPort,
    /// `enum tc_port` index.
    pub tc: u8,
    /// Connected mode (DP-alt or legacy).
    pub mode: TcMode,
    /// The (possibly live-status-corrected) legacy flag.
    pub legacy_port: bool,
    /// Raw pin assignment (`INTEL_TC_PIN_ASSIGNMENT_*`).
    pub pin_assignment: u8,
    /// Maximum DP lanes this connection provides.
    pub max_lanes: u8,
}

fn read_checked<M: MmioWindow + ?Sized>(io: &M, off: u64) -> Result<u32, TcError> {
    if !io.display_access_ok() {
        return Err(TcError::AccessLost);
    }
    let value = io.read32(off);
    if value == u32::MAX || !io.display_access_ok() {
        return Err(TcError::AccessLost);
    }
    Ok(value)
}

fn rmw<M: MmioWindow + ?Sized>(io: &M, off: u64, clear: u32, set: u32) -> Result<(), TcError> {
    let cur = read_checked(io, off)?;
    io.write32(off, (cur & !clear) | set);
    compiler_fence(Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(TcError::AccessLost)
    }
}

/// Bounded hardware-only poll (no executor bridge); `Err` on lost access.
fn poll_until<M: MmioWindow + ?Sized>(
    io: &M,
    timeout_ns: u64,
    mut done: impl FnMut() -> Result<bool, TcError>,
) -> Result<bool, TcError> {
    let mut failure = None;
    let ok = narf_scheduler::responsive_spin_until(
        || match done() {
            Ok(v) => v,
            Err(e) => {
                failure = Some(e);
                true
            }
        },
        narf_time::Deadline::after_ns(timeout_ns),
    );
    if let Some(e) = failure {
        return Err(e);
    }
    if !io.display_access_ok() {
        return Err(TcError::AccessLost);
    }
    Ok(ok)
}

fn delay_ns(ns: u64) {
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ns(ns));
}

/// `xelpdp_tc_phy_hpd_live_status`: `BIT(mode)` for every live mode.
pub fn live_status_mask<M: MmioWindow + ?Sized>(
    io: &M,
    tc: u8,
    legacy_port: bool,
) -> Result<u32, TcError> {
    let pica = read_checked(io, PICA_ISR)?;
    let sde = read_checked(io, SDE_ISR)?;
    let mut mask = 0;
    if pica & pica_dp_alt_hotplug(tc) != 0 {
        mask |= TcMode::DpAlt.bit();
    }
    if pica & pica_tbt_hotplug(tc) != 0 {
        mask |= TcMode::TbtAlt.bit();
    }
    if legacy_port && sde & sde_tc_hotplug(tc) != 0 {
        mask |= TcMode::Legacy.bit();
    }
    Ok(mask)
}

/// `adlp_tc_phy_is_ready`: an all-ones read is TC-cold, "not ready".
pub fn phy_is_ready<M: MmioWindow + ?Sized>(io: &M, tc: u8) -> Result<bool, TcError> {
    if !io.display_access_ok() {
        return Err(TcError::AccessLost);
    }
    let value = io.read32(tcss_ddi_status(tc));
    if !io.display_access_ok() {
        return Err(TcError::AccessLost);
    }
    Ok(value != u32::MAX && value & TCSS_DDI_STATUS_READY != 0)
}

/// `xelpdp_tc_phy_is_owned`.
pub fn phy_is_owned<M: MmioWindow + ?Sized>(io: &M, port: XeLpgPort) -> Result<bool, TcError> {
    Ok(read_checked(io, port.buf_ctl1())? & TC_PHY_OWNERSHIP != 0)
}

/// `xelpdp_tc_phy_tcss_power_is_enabled`.
pub fn tcss_power_enabled<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
) -> Result<bool, TcError> {
    Ok(read_checked(io, port.buf_ctl1())? & TCSS_POWER_STATE != 0)
}

/// `get_pin_assignment` below display 20: `PORT_TX_DFLEXPA1(fia)` field
/// `DP_PIN_ASSIGNMENT_MASK(fia_idx)`.
pub fn pin_assignment<M: MmioWindow + ?Sized>(io: &M, tc: u8) -> Result<u8, TcError> {
    let value = read_checked(io, port_tx_dflexpa1(tc))?;
    Ok(((value >> pin_assignment_shift(tc)) & 0xF) as u8)
}

/// `get_max_lane_count` for display 14: non-DP-alt modes carry 4 lanes;
/// DP-alt uses `mtl_get_max_lane_count` (NONE 0, C/E 4, D and the
/// MISSING_CASE fallthrough 2).
pub const fn max_lane_count(mode: TcMode, pin_assignment: u8) -> u8 {
    if !matches!(mode, TcMode::DpAlt) {
        return 4;
    }
    match pin_assignment {
        PIN_ASSIGNMENT_NONE => 0,
        PIN_ASSIGNMENT_C | PIN_ASSIGNMENT_E => 4,
        _ => 2,
    }
}

/// `tc_phy_get_current_mode` (display < 20): the mode the PHY is in now,
/// from live status and the ready/owned pair.
pub fn current_mode<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<TcMode, TcError> {
    let tc = port.tc_index().ok_or(TcError::NotTypeC)?;
    let live = TcMode::from_live_mask(live_status_mask(io, tc, legacy_port)?);
    if legacy_port {
        // IOM initializes legacy PHYs at boot/resume regardless of a sink.
        let _ = poll_until(io, PHY_READY_TIMEOUT_NS, || phy_is_ready(io, tc))?;
    }
    let ready = phy_is_ready(io, tc)?;
    let owned = phy_is_owned(io, port)?;
    Ok(if ready && owned {
        match live {
            TcMode::Legacy | TcMode::DpAlt => live,
            _ if legacy_port => TcMode::Legacy,
            _ => TcMode::DpAlt,
        }
    } else {
        match live {
            TcMode::Legacy => TcMode::Disconnected,
            TcMode::DpAlt | TcMode::TbtAlt => TcMode::TbtAlt,
            TcMode::Disconnected if legacy_port => TcMode::Disconnected,
            TcMode::Disconnected => TcMode::TbtAlt,
        }
    })
}

/// `tc_port_fixup_legacy_flag`: with exactly one live mode that the flag
/// cannot produce, trust the live status.
pub const fn fixup_legacy_flag(legacy_port: bool, live_mask: u32) -> bool {
    if live_mask.count_ones() != 1 {
        return legacy_port;
    }
    let valid = if legacy_port {
        TcMode::Legacy.bit()
    } else {
        TcMode::DpAlt.bit() | TcMode::TbtAlt.bit()
    };
    if live_mask & !valid == 0 {
        legacy_port
    } else {
        !legacy_port
    }
}

const fn default_mode(legacy_port: bool) -> TcMode {
    if legacy_port {
        TcMode::Legacy
    } else {
        TcMode::TbtAlt
    }
}

fn set_tcss_power_request<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    enable: bool,
) -> Result<(), TcError> {
    // `__xelpdp_tc_phy_enable_tcss_power` (the display-30 mailbox WA does
    // not apply to display 14).
    if enable {
        rmw(io, port.buf_ctl1(), 0, TCSS_POWER_REQUEST)
    } else {
        rmw(io, port.buf_ctl1(), TCSS_POWER_REQUEST, 0)
    }
}

fn wait_tcss_power<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    enabled: bool,
) -> Result<bool, TcError> {
    poll_until(io, TCSS_POWER_TIMEOUT_NS, || {
        Ok(tcss_power_enabled(io, port)? == enabled)
    })
}

/// `xelpdp_tc_phy_enable_tcss_power`.
fn enable_tcss_power<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    tc: u8,
    enable: bool,
    mode: TcMode,
) -> Result<(), TcError> {
    set_tcss_power_request(io, port, enable)?;
    let failure = if enable && !poll_until(io, PHY_READY_TIMEOUT_NS, || phy_is_ready(io, tc))? {
        TcError::PhyNotReady
    } else if !wait_tcss_power(io, port, enable)? {
        TcError::TcssPowerTimeout
    } else {
        return Ok(());
    };
    // out_disable: a legacy port or a power-down failure leaves the
    // request as is; a failed power-up releases it.
    if mode == TcMode::Legacy || !enable {
        return Err(failure);
    }
    set_tcss_power_request(io, port, false)?;
    let _ = wait_tcss_power(io, port, false)?;
    Err(failure)
}

fn take_ownership<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    take: bool,
) -> Result<(), TcError> {
    if take {
        rmw(io, port.buf_ctl1(), 0, TC_PHY_OWNERSHIP)
    } else {
        rmw(io, port.buf_ctl1(), TC_PHY_OWNERSHIP, 0)
    }
}

/// `xelpdp_tc_phy_connect` for one target mode.
fn connect_mode<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    tc: u8,
    legacy_port: bool,
    mode: TcMode,
    required_lanes: u8,
) -> Result<TcConnection, TcError> {
    match mode {
        TcMode::TbtAlt => {
            // The live PICA bit proves the fabric's DP-IN route; its AUX
            // path and PLL belong to USB4, never to the display PHY owner.
            if live_status_mask(io, tc, legacy_port)? & TcMode::TbtAlt.bit() == 0 {
                return Err(TcError::TunnelUnavailable);
            }
            return Ok(TcConnection {
                port,
                tc,
                mode,
                legacy_port,
                pin_assignment: PIN_ASSIGNMENT_NONE,
                max_lanes: 4,
            });
        }
        TcMode::Disconnected => return Err(TcError::TunnelUnavailable),
        TcMode::DpAlt | TcMode::Legacy => {}
    }
    enable_tcss_power(io, port, tc, true, mode)?;
    take_ownership(io, port, true)?;
    let checked = (|| {
        let pin = pin_assignment(io, tc)?;
        let max_lanes = max_lane_count(mode, pin);
        // `tc_phy_verify_legacy_or_dp_alt_mode`.
        if mode == TcMode::DpAlt {
            if live_status_mask(io, tc, legacy_port)? & TcMode::DpAlt.bit() == 0 {
                return Err(TcError::SuddenDisconnect);
            }
            if max_lanes < required_lanes {
                return Err(TcError::InsufficientLanes {
                    max: max_lanes,
                    required: required_lanes,
                });
            }
        }
        Ok(TcConnection {
            port,
            tc,
            mode,
            legacy_port,
            pin_assignment: pin,
            max_lanes,
        })
    })();
    match checked {
        Ok(conn) => Ok(conn),
        Err(e) => {
            // out_release_phy: release ownership, then wait for the TCSS
            // power state to drop (source does not clear the request here).
            take_ownership(io, port, false)?;
            let _ = wait_tcss_power(io, port, false)?;
            Err(e)
        }
    }
}

/// `tc_phy_connect`: pick the target mode from the live status (after the
/// legacy-flag fixup), run the xelpdp connect, and retry once in the
/// port's default mode on failure. A TBT default is refused, so a DP-alt
/// failure on a Type-C port returns that failure.
pub fn connect<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    legacy_port: bool,
    required_lanes: u8,
) -> Result<TcConnection, TcError> {
    let tc = port.tc_index().ok_or(TcError::NotTypeC)?;
    let mask = live_status_mask(io, tc, legacy_port)?;
    let legacy = fixup_legacy_flag(legacy_port, mask);
    let target = match TcMode::from_live_mask(mask) {
        TcMode::Disconnected => default_mode(legacy),
        mode => mode,
    };
    match connect_mode(io, port, tc, legacy, target, required_lanes) {
        Ok(conn) => Ok(conn),
        Err(TcError::AccessLost) => Err(TcError::AccessLost),
        Err(e) if target != default_mode(legacy) && default_mode(legacy) == TcMode::Legacy => {
            connect_mode(io, port, tc, legacy, TcMode::Legacy, required_lanes).map_err(|_| e)
        }
        Err(e) => Err(e),
    }
}

/// `xelpdp_tc_phy_disconnect` for a display-owned connection: release PHY
/// ownership, then drop the TCSS power request and wait for it to settle.
pub fn disconnect<M: MmioWindow + ?Sized>(io: &M, conn: &TcConnection) -> Result<(), TcError> {
    if conn.mode == TcMode::TbtAlt {
        return if io.display_access_ok() {
            Ok(())
        } else {
            Err(TcError::AccessLost)
        };
    }
    take_ownership(io, conn.port, false)?;
    enable_tcss_power(io, conn.port, conn.tc, false, conn.mode)
}

/// Whether display currently owns the PHY behind `conn` (ready and
/// owned, `tc_phy_owned_by_display`) with its TCSS powered.
pub fn connection_intact<M: MmioWindow + ?Sized>(
    io: &M,
    conn: &TcConnection,
) -> Result<bool, TcError> {
    if conn.mode == TcMode::TbtAlt {
        return Ok(live_status_mask(io, conn.tc, conn.legacy_port)? & TcMode::TbtAlt.bit() != 0);
    }
    Ok(phy_is_ready(io, conn.tc)?
        && phy_is_owned(io, conn.port)?
        && tcss_power_enabled(io, conn.port)?)
}

/// `xelpdp_aux_power_well_enable` (no LT PHY): raise
/// `XELPDP_DP_AUX_CH_CTL_POWER_REQUEST` and wait the fixed 600 µs. A
/// foreign in-flight transaction (SEND_BUSY) is refused rather than
/// re-triggered by the read-modify-write.
pub fn aux_power_enable<M: MmioWindow + ?Sized>(io: &M, port: XeLpgPort) -> Result<(), TcError> {
    let cur = read_checked(io, port.aux_ctl())?;
    if cur & AUX_CTL_SEND_BUSY != 0 {
        return Err(TcError::AuxBusy);
    }
    io.write32(port.aux_ctl(), cur | XELPDP_AUX_CH_CTL_POWER_REQUEST);
    compiler_fence(Ordering::SeqCst);
    delay_ns(AUX_POWER_UP_NS);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(TcError::AccessLost)
    }
}

/// `xelpdp_aux_power_well_disable` (no LT PHY): drop the request, wait
/// 10 µs.
pub fn aux_power_disable<M: MmioWindow + ?Sized>(io: &M, port: XeLpgPort) -> Result<(), TcError> {
    let cur = read_checked(io, port.aux_ctl())?;
    if cur & AUX_CTL_SEND_BUSY != 0 {
        return Err(TcError::AuxBusy);
    }
    io.write32(port.aux_ctl(), cur & !XELPDP_AUX_CH_CTL_POWER_REQUEST);
    compiler_fence(Ordering::SeqCst);
    delay_ns(AUX_POWER_DOWN_NS);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(TcError::AccessLost)
    }
}

/// Whether this port's AUX power request is raised.
pub fn aux_power_requested<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
) -> Result<bool, TcError> {
    Ok(read_checked(io, port.aux_ctl())? & XELPDP_AUX_CH_CTL_POWER_REQUEST != 0)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_tc_tests.rs"]
pub mod tests;

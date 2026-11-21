//! DDI (Digital Display Interface) port programming — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 12 §"Display DDI"**.
//! Cross-checked against ADL / RPL PRMs (same Gen12 surface) and
//! the Meteor Lake display PRM (DDI register block reorganised
//! for Xe-LPG, but the per-port `DDI_BUF_CTL` layout is stable).
//!
//! ## DDI model
//!
//! A DDI is the *physical* port (HDMI / DP / DP-over-USB-C). Each
//! DDI has:
//!
//! - A `DDI_BUF_CTL` register with the port-enable bit, lane
//!   count, and link-up status.
//! - Voltage-swing / pre-emphasis programming, which Gen12 does
//!   NOT do through `DDI_BUF_TRANS` (`has_buf_trans_select` is
//!   DISPLAY_VER < 10): the combo PHY is programmed through
//!   PORT_TX_DW2/DW4/DW5/DW7 in `intel_gpu_gen12_combo_phy`.
//!   (`DDI_BUF_TRANS` registers exist on the DDI block but the
//!   hardware ignores them on Gen12.)
//! - Optionally a `DDI_AUX_CTL` for native DP AUX transactions
//!   (the Stage-2 DP AUX framing in `dp_aux` produces the wire
//!   bytes; this block is the transport).
//!
//! Stage-2 ships the `DDI_BUF_CTL` codec and the lane-count
//! enum. The actual MMIO writes happen in the Stage-3 driver
//! core.

use core::convert::TryFrom;

// ── DDI port identifiers ─────────────────────────────────────────

/// Gen12 DDI port enumeration. PRM Vol. 12 §"Display DDI Port Index".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ddi {
    /// DDI A — typically the eDP panel on mobile parts.
    A = 0,
    /// DDI B — combo PHY (HDMI / DP).
    B = 1,
    /// DDI C — combo PHY.
    C = 2,
    /// DDI D / TC1 — Type-C DP/HDMI on desktop, combo on mobile.
    D = 3,
    /// DDI E / TC2.
    E = 4,
    /// DDI F / TC3.
    F = 5,
    /// DDI G / TC4 (server / desktop SKUs only).
    G = 6,
    /// DDI H / TC5.
    H = 7,
    /// DDI I / TC6 (Tiger Lake only among the qualified Gen12 families).
    I = 8,
}

impl Ddi {
    /// Per-DDI MMIO offset stride. PRM Vol. 12 §"DDI MMIO Map".
    pub const STRIDE: u64 = 0x100;
    /// Base of the per-DDI register block. DDI A is at `0x64000`;
    /// the rest follow at +0x100 each.
    pub const fn base(self) -> u64 {
        0x0006_4000 + (self as u64) * Self::STRIDE
    }
}

// ── DDI_BUF_CTL (TGL PRM Vol. 12 §"DDI_BUF_CTL") ────────────────

/// `DDI_BUF_CTL` offset relative to the DDI base.
pub const DDI_BUF_CTL_OFFSET: u64 = 0x0000;

/// `DDI_BUF_CTL[31]` — buffer enable.
pub const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
/// `DDI_BUF_CTL[7]` — buffer-active read-only status.
pub const DDI_BUF_CTL_IDLE_STATUS: u32 = 1 << 7;

/// Lane count, encoded in `DDI_BUF_CTL[3:1]`. PRM Vol. 12 §"DDI
/// Buffer Programming".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LaneCount {
    /// 1 lane (DP RBR / HDMI single-link).
    X1 = 0b000,
    /// 2 lanes.
    X2 = 0b001,
    /// 4 lanes (DP HBR2 / HBR3 4-lane).
    X4 = 0b011,
}

impl LaneCount {
    pub const fn encode(self) -> u32 {
        (self as u32) << 1
    }
}

/// Build the `DDI_BUF_CTL` value for "enable port with N lanes".
/// Voltage-swing fields are in a separate register; this just
/// programs the top-level enable + lane count.
pub fn build_ddi_buf_ctl(lanes: LaneCount) -> u32 {
    DDI_BUF_CTL_ENABLE | lanes.encode()
}

impl TryFrom<u8> for Ddi {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Ddi::A,
            1 => Ddi::B,
            2 => Ddi::C,
            3 => Ddi::D,
            4 => Ddi::E,
            5 => Ddi::F,
            6 => Ddi::G,
            7 => Ddi::H,
            8 => Ddi::I,
            _ => return Err(()),
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ddi_base_strides() -> TestResult {
        if Ddi::A.base() != 0x64000 {
            return TestResult::Fail("DDI A base wrong");
        }
        if Ddi::B.base() != 0x64100 {
            return TestResult::Fail("DDI B base wrong");
        }
        if Ddi::I.base() != 0x64800 || Ddi::try_from(8) != Ok(Ddi::I) {
            return TestResult::Fail("DDI I / TC6 identity wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_ddi", smoke_ddi_base_strides);

    fn smoke_buf_ctl_encoding() -> TestResult {
        let v = build_ddi_buf_ctl(LaneCount::X4);
        if v & DDI_BUF_CTL_ENABLE == 0 {
            return TestResult::Fail("buf enable not asserted");
        }
        if (v >> 1) & 0x7 != 0b011 {
            return TestResult::Fail("4-lane encoding wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_ddi", smoke_buf_ctl_encoding);
}

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
//! - A `DDI_BUF_TRANS` table programming the analog voltage-swing
//!   and pre-emphasis coefficients (per HBR rate, per swing
//!   level).
//! - Optionally a `DDI_AUX_CTL` for native DP AUX transactions
//!   (the Stage-2 DP AUX framing in `dp_aux` produces the wire
//!   bytes; this block is the transport).
//!
//! Stage-2 ships the `DDI_BUF_CTL` codec, the lane-count enum,
//! and the documented DP HBR voltage-swing table. The actual
//! MMIO writes happen in the Stage-3 driver core.

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
/// `DDI_BUF_TRANS_LO[N]` offset for swing-table entry N (each
/// entry is 8 bytes: low + high dword).
pub const DDI_BUF_TRANS_BASE_OFFSET: u64 = 0x0010;

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

// ── DDI_BUF_TRANS — DP voltage-swing / pre-emphasis ──────────────
//
// Source: TGL PRM Vol. 12 §"DDI Buffer Translation Tables for DP".
//
// The PRM publishes voltage-swing / pre-emphasis coefficient
// tables per link rate (RBR 1.62, HBR 2.7, HBR2 5.4, HBR3 8.1
// Gbps). Each entry is two 32-bit words written to
// `DDI_BUF_TRANS_LO/HI[N]`.
//
// The values below are the Combo-PHY HBR2 default table for
// Tiger Lake — the *most-conservative* set the PRM documents.
// Real hardware works through the table from index 0 (lowest
// swing) upward when DP link training requests escalation.
// Per-product board files override these for non-default trace
// lengths; the table here is the public-default fallback.

/// One DP voltage-swing / pre-emphasis pair.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpBufTrans {
    pub lo: u32,
    pub hi: u32,
}

/// HBR2 swing table for Combo PHY DDIs on Tiger Lake. PRM Vol. 12
/// §"DP HBR2 — DDI Buffer Translation".
///
/// Index ↔ DPCD voltage-swing levels:
/// 0 → 400 mV   no  pre-emphasis
/// 1 → 600 mV   3.5 dB pre-emphasis
/// 2 → 800 mV   6.0 dB pre-emphasis
/// 3 → 1200 mV  0.0 dB pre-emphasis (max swing, used for long traces)
pub const HBR2_BUF_TRANS: [DpBufTrans; 4] = [
    DpBufTrans {
        lo: 0x0000_00A2,
        hi: 0x0000_0018,
    },
    DpBufTrans {
        lo: 0x0000_00A4,
        hi: 0x0000_0034,
    },
    DpBufTrans {
        lo: 0x0000_00A2,
        hi: 0x0000_0030,
    },
    DpBufTrans {
        lo: 0x0000_0034,
        hi: 0x0000_0030,
    },
];

/// HBR3 swing table for Combo PHY DDIs on Tiger Lake. PRM Vol. 12
/// §"DP HBR3 — DDI Buffer Translation".
pub const HBR3_BUF_TRANS: [DpBufTrans; 4] = [
    DpBufTrans {
        lo: 0x0000_00A1,
        hi: 0x0000_0019,
    },
    DpBufTrans {
        lo: 0x0000_00A3,
        hi: 0x0000_0035,
    },
    DpBufTrans {
        lo: 0x0000_00A1,
        hi: 0x0000_0031,
    },
    DpBufTrans {
        lo: 0x0000_0033,
        hi: 0x0000_0030,
    },
];

/// Resolve the swing table for a DP link rate.
pub fn dp_buf_trans_table(link_bw_set: u8) -> Option<&'static [DpBufTrans; 4]> {
    // `link_bw_set` is the DPCD value (0x06 = RBR, 0x0A = HBR,
    // 0x14 = HBR2, 0x1E = HBR3). Source: VESA DP 1.4a §2.9.3.2.
    match link_bw_set {
        0x14 => Some(&HBR2_BUF_TRANS),
        0x1E => Some(&HBR3_BUF_TRANS),
        _ => None,
    }
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

    fn smoke_buf_trans_table_resolution() -> TestResult {
        if dp_buf_trans_table(0x14).is_none() {
            return TestResult::Fail("HBR2 not resolved");
        }
        if dp_buf_trans_table(0x1E).is_none() {
            return TestResult::Fail("HBR3 not resolved");
        }
        if dp_buf_trans_table(0xFF).is_some() {
            return TestResult::Fail("unknown rate must be None");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ddi",
        smoke_buf_trans_table_resolution
    );
}

//! Per-family MTU policy for igb (82575/82576/82580/I350/I210/I211) —
//! issue #802.
//!
//! Grounding (never fabricated; see the PR body for the citations):
//!
//! * MAX_MTU 9216 / max frame 9234 — kernel.org `Documentation/networking/
//!   device_drivers/ethernet/intel/igb.rst`: "maximum MTU 9216 ... maximum
//!   Jumbo Frames size of 9234". The 9234 figure is the *untagged* wire
//!   size (MTU + 18); the RX acceptance limit programmed into RLPML is
//!   MTU + 22 = 9238, which is exactly what the sibling igc driver
//!   programs (`igc/src/igc/hardware.rs`: `r.write(0x5004, mtu + 14 + 4
//!   + 4)`; its fixture pins `m.value(0x5004) == 9238` at MTU 9216).
//! * RLPML is the RX length limit register at offset `0x5004` (same
//!   register as igc's; VMOLR's RLPML field is the per-VF shadow of
//!   the same limit — in-tree `vmdq.rs` `VMOLR_RLPML_MASK 0x3FFF`).
//! * Linux igb additionally clamps the VMOLR SET_LPE path to
//!   `MAX_JUMBO_FRAME_SIZE 0x2600 = 9728` (the absolute hardware max);
//!   the driver-advertised max is 9234, so 9216 is the MTU envelope
//!   here. The in-tree `igb.md` spec notes that tighter clamp as an
//!   open remainder; it is not needed for the PF path this lane
//!   programs.
//! * RCTL.BSIZE 16K for jumbo (Linux `igb_setup_rctl` workaround:
//!   the controller does not receive jumbo frames unless the RCTL
//!   buffer-size field is 16K when jumbo is in use); SRRCTL.BSIZEPKT
//!   is the operative per-queue buffer size for advanced descriptors
//!   (Linux `igb_setup_srrctl`).
//!
//! Buffer sizing is fixed-at-max at probe: RX/TX pools allocate
//! 10240-byte slots (`round_up(9238, 1024)`) once, so an MTU change
//! never reallocates — it only reprograms RCTL.BSIZE, SRRCTL.BSIZEPKT
//! and RLPML, then stores the MTU. A jumbo frame therefore always has
//! a buffer waiting for it. Memory cost: 256 RX slots × (10240 − 2048)
//! ≈ 2 MiB extra DMA (TX ring is 8 slots, negligible).

use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimum Ethernet MTU (RFC 791 / Linux `ETH_MIN_MTU`).
pub const MIN_MTU: u32 = 68;

/// Standard (non-jumbo) MTU — the probe-time default.
pub const STD_MTU: u32 = 1500;

/// Maximum MTU on every igb part (82575/82576/82580/I350/I210/I211).
pub const MAX_MTU: u32 = 9216;

/// Maximum untagged wire frame at the max MTU (MTU + 18: DA+SA+type+CRC).
pub const MAX_FRAME: u32 = MAX_MTU + 18;

/// Maximum RX acceptance at the max MTU (MTU + 22: one VLAN tag inline).
pub const MAX_RX_FRAME: u32 = MAX_MTU + 22;

/// RX/TX buffer size: the max RX frame rounded up to the 1 KiB
/// SRRCTL.BSIZEPKT step. 10240 covers 9238 with headroom.
pub const RX_BUF_BYTES: usize = 10_240;
pub const TX_BUF_BYTES: usize = 10_240;

/// Untagged wire frame for a programmed MTU (what the TX cap enforces).
pub const fn frame_size(mtu: u32) -> u32 {
    mtu + 18
}

/// RX acceptance for a programmed MTU (what RLPML programs): the frame
/// plus one inline VLAN tag.
pub const fn rx_frame_size(mtu: u32) -> u32 {
    mtu + 22
}

/// SRRCTL.BSIZEPKT value (1 KiB units) for a frame size. The unit
/// is the register's `SRRCTL_BSIZEPKT_SHIFT` (10) — one source of
/// truth for the 1024-byte step, shared with the SRRCTL program in
/// `igb.rs`.
pub const fn srrctl_bsize(frame: u32) -> u32 {
    frame.div_ceil(1 << super::SRRCTL_BSIZEPKT_SHIFT)
}

/// RLPML program value for a programmed MTU: same as `rx_frame_size`.
pub const fn rlpml(mtu: u32) -> u32 {
    rx_frame_size(mtu)
}

/// MTU program: everything `set_mtu` writes, derived once from the
/// requested MTU so the register writes and the stored state cannot
/// drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuProgram {
    /// Programmed MTU (payload bytes).
    pub mtu: u32,
    /// TX cap (untagged wire frame): `mtu + 18`.
    pub frame: u32,
    /// RX acceptance (RLPML): `mtu + 22`.
    pub rx_frame: u32,
    /// SRRCTL.BSIZEPKT (1 KiB units) for `rx_frame`.
    pub srrctl_bsize: u32,
    /// RCTL.BSIZE 16K (vs 2K) — set for any jumbo MTU.
    pub rctl_16k: bool,
}

/// MTU validation failure (a plain errno, so the hook can return it
/// to the stack without allocating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuError(pub i32);

/// Validate an MTU request and derive its register program.
/// Pure: no MMIO, no allocation — safe to call before touching HW.
pub const fn mtu_transition(mtu: u32) -> Result<MtuProgram, MtuError> {
    if mtu < MIN_MTU {
        return Err(MtuError(22)); // EINVAL
    }
    if mtu > MAX_MTU {
        return Err(MtuError(22)); // EINVAL
    }
    let frame = frame_size(mtu);
    let rx_frame = rx_frame_size(mtu);
    Result::Ok(MtuProgram {
        mtu,
        frame,
        rx_frame,
        srrctl_bsize: srrctl_bsize(rx_frame),
        rctl_16k: mtu > STD_MTU,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smoke_mtu_range_boundaries() -> TestResult {
        // Below-minimum and above-maximum are EINVAL (22).
        if mtu_transition(67).is_ok() {
            return TestResult::Fail("igb MTU 67 accepted below the 68 floor");
        }
        if mtu_transition(9217).is_ok() {
            return TestResult::Fail("igb MTU 9217 accepted above the 9216 cap");
        }
        // The endpoints themselves are valid.
        if mtu_transition(MIN_MTU).is_err() || mtu_transition(MAX_MTU).is_err() {
            return TestResult::Fail("igb MTU endpoints 68 / 9216 rejected");
        }
        // Standard MTU is the probe default and is in range.
        if mtu_transition(STD_MTU).is_err() {
            return TestResult::Fail("igb MTU 1500 rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_mtu_range_boundaries);

    fn smoke_mtu_program_shapes() -> TestResult {
        // Standard MTU: TX cap 1518, RX acceptance 1522, SRRCTL 2K,
        // RCTL 2K (no 16K bit).
        let std = match mtu_transition(1500) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb MTU 1500 rejected"),
        };
        if std.frame != 1518 || std.rx_frame != 1522 || std.srrctl_bsize != 2 || std.rctl_16k {
            return TestResult::Fail("igb MTU 1500 program shape drifted");
        }
        // Max MTU: TX cap 9234 (the documented max frame), RX
        // acceptance 9238 (igc's pinned RLPML value at 9216),
        // SRRCTL 10 (10240), RCTL 16K.
        let max = match mtu_transition(9216) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb MTU 9216 rejected"),
        };
        if max.frame != 9234 || max.rx_frame != 9238 || max.srrctl_bsize != 10 || !max.rctl_16k {
            return TestResult::Fail("igb MTU 9216 program shape drifted");
        }
        // Any jumbo MTU flips RCTL to 16K, even one just above 1500.
        let jumbo = match mtu_transition(1501) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("igb MTU 1501 rejected"),
        };
        if !jumbo.rctl_16k || jumbo.srrctl_bsize != 2 {
            return TestResult::Fail("igb MTU 1501 program shape drifted");
        }
        // Buffers cover the max RX frame with headroom.
        if RX_BUF_BYTES < MAX_RX_FRAME as usize || TX_BUF_BYTES < MAX_FRAME as usize {
            return TestResult::Fail("igb buffers do not cover the max frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_mtu_program_shapes);
}

//! Per-family MTU policy for i40e (X710/XL710/XXV710/X722) — issue #802.
//!
//! Grounding (never fabricated; see the PR body for the citations):
//!
//! * MAX_MTU 9706 / max frame 9728 — current kernel
//!   `Documentation/networking/device_drivers/ethernet/intel/i40e.rst`
//!   and the idpf doc: 9706 = 9728 − 22. (An older kernel.org RST
//!   doc prints 9702; that is a stale-doc bug — 9706 is the driver
//!   value, 9728 − 22.)
//! * `rxmax` is the RX queue context's largest-frame field and
//!   `dbuff` counts 128-byte units — in-tree `ring.rs`
//!   `pack_rx_context` (`dbuff = buf_bytes >> 7`, `rxmax =
//!   max_frame`). At the max MTU, rxmax = 9706 + 22 = 9728 and
//!   dbuff = 9728 / 128 = 76.
//! * The TX small-cache sizing follows the same envelope: a normal
//!   (non-TSO) frame is at most the MTU's wire size, so the
//!   per-descriptor copy buffer is the max RX frame (9728); TSO
//!   super-frames keep their separate 64 KiB large cache.
//!
//! Buffer sizing is fixed-at-max at probe: RX buffers and TX small
//! caches allocate 9728-byte slots once, so an MTU change never
//! reallocates — it only rewrites the RX queue contexts' `rxmax`
//! (queue disable → context rewrite → enable), then stores the MTU.
//! Memory cost: 64 RX slots × (9728 − 2048) ≈ 480 KiB + 64 TX small
//! slots × (9728 − 2048) ≈ 480 KiB per queue pair (~1 MiB).

use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimum Ethernet MTU (RFC 791 / Linux `ETH_MIN_MTU`).
pub const MIN_MTU: u32 = 68;

/// Standard (non-jumbo) MTU — the probe-time default.
pub const STD_MTU: u32 = 1500;

/// Maximum MTU on every i40e part (X710/XL710/XXV710/X722).
pub const MAX_MTU: u32 = 9706;

/// Maximum RX frame at the max MTU (`rxmax`): MTU + 22 (one VLAN
/// tag inline). 9706 + 22 = 9728, the documented max frame.
pub const MAX_FRAME: u32 = MAX_MTU + 22;

/// RX/TX buffer size: the max RX frame, exactly 76 × 128-byte
/// `dbuff` units. No rounding needed.
pub const RX_BUF_BYTES: usize = 9728;
pub const TX_BUF_BYTES: usize = 9728;

/// `dbuff` units (128 bytes each) for a buffer size.
pub const fn dbuff_units(buf_bytes: u32) -> u32 {
    buf_bytes >> 7
}

/// Untagged wire frame for a programmed MTU (TX cap): MTU + 18.
pub const fn frame_size(mtu: u32) -> u32 {
    mtu + 18
}

/// RX acceptance (`rxmax`) for a programmed MTU: MTU + 22.
pub const fn rx_frame_size(mtu: u32) -> u32 {
    mtu + 22
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
    /// RX acceptance (`rxmax`): `mtu + 22`.
    pub rx_frame: u32,
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
    Result::Ok(MtuProgram {
        mtu,
        frame: frame_size(mtu),
        rx_frame: rx_frame_size(mtu),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smoke_mtu_range_boundaries() -> TestResult {
        // Below-minimum and above-maximum are EINVAL (22).
        if mtu_transition(67).is_ok() {
            return TestResult::Fail("i40e MTU 67 accepted below the 68 floor");
        }
        if mtu_transition(9707).is_ok() {
            return TestResult::Fail("i40e MTU 9707 accepted above the 9706 cap");
        }
        // The endpoints themselves are valid.
        if mtu_transition(MIN_MTU).is_err() || mtu_transition(MAX_MTU).is_err() {
            return TestResult::Fail("i40e MTU endpoints 68 / 9706 rejected");
        }
        // Standard MTU is the probe default and is in range.
        if mtu_transition(STD_MTU).is_err() {
            return TestResult::Fail("i40e MTU 1500 rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_mtu_range_boundaries);

    fn smoke_mtu_program_shapes() -> TestResult {
        // Standard MTU: TX cap 1518, rxmax 1522, dbuff 76 (the
        // fixed-at-max buffer, not the 1500 frame).
        let std = match mtu_transition(1500) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("i40e MTU 1500 rejected"),
        };
        if std.frame != 1518 || std.rx_frame != 1522 {
            return TestResult::Fail("i40e MTU 1500 program shape drifted");
        }
        // Max MTU: TX cap 9724, rxmax 9728 (the documented max
        // frame), dbuff 76.
        let max = match mtu_transition(9706) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("i40e MTU 9706 rejected"),
        };
        if max.frame != 9724 || max.rx_frame != 9728 {
            return TestResult::Fail("i40e MTU 9706 program shape drifted");
        }
        if dbuff_units(RX_BUF_BYTES as u32) != 76 || dbuff_units(TX_BUF_BYTES as u32) != 76 {
            return TestResult::Fail("i40e dbuff is not 76 units at the max frame");
        }
        // Buffers cover the max RX frame exactly.
        if RX_BUF_BYTES < MAX_FRAME as usize || TX_BUF_BYTES < MAX_FRAME as usize {
            return TestResult::Fail("i40e buffers do not cover the max frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_mtu_program_shapes);
}

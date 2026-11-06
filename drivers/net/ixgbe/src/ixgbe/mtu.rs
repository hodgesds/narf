//! Per-family MTU policy for ixgbe (82599/X540/X550/E610) — issue #802.
//!
//! Grounding (never fabricated; see the PR body for the citations):
//!
//! * MAX_MTU 9710 / max frame 9728 — kernel.org
//!   `Documentation/networking/device_drivers/ethernet/intel/ixgbe.rst`:
//!   "maximum MTU 9710 ... maximum Jumbo Frames size of 9728". The
//!   9728 figure is MTU + 18 (DA+SA+type+CRC); MAXFRS programs
//!   exactly that (MTU + 18), and the in-tree constant agrees:
//!   `vmdq.rs` `MAX_JUMBO_FRAME = 9728` (`IXGBE_MAX_JUMBO_FRAME_SIZE`).
//! * MAXFRS register 0x04268, MFS bits 31:16, shift 16 — in-tree
//!   `vmdq.rs` `REG_MAXFRS`, `MAXFRS_MFS_MASK`, `MAXFRS_MFS_SHIFT`;
//!   the SET_LPE mailbox handler already programs it as
//!   `max_frame << MAXFRS_MFS_SHIFT` (full write; low bits reserved).
//! * SRRCTL.BSIZEPKT is in 1 KiB units (in-tree `SRRCTL_BSIZE_2K = 2`,
//!   the 2 KiB program at bring-up); the value goes in unshifted.
//!
//! Buffer sizing is fixed-at-max at probe: RX/TX pools allocate
//! 10240-byte slots (`round_up(9732, 1024)`) once, so an MTU change
//! never reallocates — it only reprograms MAXFRS + per-queue SRRCTL,
//! then stores the MTU. Memory cost: 32 RX slots × (10240 − 4096)
//! ≈ 192 KiB per queue (TX ring is 32 slots, same order).

use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimum Ethernet MTU (RFC 791 / Linux `ETH_MIN_MTU`).
pub const MIN_MTU: u32 = 68;

/// Standard (non-jumbo) MTU — the probe-time default.
pub const STD_MTU: u32 = 1500;

/// Maximum MTU on every ixgbe part (82599/X540/X550/E610).
pub const MAX_MTU: u32 = 9710;

/// Maximum untagged wire frame at the max MTU (MTU + 18).
pub const MAX_FRAME: u32 = MAX_MTU + 18;

/// Maximum RX frame at the max MTU (MTU + 22: one VLAN tag inline).
/// Buffer sizing only — MAXFRS programs `frame_size` (MTU + 18).
pub const MAX_RX_FRAME: u32 = MAX_MTU + 22;

/// RX/TX buffer size: the max RX frame rounded up to the 1 KiB
/// SRRCTL.BSIZEPKT step. 10240 covers 9732 with headroom.
pub const RX_BUF_BYTES: usize = 10_240;
pub const TX_BUF_BYTES: usize = 10_240;

/// Untagged wire frame for a programmed MTU (TX cap and MAXFRS value).
pub const fn frame_size(mtu: u32) -> u32 {
    mtu + 18
}

/// RX frame for a programmed MTU (buffer sizing): the frame plus one
/// inline VLAN tag.
pub const fn rx_frame_size(mtu: u32) -> u32 {
    mtu + 22
}

/// SRRCTL.BSIZEPKT value (1 KiB units) for a frame size.
pub const fn srrctl_bsize(frame: u32) -> u32 {
    frame.div_ceil(1024)
}

/// MAXFRS program word for a programmed MTU: `(mtu + 18) << 16`
/// (MFS bits 31:16; low bits reserved, written zero — the same
/// full-write shape the SET_LPE handler already uses).
pub const fn maxfrs(mtu: u32) -> u32 {
    frame_size(mtu) << 16
}

/// MTU program: everything `set_mtu` writes, derived once from the
/// requested MTU so the register writes and the stored state cannot
/// drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuProgram {
    /// Programmed MTU (payload bytes).
    pub mtu: u32,
    /// TX cap and MAXFRS value (untagged wire frame): `mtu + 18`.
    pub frame: u32,
    /// RX frame (buffer sizing): `mtu + 22`.
    pub rx_frame: u32,
    /// SRRCTL.BSIZEPKT (1 KiB units) for `rx_frame`.
    pub srrctl_bsize: u32,
    /// MAXFRS program word.
    pub maxfrs: u32,
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
        maxfrs: maxfrs(mtu),
    })
}

mod tests {
    use super::*;

    fn smoke_mtu_range_boundaries() -> TestResult {
        // Below-minimum and above-maximum are EINVAL (22).
        if mtu_transition(67).is_ok() {
            return TestResult::Fail("ixgbe MTU 67 accepted below the 68 floor");
        }
        if mtu_transition(9711).is_ok() {
            return TestResult::Fail("ixgbe MTU 9711 accepted above the 9710 cap");
        }
        // The endpoints themselves are valid.
        if mtu_transition(MIN_MTU).is_err() || mtu_transition(MAX_MTU).is_err() {
            return TestResult::Fail("ixgbe MTU endpoints 68 / 9710 rejected");
        }
        // Standard MTU is the probe default and is in range.
        if mtu_transition(STD_MTU).is_err() {
            return TestResult::Fail("ixgbe MTU 1500 rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/ixgbe", smoke_mtu_range_boundaries);

    fn smoke_mtu_program_shapes() -> TestResult {
        // Standard MTU: TX cap 1518, MAXFRS 1518<<16, SRRCTL 2K.
        let std = match mtu_transition(1500) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ixgbe MTU 1500 rejected"),
        };
        if std.frame != 1518
            || std.rx_frame != 1522
            || std.srrctl_bsize != 2
            || std.maxfrs != 1518 << 16
        {
            return TestResult::Fail("ixgbe MTU 1500 program shape drifted");
        }
        // Max MTU: TX cap 9728 (the documented max frame and the
        // in-tree MAX_JUMBO_FRAME), MAXFRS 9728<<16, SRRCTL 10.
        let max = match mtu_transition(9710) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ixgbe MTU 9710 rejected"),
        };
        if max.frame != 9728
            || max.rx_frame != 9732
            || max.srrctl_bsize != 10
            || max.maxfrs != 9728 << 16
        {
            return TestResult::Fail("ixgbe MTU 9710 program shape drifted");
        }
        // Buffers cover the max RX frame with headroom.
        if RX_BUF_BYTES < MAX_RX_FRAME as usize || TX_BUF_BYTES < MAX_FRAME as usize {
            return TestResult::Fail("ixgbe buffers do not cover the max frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/ixgbe", smoke_mtu_program_shapes);
}

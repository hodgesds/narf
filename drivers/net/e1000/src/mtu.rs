//! Jumbo-frame MTU programming for the e1000/e1000e family (issue #802).
//!
//! Pure MTU policy: no MMIO, no allocation, so the fixtures below pin the
//! policy without silicon. The live wiring lives in [`crate::e1000`]
//! (`E1000::set_mtu`, the `DeviceControl` hook, the RCTL program).
//!
//! # Limits (grounded, not guessed)
//!
//! * Floor 68 everywhere: `ETH_MIN_MTU` (`ether_setup` default; igc
//!   already uses `68..=MAX_MTU`).
//! * Classic 82540/82544/82545 (`e1000` driver): max MTU **16110**,
//!   max frame **16128** — kernel.org `Documentation/networking/e1000.txt`:
//!   "The maximum MTU setting for Jumbo Frames is 16110. This value
//!   coincides with the maximum Jumbo Frames size of 16128."
//! * e1000e parts (82574L, I217/I218/I219 PCH): max MTU **9000**,
//!   max frame **9022** — the e1000e driver's `mtu + VLAN_ETH_HLEN +
//!   ETH_FCS_LEN` (`+22`) accounting against `max_hw_frame_size` 9022.
//!   The published e1000e doc still prints the pre-fix pair 8996/9018;
//!   the 2015 netdev thread ("e1000e: Cleanup handling of VLAN_HLEN as
//!   a part of max frame size") bumped the PCH `max_hw_frame_size`
//!   9018 to 9022, i.e. MTU 9000 under the `+22` accounting, and the
//!   fix's own text confirms "setting an MTU of 9000" for the PCH
//!   series.
//! * Remainder: 82574L may support a larger frame via e1000e's
//!   `DEFAULT_JUMBO` (`0x3F00`) path — the in-tree 82574 datasheet
//!   summary states no jumbo maximum, so this lane caps 82574L at the
//!   documented e1000e family envelope (9000) rather than claiming
//!   16K. Raising it needs a datasheet/`e1000e.h` citation, not a
//!   guess.
//!
//! # Buffer sizing
//!
//! RCTL.BSIZE only offers 2048 / 1024 / 512 / 16384, so any jumbo MTU
//! needs the 16K step: RX and TX buffers are 16384 bytes, sized for
//! the family's largest frame (16128 classic). RCTL.LPE (bit 5) gates
//! long-packet acceptance on 8254x/e1000e alike; both the BSIZE step
//! and LPE follow the *programmed* MTU, while the buffers stay fixed
//! at the max — the same shape as igc's `MAX_MTU + 22` RX sizing and
//! r8169's fixed 16K RMS (merged #1385).

use crate::e1000::{E1000_DEV_82540EM, E1000_DEV_82544GC, E1000_DEV_82545EM};

/// Smallest MTU any Ethernet driver accepts (`ETH_MIN_MTU`).
pub const MIN_MTU: u32 = 68;

/// Standard MTU; jumbo is anything above this.
pub const STD_MTU: u32 = 1500;

/// Largest MTU on the classic 82540/82544/82545 parts (Linux `e1000`).
pub const CLASSIC_MAX_MTU: u32 = 16110;

/// Largest MTU on the e1000e parts (82574L, I217/I218/I219 PCH).
pub const E1000E_MAX_MTU: u32 = 9000;

/// RX buffer bytes per descriptor: covers the classic max frame
/// (16128) with the RCTL.BSIZE 16K step. Allocated once at probe.
pub const RX_BUF_BYTES: usize = 16384;

/// TX copy-buffer bytes per descriptor slot: covers the classic max
/// frame, so a jumbo TX copy always fits its slot.
pub const TX_BUF_BYTES: usize = 16384;

/// `true` for the classic 8254x parts (Linux `e1000` driver); every
/// other ID this driver binds is an e1000e part.
pub const fn is_classic(did: u16) -> bool {
    matches!(
        did,
        E1000_DEV_82540EM | E1000_DEV_82545EM | E1000_DEV_82544GC
    )
}

/// Largest MTU for `did`.
pub const fn max_mtu(did: u16) -> u32 {
    if is_classic(did) {
        CLASSIC_MAX_MTU
    } else {
        E1000E_MAX_MTU
    }
}

/// TX wire size for `mtu`: MTU + ETH_HLEN + ETH_FCS_LEN.
pub const fn frame_size(mtu: u32) -> u32 {
    mtu + 14 + 4
}

/// RX acceptance size for `mtu`: MTU + VLAN_ETH_HLEN + ETH_FCS_LEN
/// (one VLAN tag inline). Used for the flow-control watermarks: the
/// largest frame that can arrive after XOFF must fit the RX FIFO.
pub const fn rx_frame_size(mtu: u32) -> u32 {
    mtu + 14 + 4 + 4
}

/// A validated MTU change, ready to program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtuProgram {
    /// The MTU the stack asked for.
    pub mtu: u32,
    /// TX wire cap for this MTU (`frame_size(mtu)`).
    pub frame: u32,
    /// RX acceptance size for this MTU (`rx_frame_size(mtu)`).
    pub rx_frame: u32,
    /// Whether the RCTL program needs the 16K buffer step + LPE.
    pub jumbo: bool,
}

/// Why an MTU change was refused. The hook maps this to EINVAL (22)
/// before any register is touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuError {
    /// Outside `MIN_MTU..=max_mtu(did)`.
    OutOfRange,
}

/// Validate `mtu` for `did` and build the program for it. Pure: the
/// caller programs hardware only on `Ok`.
pub const fn mtu_transition(did: u16, mtu: u32) -> Result<MtuProgram, MtuError> {
    if mtu < MIN_MTU || mtu > max_mtu(did) {
        return Err(MtuError::OutOfRange);
    }
    Ok(MtuProgram {
        mtu,
        frame: frame_size(mtu),
        rx_frame: rx_frame_size(mtu),
        jumbo: mtu > STD_MTU,
    })
}

mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    fn smoke_mtu_range_boundaries() -> TestResult {
        // Classic 82540EM: 67 rejects, 68 accepts, 16110 accepts,
        // 16111 rejects.
        if mtu_transition(E1000_DEV_82540EM, 67).is_ok()
            || mtu_transition(E1000_DEV_82540EM, 68).is_err()
            || mtu_transition(E1000_DEV_82540EM, 16110).is_err()
            || mtu_transition(E1000_DEV_82540EM, 16111).is_ok()
        {
            return TestResult::Fail("e1000 classic MTU range wrong");
        }
        // e1000e PCH (I219LM): 9000 accepts, 9001 rejects.
        if mtu_transition(crate::e1000::E1000E_DEV_I219LM, 9000).is_err()
            || mtu_transition(crate::e1000::E1000E_DEV_I219LM, 9001).is_ok()
        {
            return TestResult::Fail("e1000e MTU range wrong");
        }
        // 82574L sits in the e1000e envelope until the DEFAULT_JUMBO
        // question is settled with a citation (see module docs).
        if mtu_transition(crate::e1000::E1000E_DEV_82574L, 9000).is_err()
            || mtu_transition(crate::e1000::E1000E_DEV_82574L, 9001).is_ok()
        {
            return TestResult::Fail("e1000 82574L MTU range wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_mtu_range_boundaries);

    fn smoke_mtu_program_shapes() -> TestResult {
        // Standard MTU: no jumbo program, +18 TX / +22 RX.
        let std = match mtu_transition(E1000_DEV_82540EM, 1500) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("e1000 MTU 1500 rejected"),
        };
        if std.jumbo || std.frame != 1518 || std.rx_frame != 1522 {
            return TestResult::Fail("e1000 standard-MTU program wrong");
        }
        // Jumbo boundary: 1501 is jumbo, 9000 on classic is a 9018
        // TX frame with a 9022 RX acceptance.
        let j = match mtu_transition(E1000_DEV_82540EM, 9000) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("e1000 MTU 9000 rejected"),
        };
        if !j.jumbo || j.frame != 9018 || j.rx_frame != 9022 {
            return TestResult::Fail("e1000 jumbo program wrong");
        }
        // Classic ceiling: 16110 -> 16128 TX, 16132 RX, both inside
        // the 16384-byte buffers.
        let top = match mtu_transition(E1000_DEV_82540EM, 16110) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("e1000 MTU 16110 rejected"),
        };
        if top.frame != 16128
            || top.rx_frame != 16132
            || top.frame as usize > RX_BUF_BYTES
            || top.frame as usize > TX_BUF_BYTES
        {
            return TestResult::Fail("e1000 classic-ceiling program wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/e1000", smoke_mtu_program_shapes);
}

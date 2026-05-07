//! F1 chip-clock control register (`SBSDIO_FUNC1_CHIPCLKCSR`).
//!
//! Reference: **CYW43439 datasheet Rev. 03 §6.5 Table 6-7**. The
//! host gates the chip's ALP / HT / ILP clocks during firmware load
//! by writing this byte at F1 address `0x1000E` (see
//! [`super::sdio::F1_CHIPCLK_CTRL`]). The mirror status bits
//! report when the requested clock has actually become available.
//!
//! Cross-checked against `soypat/cyw43439` (MIT) and Embassy
//! `cyw43` (Apache-2.0 / MIT). **No GPL `brcmfmac` / `bcmdhd`
//! source consulted.**

/// Force ALP-clock-available request.
pub const FORCE_ALP_REQ: u8 = 0x01;
/// Force HT-clock-available request.
pub const FORCE_HT_REQ: u8 = 0x02;
/// Force ILP-clock request.
pub const FORCE_ILP_REQ: u8 = 0x04;
/// Status: ALP clock is available to the chip.
pub const ALP_AVAIL: u8 = 0x40;
/// Status: HT clock is available to the chip.
pub const HT_AVAIL: u8 = 0x80;

/// Mask of the request bits the host writes (low nibble).
pub const REQ_MASK: u8 = FORCE_ALP_REQ | FORCE_HT_REQ | FORCE_ILP_REQ;
/// Mask of the status bits the host reads (high nibble).
pub const STATUS_MASK: u8 = ALP_AVAIL | HT_AVAIL;

/// Decoded view of a CHIPCLK_CTRL byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockState {
    pub force_alp: bool,
    pub force_ht: bool,
    pub force_ilp: bool,
    pub alp_avail: bool,
    pub ht_avail: bool,
}

impl ClockState {
    pub fn from_reg(reg: u8) -> Self {
        Self {
            force_alp: reg & FORCE_ALP_REQ != 0,
            force_ht: reg & FORCE_HT_REQ != 0,
            force_ilp: reg & FORCE_ILP_REQ != 0,
            alp_avail: reg & ALP_AVAIL != 0,
            ht_avail: reg & HT_AVAIL != 0,
        }
    }

    pub fn to_reg(self) -> u8 {
        (if self.force_alp { FORCE_ALP_REQ } else { 0 })
            | (if self.force_ht { FORCE_HT_REQ } else { 0 })
            | (if self.force_ilp { FORCE_ILP_REQ } else { 0 })
            | (if self.alp_avail { ALP_AVAIL } else { 0 })
            | (if self.ht_avail { HT_AVAIL } else { 0 })
    }
}

/// F1 sleep / wake control register (`SBSDIO_FUNC1_SLEEPCSR`,
/// datasheet §6.5 Table 6-7, F1 address `0x1000F`).
pub mod sleep {
    /// Keep-SDIO-on bit — host writes to keep the SDIO core powered
    /// while the rest of the chip is asleep.
    pub const KSO: u8 = 0x01;
    /// Mirror of [`KSO`] read back from the chip — used to confirm
    /// the chip honoured the host's KSO request.
    pub const KSO_STATUS: u8 = 0x02;
    /// Device-on bit — set by the chip once the SOC has booted.
    pub const DEV_ON: u8 = 0x04;
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_clockstate_round_trip() -> TestResult {
        // ALP requested + HT available is the typical mid-bring-up
        // state the loader observes between request and HT-up.
        let s = ClockState {
            force_alp: true,
            force_ht: false,
            force_ilp: false,
            alp_avail: true,
            ht_avail: false,
        };
        let reg = s.to_reg();
        if reg != (FORCE_ALP_REQ | ALP_AVAIL) {
            return TestResult::Fail("ClockState reg encoding wrong");
        }
        if ClockState::from_reg(reg) != s {
            return TestResult::Fail("ClockState round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/chipclk",
        smoke_clockstate_round_trip
    );

    fn smoke_request_status_disjoint() -> TestResult {
        if REQ_MASK & STATUS_MASK != 0 {
            return TestResult::Fail("request and status masks overlap");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/chipclk",
        smoke_request_status_disjoint
    );
}

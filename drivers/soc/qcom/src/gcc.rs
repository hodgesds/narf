//! Global Clock Controller: the reset and branch-clock bits the WCSS
//! remoteproc and the WiFi block use.
//!
//! A narrowly scoped provider rather than a clock framework: per-SoC
//! tables keyed by the DT binding index (`include/dt-bindings/{reset,clock}/
//! qcom,gcc-ipq*.h`), with values verbatim from Linux `gcc-ipq8074.c`,
//! `gcc-ipq6018.c`, `gcc-ipq5018.c`.
//!
//! - Resets (`drivers/clk/qcom/reset.c`): assert = set `BIT(bit)` in
//!   `reg`, deassert = clear it, each followed by a read-back.
//! - Branch clocks (`clk-branch.c`, `clk_branch2_ops`): enable sets
//!   `enable_mask` in `enable_reg`; a `BRANCH_HALT_VOTED` branch is then
//!   polled until `CBCR_CLK_OFF` (bit 31 of `halt_reg`) clears (≤ 200 µs,
//!   sleeping); disabling a voted branch waits 10 µs instead.
//!
//! Tables carry only the WCSS/WiFi entries; a DT index outside them is
//! refused ([`GccError::UnknownIndex`]), never guessed.

use crate::io::{poll_reg, Delay, RegIo};

/// `CBCR_CLK_OFF`.
pub const CBCR_CLK_OFF: u32 = 1 << 31;
/// `clk_branch_wait` poll budget for enabling (µs).
pub const BRANCH_HALT_TIMEOUT_US: u32 = 200;

/// GCC failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GccError {
    /// The DT binding index is not in this SoC's table.
    UnknownIndex(u32),
    /// A voted branch did not report on (`CLK_OFF` stuck at 1).
    BranchStuckOff { halt_reg: u32, value: u32 },
}

/// `struct qcom_reset_map` entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResetEntry {
    pub index: u32,
    pub reg: u32,
    pub bit: u8,
}

/// `struct clk_branch` (subset).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BranchEntry {
    pub index: u32,
    pub enable_reg: u32,
    pub enable_mask: u32,
    pub halt_reg: u32,
    pub voted: bool,
}

/// Per-SoC GCC tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GccDesc {
    pub compatible: &'static str,
    pub resets: &'static [ResetEntry],
    pub branches: &'static [BranchEntry],
}

/// dt-bindings indices (`reset/qcom,gcc-ipq6018.h`, `clock/qcom,gcc-ipq8074.h`, ...).
pub mod idx {
    pub const GCC_WCSS_BCR: u32 = 22;
    pub const GCC_WCSS_Q6_BCR: u32 = 23;
    pub const IPQ6018_GCC_WCSSAON_RESET: u32 = 127;
    pub const IPQ5018_GCC_WCSS_BCR: u32 = 100;
    pub const IPQ5018_GCC_WCSS_Q6_BCR: u32 = 108;
    pub const IPQ5018_GCC_WCSSAON_RESET: u32 = 109;
    pub const IPQ8074_GCC_PRNG_AHB_CLK: u32 = 40;
    pub const IPQ6018_GCC_PRNG_AHB_CLK: u32 = 136;
}

/// `gcc_prng_ahb_clk` — identical on IPQ8074/IPQ6018/IPQ5018.
const fn prng(index: u32) -> BranchEntry {
    BranchEntry {
        index,
        enable_reg: 0x0b004,
        enable_mask: 1 << 8,
        halt_reg: 0x13004,
        voted: true,
    }
}

/// `gcc-ipq8074.c`. Linux has no `GCC_WCSSAON_RESET` entry for IPQ8074
/// (and no `remoteproc` node in `ipq8074.dtsi`); a board DT naming one is
/// refused.
pub const IPQ8074: GccDesc = GccDesc {
    compatible: "qcom,gcc-ipq8074",
    resets: &[
        ResetEntry {
            index: idx::GCC_WCSS_BCR,
            reg: 0x18000,
            bit: 0,
        },
        ResetEntry {
            index: idx::GCC_WCSS_Q6_BCR,
            reg: 0x18100,
            bit: 0,
        },
    ],
    branches: &[prng(idx::IPQ8074_GCC_PRNG_AHB_CLK)],
};

/// `gcc-ipq6018.c`.
pub const IPQ6018: GccDesc = GccDesc {
    compatible: "qcom,gcc-ipq6018",
    resets: &[
        ResetEntry {
            index: idx::GCC_WCSS_BCR,
            reg: 0x18000,
            bit: 0,
        },
        ResetEntry {
            index: idx::GCC_WCSS_Q6_BCR,
            reg: 0x18100,
            bit: 0,
        },
        ResetEntry {
            index: idx::IPQ6018_GCC_WCSSAON_RESET,
            reg: 0x59010,
            bit: 0,
        },
    ],
    branches: &[prng(idx::IPQ6018_GCC_PRNG_AHB_CLK)],
};

/// `gcc-ipq5018.c`.
pub const IPQ5018: GccDesc = GccDesc {
    compatible: "qcom,gcc-ipq5018",
    resets: &[
        ResetEntry {
            index: idx::IPQ5018_GCC_WCSS_BCR,
            reg: 0x18000,
            bit: 0,
        },
        ResetEntry {
            index: idx::IPQ5018_GCC_WCSS_Q6_BCR,
            reg: 0x18004,
            bit: 0,
        },
        ResetEntry {
            index: idx::IPQ5018_GCC_WCSSAON_RESET,
            reg: 0x59010,
            bit: 0,
        },
    ],
    branches: &[],
};

/// Every supported GCC.
pub const ALL: [&GccDesc; 3] = [&IPQ8074, &IPQ6018, &IPQ5018];

/// The table for a GCC node's compatible list.
pub fn desc_for(compatibles: &[alloc::string::String]) -> Option<&'static GccDesc> {
    ALL.iter()
        .copied()
        .find(|d| compatibles.iter().any(|c| c == d.compatible))
}

/// A reset line the remoteproc toggles (`reset_control_{assert,deassert}`).
pub trait ResetLine {
    fn assert(&self);
    fn deassert(&self);
}

/// A GCC instance over its register window.
#[derive(Debug)]
pub struct Gcc<R: RegIo> {
    regs: R,
    desc: &'static GccDesc,
}

impl<R: RegIo> Gcc<R> {
    pub fn new(regs: R, desc: &'static GccDesc) -> Self {
        Self { regs, desc }
    }

    pub fn desc(&self) -> &'static GccDesc {
        self.desc
    }

    fn reset_entry(&self, index: u32) -> Result<ResetEntry, GccError> {
        self.desc
            .resets
            .iter()
            .copied()
            .find(|e| e.index == index)
            .ok_or(GccError::UnknownIndex(index))
    }

    /// `qcom_reset_set_assert`.
    pub fn set_reset(&self, index: u32, assert: bool) -> Result<(), GccError> {
        let e = self.reset_entry(index)?;
        let mask = 1u32 << e.bit;
        self.regs
            .update32(e.reg, mask, if assert { mask } else { 0 });
        let _ = self.regs.read32(e.reg);
        Ok(())
    }

    /// A [`ResetLine`] handle for one index (validated now).
    pub fn reset_line(&self, index: u32) -> Result<GccReset<'_, R>, GccError> {
        self.reset_entry(index)?;
        Ok(GccReset { gcc: self, index })
    }

    fn branch(&self, index: u32) -> Result<BranchEntry, GccError> {
        self.desc
            .branches
            .iter()
            .copied()
            .find(|b| b.index == index)
            .ok_or(GccError::UnknownIndex(index))
    }

    /// `clk_branch2_enable` + `clk_branch_wait(enabling)`.
    pub async fn enable_branch<D: Delay + ?Sized>(
        &self,
        index: u32,
        delay: &D,
    ) -> Result<(), GccError> {
        let b = self.branch(index)?;
        self.regs
            .update32(b.enable_reg, b.enable_mask, b.enable_mask);
        if b.voted {
            poll_reg(
                &self.regs,
                delay,
                b.halt_reg,
                |v| v & CBCR_CLK_OFF == 0,
                1,
                BRANCH_HALT_TIMEOUT_US,
            )
            .await
            .map_err(|value| GccError::BranchStuckOff {
                halt_reg: b.halt_reg,
                value,
            })?;
        }
        Ok(())
    }

    /// `clk_branch2_disable` (+ the 10 µs voted-branch settle).
    pub async fn disable_branch<D: Delay + ?Sized>(
        &self,
        index: u32,
        delay: &D,
    ) -> Result<(), GccError> {
        let b = self.branch(index)?;
        self.regs.update32(b.enable_reg, b.enable_mask, 0);
        if b.voted {
            delay.sleep_us(10).await;
        }
        Ok(())
    }
}

/// One GCC reset line.
#[derive(Debug)]
pub struct GccReset<'a, R: RegIo> {
    gcc: &'a Gcc<R>,
    index: u32,
}

impl<R: RegIo> ResetLine for GccReset<'_, R> {
    fn assert(&self) {
        let _ = self.gcc.set_reset(self.index, true);
    }
    fn deassert(&self) {
        let _ = self.gcc.set_reset(self.index, false);
    }
}

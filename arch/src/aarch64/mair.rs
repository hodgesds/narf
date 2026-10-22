//! `MAIR_EL1` layout — the memory-attribute indices stage-1 descriptors
//! select through `AttrIndx` (bits 4:2).
//!
//! The attribute *encodings* are Linux's (`arch/arm64/include/asm/sysreg.h`
//! `MAIR_ATTR_*`). The *indices* are NARF's, because three of them predate
//! this table and every existing descriptor (boot.S block maps, Device
//! ioremaps, MTE-tagged domain heaps) encodes them:
//!
//! | Idx | NARF                  | Encoding | Linux index (`memory.h`) |
//! | --- | --------------------- | -------- | ------------------------ |
//! | 0   | Normal WB             | `0xFF`   | `MT_NORMAL` = 0          |
//! | 1   | Device-nGnRE          | `0x04`   | `MT_DEVICE_nGnRE` = 4    |
//! | 2   | Normal WB Tagged      | `0xF0`   | `MT_NORMAL_TAGGED` = 1   |
//! | 3   | Normal Non-cacheable  | `0x44`   | `MT_NORMAL_NC` = 2       |
//! | 4   | Device-nGnRnE         | `0x00`   | `MT_DEVICE_nGnRnE` = 3   |
//!
//! Normal is index 0 for the reason Linux gives in `memory.h`: page-table
//! code composes a leaf as `default | caller_flags`, and an index field
//! cannot be OR-ed, so the default must contribute nothing to bits 4:2.
//!
//! `frame/src/aarch64/boot.S` (BSP) and `smp_entry.S` (each AP) program
//! [`MAIR_EL1_VALUE`] with `movz`/`movk`; the kernel test below compares
//! the live register against this constant on the running CPU.

#![cfg(target_arch = "aarch64")]

/// Linux `MAIR_ATTR_NORMAL`: Normal, Inner/Outer Write-Back Non-transient,
/// Read/Write-Allocate.
pub const MAIR_ATTR_NORMAL: u64 = 0xFF;
/// Linux `MAIR_ATTR_DEVICE_nGnRE`.
pub const MAIR_ATTR_DEVICE_NGNRE: u64 = 0x04;
/// Linux `MAIR_ATTR_NORMAL_TAGGED`: Normal WB with MTE allocation tags.
pub const MAIR_ATTR_NORMAL_TAGGED: u64 = 0xF0;
/// Linux `MAIR_ATTR_NORMAL_NC`: Normal, Inner/Outer Non-cacheable. The
/// target of Linux `pgprot_writecombine`; permits speculation, unaligned
/// access and write merging, but never allocates in a cache.
pub const MAIR_ATTR_NORMAL_NC: u64 = 0x44;
/// Linux `MAIR_ATTR_DEVICE_nGnRnE`: the target of `pgprot_noncached`.
pub const MAIR_ATTR_DEVICE_NGNRNE: u64 = 0x00;

pub const ATTR_IDX_NORMAL: u64 = 0;
pub const ATTR_IDX_DEVICE_NGNRE: u64 = 1;
pub const ATTR_IDX_NORMAL_TAGGED: u64 = 2;
pub const ATTR_IDX_NORMAL_NC: u64 = 3;
pub const ATTR_IDX_DEVICE_NGNRNE: u64 = 4;

/// Linux `MAIR_ATTRIDX(attr, idx)`.
pub const fn attridx(attr: u64, idx: u64) -> u64 {
    attr << (idx * 8)
}

/// The value both boot.S and smp_entry.S write: `0x0000_0000_44F0_04FF`.
pub const MAIR_EL1_VALUE: u64 = attridx(MAIR_ATTR_NORMAL, ATTR_IDX_NORMAL)
    | attridx(MAIR_ATTR_DEVICE_NGNRE, ATTR_IDX_DEVICE_NGNRE)
    | attridx(MAIR_ATTR_NORMAL_TAGGED, ATTR_IDX_NORMAL_TAGGED)
    | attridx(MAIR_ATTR_NORMAL_NC, ATTR_IDX_NORMAL_NC)
    | attridx(MAIR_ATTR_DEVICE_NGNRNE, ATTR_IDX_DEVICE_NGNRNE);

/// The attribute byte `MAIR_EL1_VALUE` holds at `idx`.
pub const fn attr_at(mair: u64, idx: u64) -> u64 {
    (mair >> (idx * 8)) & 0xFF
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The constant keeps every pre-existing index bit-identical and adds
    /// Linux's Normal-NC and Device-nGnRnE encodings.
    fn smoke_mair_layout() -> TestResult {
        if MAIR_EL1_VALUE != 0x44F0_04FF {
            return TestResult::Fail("MAIR_EL1_VALUE is not 0x44F004FF");
        }
        // The low three bytes are the pre-NC value: existing descriptors
        // (Normal, Device-nGnRE, Tagged) decode exactly as before.
        if MAIR_EL1_VALUE & 0xFF_FFFF != 0xF0_04FF {
            return TestResult::Fail("indices 0..=2 changed");
        }
        if attr_at(MAIR_EL1_VALUE, ATTR_IDX_NORMAL_NC) != MAIR_ATTR_NORMAL_NC
            || attr_at(MAIR_EL1_VALUE, ATTR_IDX_DEVICE_NGNRNE) != MAIR_ATTR_DEVICE_NGNRNE
        {
            return TestResult::Fail("NC / nGnRnE slots wrong");
        }
        TestResult::Pass
    }

    /// The running CPU's `MAIR_EL1` is the constant. MAIR is per-PE: the
    /// BSP sets it in boot.S, each AP in smp_entry.S, and a CPU that missed
    /// the new bytes would decode a Normal-NC user leaf through a zero
    /// (Device-nGnRnE) or stale attribute.
    fn smoke_mair_live_matches() -> TestResult {
        // SAFETY: MRS MAIR_EL1 at EL1.
        let live = unsafe { crate::aarch64::sysreg::read_mair_el1() };
        if live != MAIR_EL1_VALUE {
            return TestResult::Fail("live MAIR_EL1 differs from MAIR_EL1_VALUE");
        }
        TestResult::Pass
    }

    kernel_test_in!("arch/mair", smoke_mair_layout);
    kernel_test_in!("arch/mair", smoke_mair_live_matches);
}

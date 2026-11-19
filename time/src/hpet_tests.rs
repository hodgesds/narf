//! Register-window regressions. These exercise the production programmer
//! against private aligned RAM, without touching the live HPET singleton.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn device(regs: &mut [u64; 128], channels: u8) -> Hpet {
    Hpet {
        base_phys: regs.as_mut_ptr() as u64,
        caps: HpetCaps {
            rev_id: 1,
            num_comparators: channels,
            counter_64bit: true,
            legacy_route_cap: true,
            vendor_id: 0x1022,
            clk_period_fs: 69_841_279,
        },
    }
}

fn hpet_takeover_quiesces_inherited_channels() -> TestResult {
    let mut regs = [0u64; 128];
    regs[REG_GEN_CONF as usize / 8] = GEN_CONF_ENABLE_CNF | GEN_CONF_LEGACY_CNF;
    regs[REG_MAIN_CNT as usize / 8] = 123456;
    let inherited = (0x00c00000 << 32)
        | TN_FSB_INT_DEL_CAP
        | TN_SIZE_CAP
        | TN_PER_INT_CAP
        | TN_TYPE_CNF_PERIODIC
        | TN_INT_ENB_CNF
        | TN_INT_TYPE_CNF
        | TN_FSB_EN_CNF
        | (22 << TN_INT_ROUTE_CNF_SHIFT);
    for n in 0..3 {
        regs[(REG_TIMER_BASE + n * REG_TIMER_STRIDE) as usize / 8] = inherited;
    }
    let h = device(&mut regs, 3);
    // SAFETY: this test exclusively owns the aligned register backing array.
    unsafe { h.take_over() };
    if regs[REG_GEN_CONF as usize / 8] != GEN_CONF_ENABLE_CNF
        || regs[REG_MAIN_CNT as usize / 8] != 123456
    {
        return TestResult::Fail("takeover retained legacy routing or changed the counter");
    }
    for n in 0..3 {
        let cfg = regs[(REG_TIMER_BASE + n * REG_TIMER_STRIDE) as usize / 8];
        if cfg != inherited & !(TN_INT_ENB_CNF | TN_INT_TYPE_CNF | TN_FSB_EN_CNF) {
            return TestResult::Fail(
                "takeover left an inherited channel enabled or lost capabilities",
            );
        }
    }
    // RAM records the W1C write, not the hardware-cleared value.
    if regs[REG_INT_STS as usize / 8] != 0b111 {
        return TestResult::Fail("takeover did not acknowledge every inherited channel");
    }
    TestResult::Pass
}
kernel_test_in!("time/hpet", hpet_takeover_quiesces_inherited_channels);

fn hpet_msi_oneshot_replaces_legacy_periodic_route() -> TestResult {
    for wide in [false, true] {
        let mut regs = [0u64; 128];
        let config = REG_TIMER_BASE as usize / 8;
        regs[config] = (0x00c00000 << 32)
            | TN_FSB_INT_DEL_CAP
            | TN_PER_INT_CAP
            | if wide { TN_SIZE_CAP } else { 0 }
            | TN_TYPE_CNF_PERIODIC
            | TN_VAL_SET_CNF
            | TN_INT_ENB_CNF
            | TN_INT_TYPE_CNF
            | (22 << TN_INT_ROUTE_CNF_SHIFT);
        let deadline = (1u64 << 32) + 8192;
        regs[REG_MAIN_CNT as usize / 8] = deadline - 4096;
        let h = device(&mut regs, 1);
        // SAFETY: private RAM window; no real IRQ delivery occurs.
        let result = unsafe { h.arm_oneshot_msi_checked(0, 0xfee07000, 84, deadline) };
        let cfg = regs[config];
        if result != Ok(())
            || cfg & (TN_FSB_EN_CNF | TN_INT_ENB_CNF) != TN_FSB_EN_CNF | TN_INT_ENB_CNF
            || cfg
                & (TN_INT_TYPE_CNF | TN_TYPE_CNF_PERIODIC | TN_VAL_SET_CNF | TN_INT_ROUTE_CNF_MASK)
                != 0
        {
            return TestResult::Fail(
                "MSI one-shot retained legacy/periodic routing or was not enabled",
            );
        }
        if regs[(REG_TIMER_BASE + TIMER_REG_FSB_ROUTE) as usize / 8] != (0xfee07000u64 << 32) | 84
            || regs[(REG_TIMER_BASE + TIMER_REG_COMPARATOR) as usize / 8]
                != if wide { deadline } else { 8192 }
            || (cfg & TN_32MODE_CNF != 0) == wide
            || regs[REG_INT_STS as usize / 8] != 1
        {
            return TestResult::Fail(
                "MSI address/data, comparator width or status acknowledgement differs",
            );
        }
        // The IOAPIC fallback must also remove FSB mode when reusing a channel.
        // SAFETY: same private window; the advertised route includes GSI 23.
        unsafe { h.arm_oneshot_comparator(0, 23, deadline) };
        if regs[config] & TN_FSB_EN_CNF != 0
            || regs[config] & TN_INT_TYPE_CNF == 0
            || regs[config] & TN_INT_ROUTE_CNF_MASK != 23 << TN_INT_ROUTE_CNF_SHIFT
        {
            return TestResult::Fail("IOAPIC fallback retained MSI or selected the wrong GSI");
        }
    }
    TestResult::Pass
}
kernel_test_in!("time/hpet", hpet_msi_oneshot_replaces_legacy_periodic_route);

fn hpet_msi_oneshot_rejects_unsupported_and_expired() -> TestResult {
    let mut regs = [0u64; 128];
    let h = device(&mut regs, 1);
    for n in [0, 1] {
        // SAFETY: private RAM window; invalid routes must fail without writes.
        if unsafe { h.arm_oneshot_msi_checked(n, 0xfee00000, 84, 4096) }
            != Err(ArmError::BadComparator)
            || regs.iter().any(|&v| v != 0)
        {
            return TestResult::Fail("unsupported MSI comparator was programmed");
        }
    }
    for wide in [false, true] {
        regs[REG_TIMER_BASE as usize / 8] = TN_FSB_INT_DEL_CAP | if wide { TN_SIZE_CAP } else { 0 };
        regs[REG_MAIN_CNT as usize / 8] = 8192;
        for deadline in [8000, 8192, 8192 + MIN_PROG_TICKS - 1] {
            // SAFETY: private register array; exercises the production -ETIME check.
            if unsafe { h.arm_oneshot_msi_checked(0, 0xfee00000, 84, deadline) }
                != Err(ArmError::Expired)
            {
                return TestResult::Fail("expired MSI deadline was accepted");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/hpet",
    hpet_msi_oneshot_rejects_unsupported_and_expired
);

#[cfg(test)]
#[test]
fn host_hpet_register_regressions() {
    for run in [
        hpet_takeover_quiesces_inherited_channels,
        hpet_msi_oneshot_replaces_legacy_periodic_route,
        hpet_msi_oneshot_rejects_unsupported_and_expired,
    ] {
        assert_eq!(run(), TestResult::Pass);
    }
}

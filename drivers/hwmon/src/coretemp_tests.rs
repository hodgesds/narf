//! Admission models exercise the production probe without executing an MSR.
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::{read_supported_msr, MSR_IA32_THERM_STATUS, MSR_TEMPERATURE_TARGET};

fn probe(
    vendor: &[u8; 12],
    max_leaf: u32,
    leaf1_edx: u32,
    leaf6_eax: u32,
    index: u32,
    msr: Option<u64>,
) -> (Option<u64>, u32, u32) {
    let queries = Cell::new(0u32);
    let reads = Cell::new(0u32);
    let result = read_supported_msr(
        index,
        |leaf| {
            queries.set(queries.get() | (1 << leaf));
            match leaf {
                0 => (
                    max_leaf,
                    u32::from_le_bytes(vendor[..4].try_into().unwrap()),
                    u32::from_le_bytes(vendor[8..].try_into().unwrap()),
                    u32::from_le_bytes(vendor[4..8].try_into().unwrap()),
                ),
                1 => (0, 0, 0, leaf1_edx),
                6 => (leaf6_eax, 0, 0, 0),
                _ => (0, 0, 0, 0),
            }
        },
        |actual| {
            reads.set(reads.get() + 1);
            if actual == index {
                msr
            } else {
                None
            }
        },
    );
    (result, queries.get(), reads.get())
}

fn coretemp_non_intel_never_queries_thermal_or_reads_msr() -> TestResult {
    for vendor in [b"AuthenticAMD", b"HygonGenuine", b"UnknownCPU12"] {
        let result = probe(
            vendor,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            MSR_TEMPERATURE_TARGET,
            Some(100 << 16),
        );
        if result != (None, 1, 0) {
            return TestResult::Fail("non-Intel CPU reached a thermal leaf or MSR read");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/coretemp",
    coretemp_non_intel_never_queries_thermal_or_reads_msr
);

fn coretemp_requires_supported_leaf_and_thermal_features() -> TestResult {
    for (max, msr_bit, thermal, queries) in [
        (0, 1 << 5, 1, 1),
        (5, 1 << 5, 1, 1),
        (6, 0, 1, 3),
        (6, 1 << 5, 0, 67),
    ] {
        if probe(
            b"GenuineIntel",
            max,
            msr_bit,
            thermal,
            MSR_TEMPERATURE_TARGET,
            Some(100 << 16),
        ) != (None, queries, 0)
        {
            return TestResult::Fail("missing CPU leaf or feature did not stop before MSR access");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/coretemp",
    coretemp_requires_supported_leaf_and_thermal_features
);

fn coretemp_supported_and_unreadable_msrs_remain_distinct() -> TestResult {
    for index in [MSR_TEMPERATURE_TARGET, MSR_IA32_THERM_STATUS] {
        if probe(b"GenuineIntel", 6, 1 << 5, 1, index, None) != (None, 67, 1) {
            return TestResult::Fail("unreadable optional thermal MSR was accepted");
        }
        if probe(b"GenuineIntel", 6, 1 << 5, 1, index, Some(0x8064_0000))
            != (Some(0x8064_0000), 67, 1)
        {
            return TestResult::Fail("supported thermal MSR was not read exactly once");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/coretemp",
    coretemp_supported_and_unreadable_msrs_remain_distinct
);

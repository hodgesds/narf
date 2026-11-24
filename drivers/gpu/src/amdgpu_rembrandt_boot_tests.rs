use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Linux's `amdgpu_device_ip_init` order as the stage list encodes it: the SMU
/// (GFXOFF disallowed) first, VMID0 and the GART before IH and every engine,
/// golden settings before SDMA, the SDMA0 proof and its trap before the
/// production queues, the rings before the IB tests, fences after the proofs,
/// and each stage exactly once.
fn rembrandt_boot_stage_order_follows_linux() -> TestResult {
    let at = |s: Stage| STAGES.iter().position(|&x| x == s).unwrap();
    let before = |a, b| at(a) < at(b);
    let unique = STAGES
        .iter()
        .enumerate()
        .all(|(i, s)| !STAGES[..i].contains(s));
    if !unique
        || at(Stage::Smu) != 0
        || !before(Stage::MemoryHubs, Stage::Gart)
        || !before(Stage::Gart, Stage::Interrupts)
        || !before(Stage::Interrupts, Stage::GoldenSettings)
        || !before(Stage::GoldenSettings, Stage::SdmaTest)
        || !before(Stage::SdmaTest, Stage::InterruptTest)
        || !before(Stage::InterruptTest, Stage::SdmaQueues)
        || !before(Stage::Doorbells, Stage::GfxSetup)
        || !before(Stage::Kiq, Stage::ComputeQueues)
        || !before(Stage::ComputeQueues, Stage::GfxRing)
        || !before(Stage::SdmaQueues, Stage::IbTests)
        || !before(Stage::IbTests, Stage::FenceInterrupts)
        || STAGES[STAGES.len() - 1] != Stage::ReadTopology
    {
        return TestResult::Fail("Rembrandt cold-boot stage order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rembrandt-boot",
    rembrandt_boot_stage_order_follows_linux
);

/// A GPU that is not Rembrandt is refused before any owner reserves memory.
fn rembrandt_boot_refuses_other_gpus_before_allocation() -> TestResult {
    let gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let available = pool.available();
    let addr = narf_bus::PcieAddr::new(0, 0xc4, 0, 0);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
        id: narf_bus::DeviceId {
            vendor: 0x1002,
            device: 0x73df,
            class: 0x030000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
    };
    // SAFETY: inert fixture mappings; the identity check precedes any I/O.
    let result = unsafe { ColdBoot::new(&gpu, Cap::bootstrap(), &pool, device) };
    if !matches!(result, Err(Error::Invalid)) || pool.available() != available {
        return TestResult::Fail("Rembrandt cold boot accepted another GPU or allocated first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rembrandt-boot",
    rembrandt_boot_refuses_other_gpus_before_allocation
);

/// The boot's discovery line names each inferred block's instance-0
/// version in a fixed order, and `-` for a block discovery did not list,
/// so a first boot on Rembrandt reads as a confirmation or a refutation.
fn rembrandt_discovery_line_names_the_inferred_versions() -> TestResult {
    use crate::amdgpu_discovery::{self as d, IpBlock};
    let ip = |hw_id, (major, minor, revision), instance| IpBlock {
        hw_id,
        instance,
        major,
        minor,
        revision,
        sub_revision: 0,
        variant: 0,
        base_addrs: [0; d::MAX_BASE_ADDRS],
        num_bases: 0,
    };
    let blocks = [
        ip(d::HW_ID_SMUIO, (13, 0, 3), 0),
        ip(d::HW_ID_NBIF, (7, 2, 1), 0),
        ip(d::HW_ID_MMHUB, (2, 9, 9), 1),
        ip(d::HW_ID_MMHUB, (2, 3, 0), 0),
        ip(d::HW_ID_OSSSYS, (5, 2, 1), 0),
        ip(d::HW_ID_HDP, (5, 2, 1), 0),
    ];
    if discovery_line(&blocks)
        != "amdgpu: rembrandt discovery: NBIF 7.2.1 MMHUB 2.3.0 ATHUB - OSSSYS 5.2.1 HDP 5.2.1 SMUIO 13.0.3"
    {
        return TestResult::Fail("the discovery line's order, instance or absent marker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rembrandt-boot",
    rembrandt_discovery_line_names_the_inferred_versions
);

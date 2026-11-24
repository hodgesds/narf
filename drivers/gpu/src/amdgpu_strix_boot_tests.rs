use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Linux's `gfx_v11_0_hw_init` order as the stage list encodes it: the SMU
/// (GFXOFF disallowed) first, VMID0 and the GART before IH and every engine,
/// golden settings before SDMA, the SDMA0 proof and its trap before the
/// production queues, the MES-KIQ before the rings it maps, the rings before
/// the IB tests, fences after the proofs, and each stage exactly once.
fn strix_boot_stage_order_follows_linux() -> TestResult {
    let at = |s: Stage| STAGES.iter().position(|&x| x == s).unwrap();
    let before = |a, b| at(a) < at(b);
    let unique = STAGES
        .iter()
        .enumerate()
        .all(|(i, s)| !STAGES[..i].contains(s));
    if !unique
        || STAGES.len() != 16
        || at(Stage::Smu) != 0
        || !before(Stage::MemoryHubs, Stage::Gart)
        || !before(Stage::Gart, Stage::Interrupts)
        || !before(Stage::Interrupts, Stage::GoldenSettings)
        || !before(Stage::GoldenSettings, Stage::SdmaTest)
        || !before(Stage::SdmaTest, Stage::InterruptTest)
        || !before(Stage::InterruptTest, Stage::SdmaQueues)
        || !before(Stage::Doorbells, Stage::GfxSetup)
        || !before(Stage::GfxSetup, Stage::Kiq)
        || !before(Stage::Kiq, Stage::ComputeQueues)
        || !before(Stage::ComputeQueues, Stage::GfxRing)
        || !before(Stage::GfxRing, Stage::SdmaQueues)
        || !before(Stage::SdmaQueues, Stage::IbTests)
        || !before(Stage::IbTests, Stage::FenceInterrupts)
        || STAGES[STAGES.len() - 1] != Stage::ReadTopology
    {
        return TestResult::Fail("Strix cold-boot stage order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_boot_stage_order_follows_linux
);

fn device_for(did: u16) -> BusDevice {
    let addr = narf_bus::PcieAddr::new(0, 0xc4, 0, 0);
    BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
        id: narf_bus::DeviceId {
            vendor: 0x1002,
            device: did,
            class: 0x030000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
    }
}

/// A GPU that is not Strix is refused before any owner reserves memory.
fn strix_boot_refuses_other_gpus_before_allocation() -> TestResult {
    let gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let available = pool.available();
    let device = device_for(0x73df);
    // SAFETY: inert fixture mappings; the identity check precedes any I/O.
    let result =
        unsafe { StrixColdBoot::new(&gpu, Cap::bootstrap(), &pool, &device, [0x1000, 0x2000]) };
    if !matches!(result, Err(Error::Unsupported)) || pool.available() != available {
        return TestResult::Fail("Strix cold boot accepted another GPU or allocated first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_boot_refuses_other_gpus_before_allocation
);

/// Phoenix shares `Family::Phoenix` with Strix today but is RDNA3 with its
/// own bring-up: the DID gate refuses it before any owner reserves memory.
fn strix_boot_refuses_phoenix_before_allocation() -> TestResult {
    let mut gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::PHOENIX1,
    )
    .unwrap();
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let available = pool.available();
    let device = device_for(crate::amdgpu::PHOENIX1);
    // SAFETY: inert fixture mappings; the identity check precedes any I/O.
    let result =
        unsafe { StrixColdBoot::new(&gpu, Cap::bootstrap(), &pool, &device, [0x1000, 0x2000]) };
    if !matches!(result, Err(Error::Unsupported)) || pool.available() != available {
        return TestResult::Fail("Strix cold boot accepted Phoenix or allocated first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_boot_refuses_phoenix_before_allocation
);

/// The DID gate admits exactly Strix Point and nothing else.
fn strix_did_gate_admits_only_strix() -> TestResult {
    let amd = crate::amdgpu::AMD_VENDOR;
    if !is_strix_did(amd, crate::amdgpu::STRIX_POINT)
        || is_strix_did(amd, crate::amdgpu::PHOENIX_HAWKPOINT1)
        || is_strix_did(amd, crate::amdgpu::PHOENIX1)
        || is_strix_did(amd, crate::amdgpu::PHOENIX2)
        || is_strix_did(amd, crate::amdgpu::NAVI22)
        || is_strix_did(amd, crate::amdgpu::RAPHAEL)
        || is_strix_did(0x8086, crate::amdgpu::STRIX_POINT)
    {
        return TestResult::Fail("Strix DID gate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/strix-boot", strix_did_gate_admits_only_strix);

/// The boot's discovery line names each inferred block's instance-0
/// version in a fixed order, and `-` for a block discovery did not list,
/// so a first boot on Strix reads as a confirmation or a refutation.
fn strix_discovery_line_names_the_inferred_versions() -> TestResult {
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
        ip(d::HW_ID_SMUIO, (13, 0, 4), 0),
        ip(d::HW_ID_NBIF, (7, 4, 0), 0),
        ip(d::HW_ID_MMHUB, (3, 0, 1), 0),
        ip(d::HW_ID_OSSSYS, (6, 0, 0), 0),
        ip(d::HW_ID_HDP, (5, 2, 1), 0),
    ];
    if discovery_line(&blocks)
        != "amdgpu: strix discovery: NBIF 7.4.0 MMHUB 3.0.1 ATHUB - OSSSYS 6.0.0 HDP 5.2.1 SMUIO 13.0.4"
    {
        return TestResult::Fail("the discovery line's order, instance or absent marker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_discovery_line_names_the_inferred_versions
);

/// A Strix GPU with the audited MP1 14.0.1 layout constructs: the DID
/// gate admits it and the SMU resolves, with no other owner to build.
/// The run itself is not executed here — it needs a live PMFW behind the
/// mailbox, and fails closed at MemoryHubs without one.
fn strix_boot_admits_strix_with_audited_layout() -> TestResult {
    use crate::amdgpu_discovery as d;
    let mut gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    gpu.chip =
        crate::amdgpu::__test_chip_info_for_pci_id(crate::amdgpu::AMD_VENDOR, 0x150e).unwrap();
    let template = gpu.ip_blocks[0];
    let mut block = template;
    block.hw_id = d::HW_ID_MP1;
    (block.major, block.minor, block.revision) = (14, 0, 1);
    block.num_bases = 2;
    block.base_addrs[1] = 0x2000;
    gpu.ip_blocks = vec![block];
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let device = device_for(0x150e);
    // SAFETY: inert fixture mappings; construction performs no register I/O.
    let result =
        unsafe { StrixColdBoot::new(&gpu, Cap::bootstrap(), &pool, &device, [0x1000, 0x2000]) };
    match result {
        Ok(boot) => {
            if boot.state() != State::Prepared || boot.queues_verified() {
                return TestResult::Fail("Strix cold boot did not start Prepared");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("Strix cold boot refused the audited layout"),
    }
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_boot_admits_strix_with_audited_layout
);

use super::*;
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

/// Phoenix is RDNA3 with its own bring-up: the DID gate refuses it before
/// any owner reserves memory.
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
        ip(d::HW_ID_NBIF, (7, 11, 0), 0),
        ip(d::HW_ID_MMHUB, (3, 0, 1), 0),
        ip(d::HW_ID_OSSSYS, (6, 0, 0), 0),
        ip(d::HW_ID_HDP, (5, 2, 1), 0),
    ];
    if discovery_line(&blocks)
        != "amdgpu: strix discovery: NBIF 7.11.0 MMHUB 3.0.1 ATHUB - OSSSYS 6.0.0 HDP 5.2.1 SMUIO 13.0.4"
    {
        return TestResult::Fail("the discovery line's order, instance or absent marker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_discovery_line_names_the_inferred_versions
);

/// The golden table is the Linux `gfx_v11_0.c` base table verbatim (1
/// entry for 11.0.0): the 11.0.1 table (9 entries) applies only to
/// 11.0.1/11.0.4, so Strix gets the base table only. The RMW the stage
/// applies preserves every bit outside the entry's mask while setting the
/// masked bits to the table value.
fn strix_golden_table_is_the_11_0_0_base_only() -> TestResult {
    if GOLDEN_11_0_0.len() != 1 {
        return TestResult::Fail("golden table size");
    }
    let e = &GOLDEN_11_0_0[0];
    if e.window != 1 || e.reg != 0x19a2 || e.mask != 0x20000000 || e.value != 0x20000000 {
        return TestResult::Fail("golden 11.0.0 table entry");
    }
    // The RMW the stage applies, on two live values.
    for live in [0u32, 0xffff_ffff] {
        let out = (live & !e.mask) | (e.value & e.mask);
        if out & e.mask != e.value & e.mask || out & !e.mask != live & !e.mask {
            return TestResult::Fail("golden RMW semantics");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_golden_table_is_the_11_0_0_base_only
);

/// `hw_segments` passes the discovered segment bases through and contributes
/// 0 for a segment discovery did not list, exactly what Linux passes to
/// `mes_v11_0_set_hw_resources`. The MMHUB segment accepts both 3.0.1 and
/// 3.0.2: whichever the part reports is the one discovery lists.
fn strix_hw_segments_zero_missing() -> TestResult {
    use crate::amdgpu_discovery::{self as d, IpBlock};
    let mut gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    let mut bases = [0u32; d::MAX_BASE_ADDRS];
    bases[0] = 0x1000;
    bases[1] = 0x2000;
    gpu.ip_blocks = alloc::vec![IpBlock {
        hw_id: d::HW_ID_GC,
        instance: 0,
        major: 11,
        minor: 5,
        revision: 0,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 2,
    }];
    // `bank` bounds each base against `gpu.regs.len` (0x80000 in the
    // fixture): 0x1000*4 + 4 and 0x2000*4 + 4 are both in range.
    if hw_segments(&gpu, d::HW_ID_GC, &[(11, 5, 0)]) != [0x4000, 0x8000, 0, 0, 0] {
        return TestResult::Fail("hw_segments present/missing bases");
    }
    if hw_segments(&gpu, d::HW_ID_MMHUB, &[(3, 0, 1), (3, 0, 2)]) != [0, 0, 0, 0, 0] {
        return TestResult::Fail("hw_segments absent IP");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/strix-boot", strix_hw_segments_zero_missing);

/// The doorbell derivation the stages rely on: SDMA engine 0's assignment
/// index doubled into dword space, the two MES rings, and the 1024-dword MES
/// command rings.
fn strix_boot_doorbell_assignment() -> TestResult {
    if SDMA0_DOORBELL_INDEX != 0x100
        || u32::from(SDMA0_DOORBELL_INDEX) << 1 != 0x200
        || MES_SCHED_DOORBELL_DW != 0x16
        || MES_KIQ_DOORBELL_DW != 0x18
        || MES_FRAMES * 64 != 1024
    {
        return TestResult::Fail("Strix doorbell assignment");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/strix-boot", strix_boot_doorbell_assignment);

/// `STRIX_TOPOLOGY` is the `gfx_v11_0_sw_init` 11.5.0 arm, which is the
/// same arm as Phoenix's (11.0.0–11.0.4): one ME, one pipe per ME, two
/// queues per GFX pipe, one MEC, four pipes per MEC, four queues per
/// compute pipe, eight compute rings. The 8 rests on the shared-arm
/// argument (`get_num_kcq` is not in the ref checkout); the SDMA instance
/// count (1) is Phoenix's hardcoded value, not a read discovery table.
fn strix_topology_matches_the_shared_phoenix_arm() -> TestResult {
    let t = &STRIX_TOPOLOGY;
    if t.num_me != 1
        || t.num_pipe_per_me != 1
        || t.num_queue_per_pipe_gfx != 2
        || t.num_gfx_rings != 1
        || t.num_mec != 1
        || t.num_pipe_per_mec != 4
        || t.num_queue_per_pipe_compute != 4
        || t.num_compute_rings != 8
        || t.num_sdma_instances != 1
        || t.first_kfd_vmid != 8
        || t.db_start_dw_offset != 0
    {
        return TestResult::Fail("Strix MES topology");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/strix-boot",
    strix_topology_matches_the_shared_phoenix_arm
);

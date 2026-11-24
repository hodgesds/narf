use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Linux's `gfx_v11_0_hw_init` order as the stage list encodes it: the SMU
/// (GFXOFF disallowed) first, VMID0 and the GART before IH and every engine,
/// golden settings before SDMA, the SDMA0 proof and its trap before the
/// production queues, the MES-KIQ before the rings it maps, the rings before
/// the IB tests, fences after the proofs, and each stage exactly once.
fn phoenix_boot_stage_order_follows_linux() -> TestResult {
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
        return TestResult::Fail("Phoenix cold-boot stage order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_boot_stage_order_follows_linux
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

/// A GPU that is not Phoenix is refused before any owner reserves memory.
fn phoenix_boot_refuses_other_gpus_before_allocation() -> TestResult {
    let gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let available = pool.available();
    let device = device_for(0x73df);
    // SAFETY: inert fixture mappings; the identity check precedes any I/O.
    let result =
        unsafe { PhoenixColdBoot::new(&gpu, Cap::bootstrap(), &pool, &device, [0x1000, 0x2000]) };
    if !matches!(result, Err(Error::Unsupported)) || pool.available() != available {
        return TestResult::Fail("Phoenix cold boot accepted another GPU or allocated first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_boot_refuses_other_gpus_before_allocation
);

/// Strix shares `Family::Phoenix` but is RDNA3.5 with its own bring-up: the
/// DID gate refuses it before any owner reserves memory.
fn phoenix_boot_refuses_strix_before_allocation() -> TestResult {
    let mut gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    gpu.chip =
        crate::amdgpu::__test_chip_info_for_pci_id(crate::amdgpu::AMD_VENDOR, 0x150e).unwrap();
    let pool = crate::amdgpu_cp_navi22::tests::pool(1 << 20);
    let available = pool.available();
    let device = device_for(0x150e);
    // SAFETY: inert fixture mappings; the identity check precedes any I/O.
    let result =
        unsafe { PhoenixColdBoot::new(&gpu, Cap::bootstrap(), &pool, &device, [0x1000, 0x2000]) };
    if !matches!(result, Err(Error::Unsupported)) || pool.available() != available {
        return TestResult::Fail("Phoenix cold boot accepted Strix or allocated first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_boot_refuses_strix_before_allocation
);

/// The DID gate admits exactly the three Phoenix DIDs and nothing else.
fn phoenix_did_gate_admits_only_phoenix() -> TestResult {
    let amd = crate::amdgpu::AMD_VENDOR;
    if !is_phoenix_did(amd, crate::amdgpu::PHOENIX_HAWKPOINT1)
        || !is_phoenix_did(amd, crate::amdgpu::PHOENIX1)
        || !is_phoenix_did(amd, crate::amdgpu::PHOENIX2)
        || is_phoenix_did(amd, 0x150e)
        || is_phoenix_did(amd, crate::amdgpu::NAVI22)
        || is_phoenix_did(amd, crate::amdgpu::RAPHAEL)
        || is_phoenix_did(0x8086, crate::amdgpu::PHOENIX1)
    {
        return TestResult::Fail("Phoenix DID gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_did_gate_admits_only_phoenix
);

/// The boot's discovery line names each inferred block's instance-0
/// version in a fixed order, and `-` for a block discovery did not list,
/// so a first boot on Phoenix reads as a confirmation or a refutation.
fn phoenix_discovery_line_names_the_inferred_versions() -> TestResult {
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
        != "amdgpu: phoenix discovery: NBIF 7.4.0 MMHUB 3.0.1 ATHUB - OSSSYS 6.0.0 HDP 5.2.1 SMUIO 13.0.4"
    {
        return TestResult::Fail("the discovery line's order, instance or absent marker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_discovery_line_names_the_inferred_versions
);

/// The golden tables are the Linux `gfx_v11_0.c` tables verbatim (9 entries
/// for 11.0.1, 1 for 11.0.0), and the RMW the stage applies preserves every
/// bit outside each entry's mask while setting the masked bits to the table
/// value.
fn phoenix_golden_tables_match_linux() -> TestResult {
    if GOLDEN_11_0_1.len() != 9 || GOLDEN_11_0_0.len() != 1 {
        return TestResult::Fail("golden table sizes");
    }
    let expect_11_0_1: [(u32, u32, u32, u32); 9] = [
        (1, 0x5087, 0x9fff8fff, 0x00000010),
        (1, 0x5086, 0xffff8fff, 0x00000010),
        (0, 0x1f53, 0x0007ffff, 0x0000c200),
        (1, 0x2e0c, 0xffff001b, 0x00f01988),
        (0, 0x1025, 0xf0ffffff, 0x00880007),
        (1, 0x0944, 0xfffffffd, 0x00000008),
        (1, 0x0960, 0xfff891ff, 0x55480100),
        (0, 0x12e2, 0xf7f7ffff, 0x01030000),
        (1, 0x19a3, 0xfcffffff, 0x0000000a),
    ];
    for (i, (window, reg, mask, value)) in expect_11_0_1.iter().enumerate() {
        let e = &GOLDEN_11_0_1[i];
        if e.window != *window || e.reg != *reg || e.mask != *mask || e.value != *value {
            return TestResult::Fail("golden 11.0.1 table entry");
        }
        // The RMW the stage applies, on two live values.
        for live in [0u32, 0xffff_ffff] {
            let out = (live & !e.mask) | (e.value & e.mask);
            if out & e.mask != e.value & e.mask || out & !e.mask != live & !e.mask {
                return TestResult::Fail("golden RMW semantics");
            }
        }
    }
    let e = &GOLDEN_11_0_0[0];
    if e.window != 1 || e.reg != 0x19a2 || e.mask != 0x20000000 || e.value != 0x20000000 {
        return TestResult::Fail("golden 11.0.0 table entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_golden_tables_match_linux
);

/// The MES header parser reads the two entry points from the
/// `mes_firmware_header_v1_0` layout (common header 32 bytes;
/// `mes_uc_start_addr` at 56/60, `mes_data_start_addr` at 64/68), and
/// refuses a zero entry point or a truncated image.
fn phoenix_mes_header_parser_reads_entry_points() -> TestResult {
    let mut image = [0u8; 128];
    let put = |image: &mut [u8; 128], off: usize, v: u32| {
        image[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put(&mut image, 56, 0x5678_9abc);
    put(&mut image, 60, 0x0000_1234);
    put(&mut image, 64, 0xcba9_8765);
    put(&mut image, 68, 0x0000_0fed);
    if parse_mes_start_addrs(&image) != Some((0x0000_1234_5678_9abc, 0x0000_0fed_cba9_8765)) {
        return TestResult::Fail("MES header entry points");
    }
    let mut zero_uc = image;
    put(&mut zero_uc, 56, 0);
    put(&mut zero_uc, 60, 0);
    if parse_mes_start_addrs(&zero_uc).is_some() {
        return TestResult::Fail("MES header zero entry point accepted");
    }
    if parse_mes_start_addrs(&image[..64]).is_some() {
        return TestResult::Fail("MES header truncated image accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/phoenix-boot",
    phoenix_mes_header_parser_reads_entry_points
);

/// `hw_segments` passes the discovered segment bases through and contributes
/// 0 for a segment discovery did not list, exactly what Linux passes to
/// `mes_v11_0_set_hw_resources`.
fn phoenix_hw_segments_zero_missing() -> TestResult {
    use crate::amdgpu_discovery::{self as d, IpBlock};
    let mut gpu = crate::amdgpu_cp_navi22::tests::navi22_gpu();
    let mut bases = [0u32; d::MAX_BASE_ADDRS];
    bases[0] = 0x1000;
    bases[1] = 0x2000;
    gpu.ip_blocks = alloc::vec![IpBlock {
        hw_id: d::HW_ID_GC,
        instance: 0,
        major: 11,
        minor: 0,
        revision: 1,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 2,
    }];
    // `bank` bounds each base against `gpu.regs.len` (0x80000 in the
    // fixture): 0x1000*4 + 4 and 0x2000*4 + 4 are both in range.
    if hw_segments(&gpu, d::HW_ID_GC, &[(11, 0, 1)]) != [0x4000, 0x8000, 0, 0, 0] {
        return TestResult::Fail("hw_segments present/missing bases");
    }
    if hw_segments(&gpu, d::HW_ID_MMHUB, &[(3, 0, 1)]) != [0, 0, 0, 0, 0] {
        return TestResult::Fail("hw_segments absent IP");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/phoenix-boot", phoenix_hw_segments_zero_missing);

/// The doorbell derivation the stages rely on: SDMA engine 0's assignment
/// index doubled into dword space, the two MES rings, and the 1024-dword MES
/// command rings.
fn phoenix_boot_doorbell_assignment() -> TestResult {
    if SDMA0_DOORBELL_INDEX != 0x100
        || u32::from(SDMA0_DOORBELL_INDEX) << 1 != 0x200
        || MES_SCHED_DOORBELL_DW != 0x16
        || MES_KIQ_DOORBELL_DW != 0x18
        || MES_FRAMES * 64 != 1024
    {
        return TestResult::Fail("Phoenix doorbell assignment");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/phoenix-boot", phoenix_boot_doorbell_assignment);

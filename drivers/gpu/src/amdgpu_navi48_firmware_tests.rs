use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
pub(crate) fn gpu() -> AmdGpu {
    let mut gpu = crate::amdgpu_gfx_navi22::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, 0x7550).unwrap();
    for (ip, version) in
        gpu.ip_blocks
            .iter_mut()
            .zip([(12, 0, 1), (14, 0, 3), (7, 0, 1), (5, 0, 0), (4, 1, 0)])
    {
        (ip.major, ip.minor, ip.revision) = version;
    }
    gpu.ip_blocks[1].num_bases = 2;
    gpu
}
fn navi48_firmware_selection_and_complete_set() -> TestResult {
    for smu in [2, 3] {
        for sdma in [0, 1] {
            let mut g = gpu();
            g.ip_blocks[1].revision = smu;
            g.ip_blocks[2].revision = sdma;
            let target = Target::resolve(&g).unwrap();
            if Source::Smc.name(target, MesMode::Separate)
                != if smu == 2 {
                    "amdgpu/smu_14_0_2.bin"
                } else {
                    "amdgpu/smu_14_0_3.bin"
                }
                || Source::Sdma.name(target, MesMode::Unified)
                    != if sdma == 0 {
                        "amdgpu/sdma_7_0_0.bin"
                    } else {
                        "amdgpu/sdma_7_0_1.bin"
                    }
                || Source::Mes.name(target, MesMode::Unified)
                    != Source::Mes1.name(target, MesMode::Unified)
                || Source::Mes.name(target, MesMode::Separate)
                    == Source::Mes1.name(target, MesMode::Separate)
            {
                return TestResult::Fail("IP/revision/MES firmware name selection");
            }
        }
    }
    for index in 0..Source::ALL.len() {
        let mut f = fixture();
        f.bytes[index].clear();
        if f.images().is_ok() {
            return TestResult::Fail("missing mandatory Navi48 image accepted");
        }
    }
    let cap = Cap::bootstrap();
    cap.revoke();
    if !matches!(
        Firmware::open(&gpu(), &cap, MesMode::Unified),
        Err(Error::Revoked)
    ) {
        return TestResult::Fail("Navi48 firmware read without current authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_firmware_selection_and_complete_set
);
fn navi48_firmware_rejects_wrong_or_duplicate_ips() -> TestResult {
    for index in 0..5 {
        let mut g = gpu();
        g.ip_blocks[index].major = 0;
        if Target::resolve(&g).is_ok() {
            return TestResult::Fail("unsupported Navi48 firmware IP admitted");
        }
        let mut g = gpu();
        g.ip_blocks.push(g.ip_blocks[index]);
        if Target::resolve(&g).is_ok() {
            return TestResult::Fail("duplicate Navi48 firmware IP admitted");
        }
    }
    let mut g = gpu();
    g.ip_blocks[4].minor = 0;
    g.ip_blocks[4].revision = 1;
    if Target::resolve(&g).is_err() {
        return TestResult::Fail("normalized DCN4.0.1 rejected");
    }
    g.chip.did = 0x7551;
    if Target::resolve(&g).is_ok() {
        return TestResult::Fail("professional kicker target admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_firmware_rejects_wrong_or_duplicate_ips
);

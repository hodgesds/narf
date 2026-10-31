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
fn rdna4_media_sram_type_rejects_jpeg_dpg_on_navi44() -> TestResult {
    for gc_revision in [0, 1] {
        let mut gpu = gpu();
        gpu.ip_blocks[0].revision = gc_revision;
        gpu.ip_blocks[1].revision = 2;
        gpu.ip_blocks[2].revision = 0;
        let target = Target::resolve(&gpu).unwrap();
        assert_eq!(target.media_sram_type(false), Some(49));
        assert_eq!(
            target.media_sram_type(true),
            if gc_revision == 1 { Some(128) } else { None }
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-dpg",
    rdna4_media_sram_type_rejects_jpeg_dpg_on_navi44
);
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
    // The AI PRO R9700 is Navi48: ordinary images, unless it is the 0xC8
    // kicker revision (amdgpu_is_kicker_fw), whose RLC/IMU/SMU differ.
    g.chip.did = 0x7551;
    let plain = Target::resolve(&g).unwrap();
    g.chip.revision = 0xc8;
    let kicker = Target::resolve(&g).unwrap();
    if Source::Rlc.name(plain, MesMode::Unified) != "amdgpu/gc_12_0_1_rlc.bin"
        || Source::Rlc.name(kicker, MesMode::Unified) != "amdgpu/gc_12_0_1_rlc_kicker.bin"
        || Source::Imu.name(kicker, MesMode::Unified) != "amdgpu/gc_12_0_1_imu_kicker.bin"
        || Source::Smc.name(kicker, MesMode::Unified) != "amdgpu/smu_14_0_3_kicker.bin"
        || Source::Pfp.name(kicker, MesMode::Unified) != "amdgpu/gc_12_0_1_pfp.bin"
    {
        return TestResult::Fail("AI PRO R9700 firmware or kicker selection");
    }
    // A kicker revision on MP1 14.0.2 has no kicker SMU image to load.
    g.ip_blocks[1].revision = 2;
    if Target::resolve(&g).is_ok() {
        return TestResult::Fail("kicker set without kicker images admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_firmware_rejects_wrong_or_duplicate_ips
);
fn rdna4_profiles_select_their_die_firmware_set() -> TestResult {
    use crate::amdgpu_rdna4::{tests::Profile, Rdna4Chip};
    for profile in Profile::ALL {
        let mut g = gpu();
        profile.apply(&mut g);
        let Ok(target) = Target::resolve(&g) else {
            return TestResult::Fail("RDNA4 profile firmware target refused");
        };
        let (gc, smu, sdma) = match profile.chip() {
            Rdna4Chip::Navi48 => ("gc_12_0_1", "smu_14_0_3", "sdma_7_0_1"),
            Rdna4Chip::Navi44 => ("gc_12_0_0", "smu_14_0_2", "sdma_7_0_0"),
        };
        for source in Source::ALL {
            let name = source.name(target, MesMode::Unified);
            let expected_prefix = match source {
                Source::Smc => smu,
                Source::Sdma => sdma,
                Source::Vcn => "vcn_5_0_0",
                Source::Dmcub => "dcn_4_0_1",
                _ => gc,
            };
            if !name
                .strip_prefix("amdgpu/")
                .is_some_and(|n| n.starts_with(expected_prefix))
            {
                return TestResult::Fail("profile firmware image from the wrong IP version");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    rdna4_profiles_select_their_die_firmware_set
);

//! Strix Point bring-up: identity, firmware bundle, VCN routing, DCN 3.5
//! profile and modeset selection, DMUB 3.5 preparation. Fixture-only —
//! no Strix silicon is known to exist on the test bench, and the ColdBoot
//! owner does not exist yet (tracker #2467), so the graphics engines stay
//! down and only the display path is exercised here.
use crate::{
    amdgpu, amdgpu_dcn, amdgpu_dcn_profile::Profile, amdgpu_discovery as ip,
    amdgpu_dmub_firmware as firmware, amdgpu_info, amdgpu_video::VcnVersion,
};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Strix Point (0x150E) is its own family — GFX 11.5.0, DCN 3.5,
/// PSP 14.0.1 — not a Phoenix variant, and an APU by id and by GC version.
fn strix_identity_matches_linux() -> TestResult {
    if amdgpu::STRIX_POINT != 0x150E {
        return TestResult::Fail("Strix Point is 0x150E in pci.ids");
    }
    let Some(info) = amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, amdgpu::STRIX_POINT)
    else {
        return TestResult::Fail("Strix Point's device id resolves to no chip");
    };
    if info.family != amdgpu::Family::Strix {
        return TestResult::Fail("Strix Point must resolve to Family::Strix, not Phoenix");
    }
    if info.asic != "strix" || info.fw_name != "amdgpu/strix.bin" {
        return TestResult::Fail("Strix Point asic/fw_name mismatch");
    }
    // An APU by id before discovery, and by GC version after it
    // (amdgpu_discovery.c's GC 11.5.0 case: AMDGPU_FAMILY_GC_11_5_0).
    if !info.is_apu() || !amdgpu::gc_version_is_apu(11, 5, 0) {
        return TestResult::Fail("Strix Point must be an APU");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_identity_matches_linux);

/// The STRIX_FW bundle, in PSP load order: TOC, SDMA, CP, MES, IMU, RLC,
/// VCN, DMCUB, TA — RLC last of the graphics firmwares so the PSP
/// autoload fires only once the rest have landed. No SMU entry (APU
/// PMFW is BIOS-resident), and no `gc_11_5_0_mes.bin`: GC 11.5.0 takes
/// `mes_2` + `mes1` only (`mes_v11_0.c`).
fn strix_firmware_bundle_matches_linux() -> TestResult {
    let Some(info) = amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, amdgpu::STRIX_POINT)
    else {
        return TestResult::Fail("Strix Point's device id resolves to no chip");
    };
    let names: Vec<&str> = info.fw_list.iter().map(|e| e.name).collect();
    let expected: [&str; 12] = [
        "amdgpu/psp_14_0_1_toc.bin",
        "amdgpu/sdma_6_1_0.bin",
        "amdgpu/gc_11_5_0_pfp.bin",
        "amdgpu/gc_11_5_0_me.bin",
        "amdgpu/gc_11_5_0_mec.bin",
        "amdgpu/gc_11_5_0_mes_2.bin",
        "amdgpu/gc_11_5_0_mes1.bin",
        "amdgpu/gc_11_5_0_imu.bin",
        "amdgpu/gc_11_5_0_rlc.bin",
        "amdgpu/vcn_4_0_5.bin",
        "amdgpu/dcn_3_5_dmcub.bin",
        "amdgpu/psp_14_0_1_ta.bin",
    ];
    if names != expected {
        return TestResult::Fail("Strix bundle is not the audited 14.0.1 set in load order");
    }
    if names
        .iter()
        .any(|n| n.contains("smu") || *n == "amdgpu/gc_11_5_0_mes.bin")
    {
        return TestResult::Fail("Strix bundle carries an SMU blob or a mes.bin");
    }
    if info
        .fw_list
        .iter()
        .any(|e| e.cmd == amdgpu::SMU_LOAD_PMFW_MP1)
    {
        return TestResult::Fail("an APU bundle must not carry an SMU PMFW blob");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-strix",
    strix_firmware_bundle_matches_linux
);

/// VCN 4.0.5 (UVD 4.0.5/4.0.6): Linux `vcn_v4_0_5` for VCN 4.0.5/4.0.6
/// in `amdgpu_discovery.c`. Phoenix stays V4_0_2 — the audit's mislabel
/// of Phoenix as 4.0.5 must not come back through this arm.
fn strix_vcn_is_4_0_5() -> TestResult {
    if VcnVersion::from_family(amdgpu::Family::Strix) != Some(VcnVersion::V4_0_5) {
        return TestResult::Fail("Strix must route to VCN 4.0.5");
    }
    if VcnVersion::from_family(amdgpu::Family::Phoenix) != Some(VcnVersion::V4_0_2) {
        return TestResult::Fail("Phoenix must stay VCN 4.0.2");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_vcn_is_4_0_5);

/// DCN 3.5.0 on Strix Point resolves to its own profile with the
/// borrowed 4/5/5 caps (pending `dcn35_resource.c` verification, lane 6).
fn strix_dcn35_profile_resolves() -> TestResult {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip.did = amdgpu::STRIX_POINT;
    let mut dcn = gpu.ip_blocks[0];
    dcn.hw_id = ip::HW_ID_DCN;
    dcn.instance = 0;
    dcn.major = 3;
    dcn.minor = 5;
    dcn.revision = 0;
    dcn.num_bases = 4;
    dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
    gpu.ip_blocks.push(dcn);
    let Ok(profile) = Profile::resolve(&gpu) else {
        return TestResult::Fail("DCN 3.5 did not resolve");
    };
    if profile != Profile::Dcn35
        || profile.is_dcn32()
        || profile.is_dcn314()
        || (profile.pipes(), profile.streams(), profile.channels()) != (4, 5, 5)
    {
        return TestResult::Fail("DCN 3.5 profile is not Dcn35 with the borrowed 4/5/5 caps");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_dcn35_profile_resolves);

/// Modeset selection by discovery: a (3, 5, 0) DCN block takes the 3.5
/// sequence (V_BLANK 0x1b38, V_SYNC_A 0x1b39, CONTROL 0x1b43,
/// INTERRUPT_CONTROL 0x1b5a), while a (3, 1, 4) block takes the 2.0
/// sequence (0x1b36 / 0x1b37 / 0x1b41 / 0x1b59). Selecting the 2.0
/// sequence for Strix would land every vertical timing register and
/// the master enable two dwords past where they live.
fn strix_modeset_uses_dcn35_offsets() -> TestResult {
    let Some(timing) = amdgpu_dcn::timing_for_mode(1920, 1080, 60) else {
        return TestResult::Fail("no 1920x1080@60 timing");
    };
    let block = |minor: u8, revision: u8| {
        let mut base_addrs = [0u32; ip::MAX_BASE_ADDRS];
        base_addrs[0] = 0x1000;
        ip::IpBlock {
            hw_id: ip::HW_ID_DCN,
            instance: 0,
            major: 3,
            minor,
            revision,
            sub_revision: 0,
            variant: 0,
            base_addrs,
            num_bases: 1,
        }
    };
    let blocks35 = [block(5, 0)];
    let Some(seq35) =
        amdgpu_dcn::build_modeset_from_discovery(&blocks35, &timing, 0x1000_0000, 1920)
    else {
        return TestResult::Fail("DCN 3.5 modeset did not build");
    };
    let addrs35: Vec<u32> = seq35.iter().map(|w| w.addr).collect();
    for want in [
        0x1000 + 0x1b38, // V_BLANK_START_END
        0x1000 + 0x1b39, // V_SYNC_A
        0x1000 + 0x1b43, // OTG_CONTROL
        0x1000 + 0x1b5a, // OTG_INTERRUPT_CONTROL
    ] {
        if !addrs35.contains(&want) {
            return TestResult::Fail("DCN 3.5 sequence misses a moved OTG register");
        }
    }
    for stale in [
        0x1000 + 0x1b36,
        0x1000 + 0x1b37,
        0x1000 + 0x1b41,
        0x1000 + 0x1b59,
    ] {
        if addrs35.contains(&stale) {
            return TestResult::Fail("DCN 3.5 sequence writes a DCN 2.0 OTG slot");
        }
    }
    let blocks314 = [block(1, 4)];
    let Some(seq314) =
        amdgpu_dcn::build_modeset_from_discovery(&blocks314, &timing, 0x1000_0000, 1920)
    else {
        return TestResult::Fail("DCN 3.1.4 modeset did not build");
    };
    let addrs314: Vec<u32> = seq314.iter().map(|w| w.addr).collect();
    for want in [0x1000 + 0x1b36, 0x1000 + 0x1b41] {
        if !addrs314.contains(&want) {
            return TestResult::Fail("DCN 3.1.4 sequence misses a 2.0 OTG register");
        }
    }
    if addrs314.contains(&(0x1000 + 0x1b38)) || addrs314.contains(&(0x1000 + 0x1b43)) {
        return TestResult::Fail("DCN 3.1.4 sequence writes a DCN 3.5 OTG slot");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_modeset_uses_dcn35_offsets);

/// UAPI family: Strix is GC 11.5.0 (`amdgpu_discovery.c`'s GC 11.5.0
/// case: `AMDGPU_FAMILY_GC_11_5_0` = 150). Mesa keys ASIC behaviour off
/// this, so a Phoenix value here would select the wrong userspace path.
fn strix_family_id_is_gc_11_5_0() -> TestResult {
    let snap = amdgpu_info::Snapshot {
        did: u32::from(amdgpu::STRIX_POINT),
        family: amdgpu::Family::Strix,
        vram_size: 0,
        visible_vram_size: 0,
        is_apu: true,
        gc: None,
        ip_blocks: Vec::new(),
        navi22: Default::default(),
        reference_clock_10khz: 0,
        vram_type: 0,
        vram_bit_width: 0,
    };
    if amdgpu_info::family_id(&snap) != Some(150) {
        return TestResult::Fail("Strix UAPI family is not AMDGPU_FAMILY_GC_11_5_0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_family_id_is_gc_11_5_0);

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// A synthetic DCN 3.5 DMCUB image: the shared `combined()` fixture
/// with the header IP version rewritten to (3, 5) and the metadata's
/// shared-state size / features set. Metadata sits 64 bytes
/// (`sizeof(union dmub_fw_meta)`) before the 256-byte PSP footer.
fn dcn35_image(shared_state_size: u32, features: u16) -> Vec<u8> {
    let mut bytes = firmware::tests::combined(256, 0);
    bytes[12] = 3;
    bytes[14] = 5;
    let meta = bytes.len() - 256 - 64;
    put32(&mut bytes, meta + 20, shared_state_size);
    bytes[meta + 24..meta + 26].copy_from_slice(&features.to_le_bytes());
    bytes
}

/// `prepare_dcn35`: the combined layout plus the Region6 shared-state
/// window Linux's `dmub_dcn35_setup_windows` programs. The shared-state
/// contract is the DMUB-wide one `prepare_dcn401` encodes (the declared
/// region must fit the declared feature blocks, floored at the six
/// 256-byte feature blocks); an image declaring no shared state keeps a
/// zero-size region6, and a wrong IP version is refused.
fn strix_dmub_prepare_dcn35() -> TestResult {
    let vbios = [0u8; 512];
    let bytes = dcn35_image(1536, 0);
    let Ok(image) = firmware::Image::parse(&bytes) else {
        return TestResult::Fail("synthetic DCN 3.5 image rejected");
    };
    if image.metadata().shared_state_size != 1536 {
        return TestResult::Fail("synthetic image does not declare its shared state");
    }
    let Ok(prepared) = image.prepare_dcn35(&vbios) else {
        return TestResult::Fail("DCN 3.5 image with shared state refused");
    };
    if prepared.layout().region(firmware::Window::SharedState).size != 1536 {
        return TestResult::Fail("Region6 is not the declared shared-state size");
    }
    // No shared state: the region stays zero-size (unprogrammed).
    let bytes = dcn35_image(0, 0);
    let Ok(image) = firmware::Image::parse(&bytes) else {
        return TestResult::Fail("synthetic DCN 3.5 image without shared state rejected");
    };
    let Ok(prepared) = image.prepare_dcn35(&vbios) else {
        return TestResult::Fail("DCN 3.5 image without shared state refused");
    };
    if prepared.layout().region(firmware::Window::SharedState).size != 0 {
        return TestResult::Fail("no-shared-state image must keep a zero-size region6");
    }
    // Feature blocks that do not fit the declared region are refused.
    let bytes = dcn35_image(512, 6);
    let Ok(image) = firmware::Image::parse(&bytes) else {
        return TestResult::Fail("synthetic DCN 3.5 image with oversized features rejected");
    };
    if image.prepare_dcn35(&vbios).is_ok() {
        return TestResult::Fail("feature blocks larger than the region accepted");
    }
    // A DCN 3.1 image is not a 3.5 image, and neither is a 4.0 one.
    for (major, minor) in [(3u8, 1u8), (4u8, 0u8)] {
        let mut bytes = dcn35_image(1536, 0);
        bytes[12] = major;
        bytes[14] = minor;
        let Ok(image) = firmware::Image::parse(&bytes) else {
            return TestResult::Fail("synthetic non-3.5 image rejected at parse");
        };
        if image.prepare_dcn35(&vbios).is_ok() {
            return TestResult::Fail("non-3.5 image accepted by prepare_dcn35");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-strix", strix_dmub_prepare_dcn35);

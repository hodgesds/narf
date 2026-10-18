use super::*;
use crate::amdgpu_gfx_firmware::tests::container;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) fn fixture() -> Firmware {
    fixture_with_vcn(1)
}
/// Complete set for a board exposing the VCN instances in `mask`.
pub(crate) fn fixture_with_vcn(mask: u8) -> Firmware {
    Firmware {
        bytes: core::array::from_fn(|i| Some(container(Source::ORDER[i]))),
        vcn: mask,
    }
}
fn navi22_graphics_set_requires_all_images_except_missing_mec2() -> TestResult {
    for i in 0..Source::ORDER.len() {
        let mut firmware = fixture();
        firmware.bytes[i] = None;
        if firmware.images().is_ok() != (Source::ORDER[i] == Source::Mec2) {
            return TestResult::Fail(
                "missing required firmware accepted or optional MEC2 required",
            );
        }
    }
    for source in Source::ORDER {
        for error in [
            narf_firmware::FirmwareError::NotFound,
            narf_firmware::FirmwareError::SignatureInvalid,
            narf_firmware::FirmwareError::BadFormat,
            narf_firmware::FirmwareError::AuthorityRevoked,
        ] {
            let missing = optional(source, Err(Error::Registry(source, error)));
            if missing.is_ok()
                != (source == Source::Mec2 && error == narf_firmware::FirmwareError::NotFound)
            {
                return TestResult::Fail("firmware failure hidden as optional absence");
            }
        }
    }
    let mut firmware = fixture();
    firmware.bytes[5].as_mut().unwrap()[0] = 0xff;
    if firmware.images().is_ok() {
        return TestResult::Fail("corrupt optional MEC2 silently skipped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_graphics_set_requires_all_images_except_missing_mec2
);

pub(crate) fn gpu() -> AmdGpu {
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0x10000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let ip = |id, v: (u8, u8, u8)| discovery::IpBlock {
        hw_id: id,
        instance: 0,
        major: v.0,
        minor: v.1,
        revision: v.2,
        sub_revision: 0,
        variant: 0,
        base_addrs: [0; discovery::MAX_BASE_ADDRS],
        num_bases: 1,
    };
    AmdGpu {
        regs: map,
        fb_bar: map,
        chip: crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::NAVI22,
        )
        .unwrap(),
        vram: crate::amdgpu::VramInfo {
            base: 0,
            size: 12 << 30,
            visible_size: 256 << 20,
        },
        mode: None,
        fw_loaded: false,
        gc_info: None,
        vbios: None,
        ip_blocks: vec![
            ip(discovery::HW_ID_GC, (10, 3, 2)),
            ip(discovery::HW_ID_MP1, (11, 0, 11)),
            ip(discovery::HW_ID_SDMA0, (5, 2, 2)),
            ip(discovery::HW_ID_VCN, (3, 0, 0)),
            ip(discovery::HW_ID_DCN, (3, 0, 0)),
        ],
    }
}
/// Navy Flounder discovery: VCN 3.0.0 instance 0 plus 3.0.1 instance 1.
fn navi22_graphics_set_accepts_both_vcn_instances() -> TestResult {
    let mut two = gpu();
    let mut second = two.ip_blocks[3];
    second.instance = 1;
    second.revision = 1;
    two.ip_blocks.push(second);
    if check_device(&two).is_err() || vcn_instances(&two) != Ok(3) || vcn_instances(&gpu()) != Ok(1)
    {
        return TestResult::Fail("two-instance Navi22 VCN discovery refused");
    }
    for case in 0..3 {
        let mut bad = gpu();
        let mut extra = bad.ip_blocks[3];
        match case {
            0 => extra.instance = 2,
            1 => {
                extra.instance = 1;
                extra.minor = 1;
            }
            _ => {
                // Instance 1 without instance 0.
                bad.ip_blocks.remove(3);
                extra.instance = 1;
            }
        }
        bad.ip_blocks.push(extra);
        if check_device(&bad).is_ok() {
            return TestResult::Fail("foreign VCN instance layout accepted");
        }
    }
    let mut firmware = fixture_with_vcn(3);
    firmware.harvest_vcn(2);
    let images = firmware.images().unwrap();
    let vcn: Vec<u32> = images[7]
        .unwrap()
        .payloads()
        .map(|p| p.firmware_type())
        .collect();
    if firmware.vcn_instances() != 1
        || vcn != [13]
        || firmware.vcn_size() != Some(container(Source::Vcn).len())
    {
        return TestResult::Fail("VCN harvest not applied to PSP payloads");
    }
    firmware.harvest_vcn(1);
    if images_count(&firmware) != 0 {
        return TestResult::Fail("fully harvested VCN still uploaded");
    }
    TestResult::Pass
}
fn images_count(firmware: &Firmware) -> usize {
    firmware.images().unwrap()[7].unwrap().payloads().count()
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_graphics_set_accepts_both_vcn_instances
);

fn navi22_graphics_set_checks_ip_and_live_registry_authority() -> TestResult {
    for case in 0..10 {
        let mut bad = gpu();
        match case {
            0 => bad.chip.did = crate::amdgpu::PHOENIX1,
            1 => bad.ip_blocks[0].revision = 0,
            2 => bad.ip_blocks[1].revision = 7,
            3 => bad.ip_blocks[2].revision = 0,
            4 => bad.ip_blocks.push(bad.ip_blocks[2]),
            5 => bad.ip_blocks[3].revision = 16,
            6 => bad.ip_blocks.push(bad.ip_blocks[3]),
            7 => bad.ip_blocks[4].minor = 1,
            8 => bad.ip_blocks.push(bad.ip_blocks[4]),
            _ => bad.ip_blocks.pop().map(|_| ()).unwrap(),
        }
        if check_device(&bad).is_ok() {
            return TestResult::Fail("foreign/missing/duplicate graphics IP accepted");
        }
    }
    let authority = Cap::bootstrap();
    authority.revoke();
    if !matches!(Firmware::open(&gpu(), &authority), Err(Error::Revoked)) {
        return TestResult::Fail("firmware read ignored registry revocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_graphics_set_checks_ip_and_live_registry_authority
);

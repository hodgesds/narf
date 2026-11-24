//! RDNA3 identity: discovery-GC identification, the per-die IP versions,
//! and the `pci.ids` device list.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A synthetic board the identity tests run against. Each turns a Navi22
/// descriptor into the named die by changing only what discovery, the PCI
/// header and harvesting would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// RX 7900 XTX: GC 11.0.0, MP 13.0.0, SDMA 6.0.0, DCN 3.2.0, VCN 4.0.0.
    Navi31,
    /// RX 7800 XT: GC 11.0.3, MP 13.0.10, SDMA 6.0.3, DCN 3.2.0, VCN 4.0.0.
    Navi32,
    /// RX 7600: GC 11.0.2, MP 13.0.7, SDMA 6.0.2, DCN 3.2.1, VCN 4.0.4.
    Navi33,
}
impl Profile {
    pub(crate) const ALL: [Self; 3] = [Self::Navi31, Self::Navi32, Self::Navi33];
    pub(crate) fn chip(self) -> Rdna3Chip {
        match self {
            Self::Navi31 => Rdna3Chip::Navi31,
            Self::Navi32 => Rdna3Chip::Navi32,
            Self::Navi33 => Rdna3Chip::Navi33,
        }
    }
    pub(crate) fn did(self) -> u16 {
        match self {
            Self::Navi31 => 0x744C,
            Self::Navi32 => 0x747E,
            Self::Navi33 => 0x7480,
        }
    }
    pub(crate) fn from_chip(chip: Rdna3Chip) -> Self {
        match chip {
            Rdna3Chip::Navi31 => Self::Navi31,
            Rdna3Chip::Navi32 => Self::Navi32,
            Rdna3Chip::Navi33 => Self::Navi33,
        }
    }
    /// Rewrite a Navi22 descriptor into this board: PCI id, every discovered
    /// GC/MP0/MP1/SDMA0/VCN/DCN version. Blocks the descriptor lacks (MP0)
    /// are added.
    pub(crate) fn apply(self, gpu: &mut AmdGpu) {
        gpu.chip.did = self.did();
        gpu.chip.family = Family::Navi3;
        gpu.chip.asic = self.chip().asic();
        let versions = self.chip().ip_versions();
        let set = |b: &mut IpBlock, v: (u8, u8, u8)| {
            (b.major, b.minor, b.revision) = v;
        };
        for b in &mut gpu.ip_blocks {
            match b.hw_id {
                ip::HW_ID_GC => set(b, versions.gc),
                ip::HW_ID_MP1 => set(b, versions.mp),
                ip::HW_ID_SDMA0 => set(b, versions.sdma),
                ip::HW_ID_VCN => set(b, versions.vcn),
                ip::HW_ID_DCN => set(b, versions.dcn),
                _ => {}
            }
        }
        if !gpu.ip_blocks.iter().any(|b| b.hw_id == ip::HW_ID_MP0) {
            gpu.ip_blocks.push(IpBlock {
                hw_id: ip::HW_ID_MP0,
                instance: 0,
                major: versions.mp.0,
                minor: versions.mp.1,
                revision: versions.mp.2,
                sub_revision: 0,
                variant: 0,
                base_addrs: [0; ip::MAX_BASE_ADDRS],
                num_bases: 1,
            });
        }
    }
}

/// A Navi31 board: the base the ownership tests install in the controller
/// slot.
pub(crate) fn gpu() -> AmdGpu {
    let mut gpu = crate::amdgpu_gfx_navi22::tests::gpu();
    Profile::Navi31.apply(&mut gpu);
    gpu
}

fn rdna3_identity_follows_discovered_gc_not_pci_id() -> TestResult {
    for profile in Profile::ALL {
        let mut g = crate::amdgpu_gfx_navi22::tests::gpu();
        profile.apply(&mut g);
        if Rdna3Chip::of(&g) != Some(profile.chip()) {
            return TestResult::Fail("profile die not identified from GC");
        }
        // The die's own table agrees with what discovery just said.
        if profile.chip().gc_version() != profile.chip().ip_versions().gc {
            return TestResult::Fail("die GC version disagrees with its IP table");
        }
    }
    // An unlisted board id with Navi33 discovery is Navi33.
    let mut fixture = gpu();
    Profile::Navi33.apply(&mut fixture);
    fixture.chip.did = 0x7498;
    if Rdna3Chip::of(&fixture) != Some(Rdna3Chip::Navi33) {
        return TestResult::Fail("unlisted RDNA3 id refused");
    }
    for (case, refuse) in [
        (0, "GC 11.0.4 accepted as discrete RDNA3"),
        (1, "GC 11.0.1 Phoenix accepted as discrete RDNA3"),
        (2, "duplicate GC accepted"),
        (3, "GC instance 1 accepted"),
        (4, "non-RDNA3 family accepted"),
        (5, "foreign vendor accepted"),
        (6, "Phoenix-family id accepted"),
    ] {
        let mut g = gpu();
        match case {
            0 => {
                for b in &mut g.ip_blocks {
                    if b.hw_id == ip::HW_ID_GC {
                        b.revision = 4;
                    }
                }
            }
            1 => {
                for b in &mut g.ip_blocks {
                    if b.hw_id == ip::HW_ID_GC {
                        b.revision = 1;
                    }
                }
            }
            2 => g.ip_blocks.push(g.ip_blocks[0]),
            3 => {
                for b in &mut g.ip_blocks {
                    if b.hw_id == ip::HW_ID_GC {
                        b.instance = 1;
                    }
                }
            }
            4 => g.chip.family = Family::Navi4,
            5 => g.chip.vid = 0x10de,
            _ => {
                g.chip = crate::amdgpu::__test_chip_info_for_pci_id(
                    crate::amdgpu::AMD_VENDOR,
                    crate::amdgpu::PHOENIX_HAWKPOINT1,
                )
                .unwrap();
            }
        }
        if Rdna3Chip::of(&g).is_some() {
            return TestResult::Fail(refuse);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna3",
    rdna3_identity_follows_discovered_gc_not_pci_id
);

fn rdna3_known_devices_match_pci_ids() -> TestResult {
    if KNOWN_DEVICES.len() != 20 {
        return TestResult::Fail("RDNA3 device list is not the 20 pci.ids ids");
    }
    let mut seen = [0u16; 20];
    for (i, d) in KNOWN_DEVICES.iter().enumerate() {
        if known_device(d.did) != Some(d) {
            return TestResult::Fail("known RDNA3 id does not round-trip");
        }
        if d.chip.gc_version() != d.chip.ip_versions().gc {
            return TestResult::Fail("known RDNA3 id's die disagrees with its GC");
        }
        if seen[..i].contains(&d.did) {
            return TestResult::Fail("duplicate RDNA3 device id");
        }
        seen[i] = d.did;
    }
    // The one id the probe table already registers is the Navi31 flagship.
    if known_device(0x744C) != Some(&KNOWN_DEVICES[5])
        || crate::amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, 0x744C)
            .is_none_or(|c| c.family != Family::Navi3 || c.asic != "navi31")
    {
        return TestResult::Fail("0x744C is not the registered Navi31 flagship");
    }
    // Every other listed id is a Navi3 die by discovery even though lane 0
    // has not registered it in the probe table yet.
    for d in KNOWN_DEVICES {
        if d.did == 0x744C {
            continue;
        }
        let mut g = gpu();
        g.chip.did = d.did;
        g.chip.family = Family::Navi3;
        Profile::from_chip(d.chip).apply(&mut g);
        g.chip.did = d.did;
        if Rdna3Chip::of(&g) != Some(d.chip) {
            return TestResult::Fail("listed RDNA3 id not identified by discovery");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/rdna3", rdna3_known_devices_match_pci_ids);

fn rdna3_per_die_ip_versions_match_linux() -> TestResult {
    // The firmware sets (Gentoo AMDGPU table; LP#2034103 for Navi32):
    // Navi31 GC 11.0.0 / MP 13.0.0 / SDMA 6.0.0 / DCN 3.2.0 / VCN 4.0.0,
    // Navi32 GC 11.0.3 / MP 13.0.10 / SDMA 6.0.3 / DCN 3.2.0 / VCN 4.0.0,
    // Navi33 GC 11.0.2 / MP 13.0.7 / SDMA 6.0.2 / DCN 3.2.1 / VCN 4.0.4.
    // Note the 32/33 order: it is the opposite of the pre-launch guess.
    for (chip, gc, mp, sdma, dcn, vcn, ext, gfx) in [
        (
            Rdna3Chip::Navi31,
            (11, 0, 0),
            (13, 0, 0),
            (6, 0, 0),
            (3, 2, 0),
            (4, 0, 0),
            0x01u32,
            110_000u32,
        ),
        (
            Rdna3Chip::Navi32,
            (11, 0, 3),
            (13, 0, 10),
            (6, 0, 3),
            (3, 2, 0),
            (4, 0, 0),
            0x20u32,
            110_001u32,
        ),
        (
            Rdna3Chip::Navi33,
            (11, 0, 2),
            (13, 0, 7),
            (6, 0, 2),
            (3, 2, 1),
            (4, 0, 4),
            0x10u32,
            110_002u32,
        ),
    ] {
        let versions = chip.ip_versions();
        if versions.gc != gc
            || versions.mp != mp
            || versions.sdma != sdma
            || versions.dcn != dcn
            || versions.vcn != vcn
        {
            return TestResult::Fail("per-die IP versions do not match the firmware sets");
        }
        if chip.gc_version() != gc
            || Rdna3Chip::from_gc(gc) != Some(chip)
            || chip.external_rev(0) != ext
            || chip.gfx_target_version() != gfx
        {
            return TestResult::Fail("per-die GC/external-rev/GFX-target mapping is wrong");
        }
        if !GC_VERSIONS.contains(&gc) || !MP_VERSIONS.contains(&mp) {
            return TestResult::Fail("per-die version missing from the shared tables");
        }
    }
    // The discovered MP versions the platform retains agree with the table.
    let g = gpu();
    let (mp0, mp1) = mp_versions(&g.ip_blocks);
    if mp0 != Some((13, 0, 0)) || mp1 != Some((13, 0, 0)) {
        return TestResult::Fail("Navi31 MP0/MP1 discovery read is wrong");
    }
    let mut nav32 = crate::amdgpu_gfx_navi22::tests::gpu();
    Profile::Navi32.apply(&mut nav32);
    let (mp0, mp1) = mp_versions(&nav32.ip_blocks);
    if mp0 != Some((13, 0, 10)) || mp1 != Some((13, 0, 10)) {
        return TestResult::Fail("Navi32 MP0/MP1 discovery read is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/rdna3", rdna3_per_die_ip_versions_match_linux);

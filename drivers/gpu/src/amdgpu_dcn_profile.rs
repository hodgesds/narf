//! Display layouts verified against Linux dcn_3_0_0/dcn_3_1_2/dcn_3_1_4/dcn_3_1_5/
//! dcn_3_2_0/dcn_3_2_1 headers and dcn30/dcn31/dcn314/dcn315/dcn32/dcn321 resource
//! tables. Register compatibility is block-specific.
//!
//! DCN 3.1.5 (Raphael) is "DCN31 proper": `dcn315_resource.c` builds hubp31,
//! dpp3, mpc31, opp31 and hubbub31 exactly as `dcn314_resource.c` does, and
//! the HUBP/DPP/MPC/OPP registers sit at the same offsets in both headers, so
//! those blocks take [`Profile::Dcn315`] on their DCN 3.1.4 path. The timing
//! generator (optc31, not optc314) has its own register layout in
//! `amdgpu_dcn_otg::layout_shift`; the DIO stream encoder (dcn30's, not
//! dcn314's) takes the DCN30 unblank; the DCCG (dccg31, not dccg314) offers
//! only the operations dccg31 has; the clock manager speaks dcn315_smu.c's
//! SMU 13.0.5 mailbox (`amdgpu_dcn_clk`).
//!
//! DCN 3.1.2 (Rembrandt) is the DCN31 original `dcn31_resource.c` builds:
//! hubp31, dpp3, mpc31, opp31 and hubbub31, four pipes, five stream encoders
//! and five DDC channels, the optc31 timing generator, the dccg31 clock
//! generator, and the dcn31_smu.c display-clock mailbox — which is the
//! dcn314_smu.c mailbox (`amdgpu_dcn_clk::Mailbox::Dcn314`), the same
//! C2PMSG_67/83/91 registers and VBIOSSMC message IDs.
use crate::{amdgpu, amdgpu_dcn_clk::Error, amdgpu_discovery as ip};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Navi22,
    Dcn302,
    Dcn303,
    Dcn314,
    /// Rembrandt (`1002:1681`). See the module doc for which blocks admit it.
    Dcn312,
    /// Raphael (`1002:164E`). See the module doc for which blocks admit it.
    Dcn315,
    /// Navi31 / Navi32: DCN 3.2.0 (`dcn32_resource.c`).
    Dcn320,
    /// Navi33: DCN 3.2.1 (`dcn321_resource.c`).
    Dcn321,
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::{
        amdgpu_dcn_hubp::Hubp,
        amdgpu_dcn_otg::Otg,
        amdgpu_dcn_plane::{Dpp, Mpc, Opp},
        amdgpu_dcn_stream::Stream,
    };
    use narf_capabilities::Cap;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn dcn_navi22_constructors_bound_all_six_instances() -> TestResult {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut dcn = gpu.ip_blocks[0];
        dcn.hw_id = ip::HW_ID_DCN;
        dcn.major = 3;
        dcn.minor = 0;
        dcn.revision = 0;
        dcn.num_bases = 4;
        dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
        gpu.ip_blocks.push(dcn);
        let cap = Cap::bootstrap();
        // SAFETY: constructors only validate the inert maps, never access them.
        unsafe {
            if Otg::new(&gpu, cap, 5).is_err()
                || Hubp::new(&gpu, cap, 5).is_err()
                || Dpp::new(&gpu, cap, 5).is_err()
                || Opp::new(&gpu, cap, 5).is_err()
                || Mpc::new(&gpu, cap, 5).is_err()
                || Stream::new(&gpu, cap, 5).is_err()
                || Otg::new(&gpu, cap, 6).is_ok()
                || Hubp::new(&gpu, cap, 6).is_ok()
                || Dpp::new(&gpu, cap, 6).is_ok()
                || Opp::new(&gpu, cap, 6).is_ok()
                || Mpc::new(&gpu, cap, 6).is_ok()
                || Stream::new(&gpu, cap, 6).is_ok()
            {
                return TestResult::Fail("Navi22 six-instance constructor bounds");
            }
            let len = gpu.regs.len;
            gpu.regs.len = (0x4000 + 0x1e09) * 4 + 3;
            if Otg::new(&gpu, cap, 5).is_ok() {
                return TestResult::Fail("truncated last OTG register admitted");
            }
            gpu.regs.len = len;
        }
        gpu.ip_blocks.last_mut().unwrap().revision = 2;
        if Profile::resolve(&gpu).is_ok() {
            return TestResult::Fail("Navi23 admitted by Navi22 layout");
        }
        gpu.ip_blocks.last_mut().unwrap().revision = 0;
        gpu.ip_blocks.push(dcn);
        if Profile::resolve(&gpu).is_ok() {
            return TestResult::Fail("ambiguous DCN layout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn-profile",
        dcn_navi22_constructors_bound_all_six_instances
    );

    fn dcn_rdna2_constructors_follow_physical_capacity() -> TestResult {
        for (did, revision, capacity) in [
            (0x73bf, 0, 6),
            (0x73df, 0, 6),
            (0x73ff, 2, 5),
            (0x743f, 3, 2),
        ] {
            let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
            gpu.chip.did = did;
            let mut dcn = gpu.ip_blocks[0];
            dcn.hw_id = ip::HW_ID_DCN;
            dcn.instance = 0;
            dcn.major = 3;
            dcn.minor = 0;
            dcn.revision = revision;
            dcn.num_bases = 4;
            dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
            gpu.ip_blocks.push(dcn);
            let cap = Cap::bootstrap();
            for index in 0..=capacity {
                // SAFETY: construction only validates inert mappings.
                let accepted = unsafe {
                    [
                        Otg::new(&gpu, cap, index).is_ok(),
                        Hubp::new(&gpu, cap, index).is_ok(),
                        Dpp::new(&gpu, cap, index).is_ok(),
                        Opp::new(&gpu, cap, index).is_ok(),
                        Mpc::new(&gpu, cap, index).is_ok(),
                        Stream::new(&gpu, cap, index).is_ok(),
                    ]
                };
                if accepted.iter().any(|ok| *ok != (index < capacity)) {
                    return TestResult::Fail("RDNA2 display constructor capacity");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn-profile",
        dcn_rdna2_constructors_follow_physical_capacity
    );
    /// DCN 3.1.5 binds only on Raphael, admits the blocks whose layout is
    /// shared with DCN 3.1.4 or ported (four pipes, as `res_cap_dcn315`), and
    /// refuses the ones whose layouts differ and are not yet ported.
    fn dcn315_admits_shared_blocks_and_refuses_unported_ones() -> TestResult {
        use crate::{amdgpu, amdgpu_dcn_dccg::Dccg};
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut dcn = gpu.ip_blocks[0];
        dcn.hw_id = ip::HW_ID_DCN;
        dcn.instance = 0;
        dcn.major = 3;
        dcn.minor = 1;
        dcn.revision = 5;
        dcn.num_bases = 4;
        dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
        gpu.ip_blocks.push(dcn);
        // Another id carrying DCN 3.1.5 is not Raphael and is not admitted.
        if Profile::resolve(&gpu).is_ok() {
            return TestResult::Fail("DCN 3.1.5 admitted on a non-Raphael id");
        }
        gpu.chip = amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, amdgpu::RAPHAEL)
            .expect("Raphael identity");
        let Ok(profile) = Profile::resolve(&gpu) else {
            return TestResult::Fail("Raphael's DCN 3.1.5 did not resolve");
        };
        if profile != Profile::Dcn315
            || profile.is_dcn30()
            || profile.is_dcn314()
            || (profile.pipes(), profile.streams(), profile.channels()) != (4, 5, 5)
            || !profile.has_plane_power_gating()
        {
            return TestResult::Fail("DCN 3.1.5 resource caps are not dcn315_resource.c's");
        }
        let cap = Cap::bootstrap();
        // SAFETY: constructors only validate the inert maps, never access them.
        unsafe {
            for index in 0..=4 {
                let accepted = [
                    Hubp::new(&gpu, cap, index).is_ok(),
                    Dpp::new(&gpu, cap, index).is_ok(),
                    Mpc::new(&gpu, cap, index).is_ok(),
                    Opp::new(&gpu, cap, index).is_ok(),
                ];
                if accepted.iter().any(|ok| *ok != (index < 4)) {
                    return TestResult::Fail("DCN 3.1.5 shared-block capacity");
                }
            }
            if Otg::new(&gpu, cap, 3).is_err() || Otg::new(&gpu, cap, 4).is_ok() {
                return TestResult::Fail("DCN 3.1.5 OTG capacity");
            }
            if Stream::new(&gpu, cap, 4).is_err() || Stream::new(&gpu, cap, 5).is_ok() {
                return TestResult::Fail("DCN 3.1.5 stream encoder capacity");
            }
            match Dccg::new(&gpu, cap) {
                Ok(dccg) if !dccg.has_pixel_rate_div() => {}
                _ => return TestResult::Fail("DCN 3.1.5 DCCG is dccg31, without K1/K2"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn-profile",
        dcn315_admits_shared_blocks_and_refuses_unported_ones
    );

    /// DCN 3.1.2 binds only on Rembrandt, admits the blocks whose layout is
    /// shared with DCN 3.1.4 or ported (four pipes, as `res_cap_dcn31`), and
    /// refuses the ones whose layouts differ and are not yet ported.
    fn dcn312_admits_shared_blocks_and_refuses_unported_ones() -> TestResult {
        use crate::{amdgpu, amdgpu_dcn_dccg::Dccg};
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut dcn = gpu.ip_blocks[0];
        dcn.hw_id = ip::HW_ID_DCN;
        dcn.instance = 0;
        dcn.major = 3;
        dcn.minor = 1;
        dcn.revision = 2;
        dcn.num_bases = 4;
        dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
        gpu.ip_blocks.push(dcn);
        // Another id carrying DCN 3.1.2 is not Rembrandt and is not admitted.
        if Profile::resolve(&gpu).is_ok() {
            return TestResult::Fail("DCN 3.1.2 admitted on a non-Rembrandt id");
        }
        gpu.chip = amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, amdgpu::REMBRANDT)
            .expect("Rembrandt identity");
        let Ok(profile) = Profile::resolve(&gpu) else {
            return TestResult::Fail("Rembrandt's DCN 3.1.2 did not resolve");
        };
        if profile != Profile::Dcn312
            || profile.is_dcn30()
            || profile.is_dcn314()
            || (profile.pipes(), profile.streams(), profile.channels()) != (4, 5, 5)
            || !profile.has_plane_power_gating()
        {
            return TestResult::Fail("DCN 3.1.2 resource caps are not dcn31_resource.c's");
        }
        let cap = Cap::bootstrap();
        // SAFETY: constructors only validate the inert maps, never access them.
        unsafe {
            for index in 0..=4 {
                let accepted = [
                    Hubp::new(&gpu, cap, index).is_ok(),
                    Dpp::new(&gpu, cap, index).is_ok(),
                    Mpc::new(&gpu, cap, index).is_ok(),
                    Opp::new(&gpu, cap, index).is_ok(),
                ];
                if accepted.iter().any(|ok| *ok != (index < 4)) {
                    return TestResult::Fail("DCN 3.1.2 shared-block capacity");
                }
            }
            if Otg::new(&gpu, cap, 3).is_err() || Otg::new(&gpu, cap, 4).is_ok() {
                return TestResult::Fail("DCN 3.1.2 OTG capacity");
            }
            if Stream::new(&gpu, cap, 4).is_err() || Stream::new(&gpu, cap, 5).is_ok() {
                return TestResult::Fail("DCN 3.1.2 stream encoder capacity");
            }
            match Dccg::new(&gpu, cap) {
                Ok(dccg) if !dccg.has_pixel_rate_div() => {}
                _ => return TestResult::Fail("DCN 3.1.2 DCCG is dccg31, without K1/K2"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn-profile",
        dcn312_admits_shared_blocks_and_refuses_unported_ones
    );

    /// DCN 3.2.0 (Navi31/32) and 3.2.1 (Navi33) resolve to their own
    /// profiles with the resource caps from `dcn32_resource.c` /
    /// `dcn321_resource.c` (4 pipes, 5 streams, 5 channels), and the
    /// OTG constructor bounds all four pipes — DCN 3.2 uses the
    /// 2.0/3.1.4 OTG layout, not the 3.5 one. Shared HUBP/DPP/MPC/OPP
    /// blocks are NOT asserted here: their register tables are the
    /// DCN 3.1.4 ones and the 3.2 port is lane 9's, so they stay
    /// fail-closed for 3.2 until then.
    fn dcn32_resolves_with_four_pipes() -> TestResult {
        for (minor, revision, expected) in
            [(2u8, 0u8, Profile::Dcn320), (2u8, 1u8, Profile::Dcn321)]
        {
            let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
            let mut dcn = gpu.ip_blocks[0];
            dcn.hw_id = ip::HW_ID_DCN;
            dcn.instance = 0;
            dcn.major = 3;
            dcn.minor = minor;
            dcn.revision = revision;
            dcn.num_bases = 4;
            dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
            gpu.ip_blocks.push(dcn);
            let Ok(profile) = Profile::resolve(&gpu) else {
                return TestResult::Fail("DCN 3.2 did not resolve");
            };
            if profile != expected
                || !profile.is_dcn32()
                || profile.is_dcn30()
                || profile.is_dcn314()
                || (profile.pipes(), profile.streams(), profile.channels()) != (4, 5, 5)
                || !profile.has_plane_power_gating()
            {
                return TestResult::Fail("DCN 3.2 resource caps are not dcn32_resource.c's");
            }
            let cap = Cap::bootstrap();
            // SAFETY: constructors only validate the inert maps, never access them.
            unsafe {
                if Otg::new(&gpu, cap, 3).is_err() || Otg::new(&gpu, cap, 4).is_ok() {
                    return TestResult::Fail("DCN 3.2 OTG capacity is not four pipes");
                }
            }
        }
        // (3, 2, 2) is no shipping DCN: still unsupported.
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut dcn = gpu.ip_blocks[0];
        dcn.hw_id = ip::HW_ID_DCN;
        dcn.instance = 0;
        dcn.major = 3;
        dcn.minor = 2;
        dcn.revision = 2;
        dcn.num_bases = 4;
        dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
        gpu.ip_blocks.push(dcn);
        if Profile::resolve(&gpu).is_ok() {
            return TestResult::Fail("DCN 3.2.2 admitted without a resource table");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn-profile", dcn32_resolves_with_four_pipes);
}
impl Profile {
    pub fn is_dcn30(self) -> bool {
        matches!(self, Self::Navi22 | Self::Dcn302 | Self::Dcn303)
    }
    pub fn channels(self) -> u8 {
        match self {
            Self::Navi22 => 6,
            Self::Dcn302 => 5,
            Self::Dcn303 => 2,
            // linux: n/a (literals in dcn31_resource.c: res_cap_dcn31.num_ddc
            // and dcn315_resource.c: res_cap_dcn315.num_ddc)
            Self::Dcn312 | Self::Dcn314 | Self::Dcn315 => 5,
            // linux: n/a (literals in dcn32_resource.c / dcn321_resource.c:
            // res_cap_dcn32.num_ddc / res_cap_dcn321.num_ddc)
            Self::Dcn320 | Self::Dcn321 => 5,
        }
    }
    /// Whether this profile's timing generator, DCCG, stream encoder and
    /// clock manager are the DCN 3.1.4 implementations. False on DCN 3.1.5,
    /// whose blocks are the DCN31 originals at different offsets.
    pub fn is_dcn314(self) -> bool {
        self == Self::Dcn314
    }
    /// Whether this profile is a DCN 3.2 one (Navi31/32 3.2.0, Navi33 3.2.1).
    /// DCN 3.2 agrees with DCN 3.1.4 on every OTG register id the timing
    /// generator touches, so its OTG layout shift is 0 like Dcn314's.
    pub fn is_dcn32(self) -> bool {
        matches!(self, Self::Dcn320 | Self::Dcn321)
    }
    pub fn has_plane_power_gating(self) -> bool {
        self != Self::Dcn303
    }
    pub fn resolve(gpu: &amdgpu::AmdGpu) -> Result<Self, Error> {
        let mut blocks = gpu
            .ip_blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_DCN && b.instance == 0);
        let block = blocks.next().ok_or(Error::Unsupported)?;
        if blocks.next().is_some() {
            return Err(Error::Unsupported);
        }
        match (block.major, block.minor, block.revision) {
            // linux: n/a (DCE_HWIP IP_VERSION(3, 0, 0) case in amdgpu_discovery.c, Navi22 1002:73df)
            (3, 0, 0)
                if gpu.chip.vid == amdgpu::AMD_VENDOR
                    && crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
                        .is_some_and(|p| p.dcn_version == (3, 0, 0)) =>
            {
                Ok(Self::Navi22)
            }
            (3, 0, 2)
                if crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
                    .is_some_and(|p| p.dcn_version == (3, 0, 2)) =>
            {
                Ok(Self::Dcn302)
            }
            (3, 0, 3)
                if crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
                    .is_some_and(|p| p.dcn_version == (3, 0, 3)) =>
            {
                Ok(Self::Dcn303)
            }
            (3, 1, 4) => Ok(Self::Dcn314), // linux: n/a (DCN 3.1.4 path)
            // Bound to the one id that carries it, as DCN 3.1.5 is: Linux's
            // DCN 3.1.2 case covers no other shipping part.
            (3, 1, 2)
                if gpu.chip.vid == amdgpu::AMD_VENDOR && gpu.chip.did == amdgpu::REMBRANDT =>
            {
                Ok(Self::Dcn312)
            }
            // Bound to the one id that carries it, as the RDNA2 profiles are:
            // Linux's DCN 3.1.5 case covers no other shipping part.
            (3, 1, 5) if gpu.chip.vid == amdgpu::AMD_VENDOR && gpu.chip.did == amdgpu::RAPHAEL => {
                Ok(Self::Dcn315)
            }
            // DCN 3.2.0 is Navi31 / Navi32 and DCN 3.2.1 is Navi33 (corrected
            // die pairing, RDNA3 programme record): the two resource tables
            // carry identical 4/5/5 caps, and no other shipping part reports
            // either version, so both arms stay unguarded like Dcn314's.
            (3, 2, 0) => Ok(Self::Dcn320), // linux: n/a (DCN 3.2.0 path)
            (3, 2, 1) => Ok(Self::Dcn321), // linux: n/a (DCN 3.2.1 path)
            _ => Err(Error::Unsupported),
        }
    }
    pub fn pipes(self) -> u8 {
        match self {
            // linux: n/a (literal in dcn30_resource.c: res_cap_dcn3.num_timing_generator)
            Self::Navi22 => 6,
            Self::Dcn302 => 5,
            Self::Dcn303 => 2,
            Self::Dcn314 => 4, // linux: n/a (DCN 3.1.4 path)
            // linux: n/a (literals in dcn31_resource.c:
            // res_cap_dcn31.num_timing_generator and dcn315_resource.c:
            // res_cap_dcn315.num_timing_generator)
            Self::Dcn312 | Self::Dcn315 => 4,
            // linux: n/a (literals in dcn32_resource.c / dcn321_resource.c:
            // res_cap_dcn32.num_timing_generator / res_cap_dcn321.num_timing_generator)
            Self::Dcn320 | Self::Dcn321 => 4,
        }
    }
    pub fn streams(self) -> u8 {
        match self {
            // linux: n/a (literal in dcn30_resource.c: res_cap_dcn3.num_stream_encoder)
            Self::Navi22 => 6,
            Self::Dcn302 => 5,
            Self::Dcn303 => 2,
            Self::Dcn314 => 5, // linux: n/a (DCN 3.1.4 path)
            // linux: n/a (literals in dcn31_resource.c:
            // res_cap_dcn31.num_stream_encoder and dcn315_resource.c:
            // res_cap_dcn315.num_stream_encoder)
            Self::Dcn312 | Self::Dcn315 => 5,
            // linux: n/a (literals in dcn32_resource.c / dcn321_resource.c:
            // res_cap_dcn32.num_stream_encoder / res_cap_dcn321.num_stream_encoder)
            Self::Dcn320 | Self::Dcn321 => 5,
        }
    }
    pub fn bank(self, gpu: &amdgpu::AmdGpu, index: usize, last: u32) -> Result<u64, Error> {
        let versions: &[(u8, u8, u8)] = match self {
            Self::Dcn302 => &[(3, 0, 2)],
            Self::Dcn303 => &[(3, 0, 3)],
            Self::Navi22 => &[(3, 0, 0)], // linux: n/a (DCE_HWIP IP_VERSION(3, 0, 0))
            Self::Dcn314 => &[(3, 1, 4)], // linux: n/a (DCN 3.1.4 path)
            Self::Dcn312 => &[(3, 1, 2)], // linux: n/a (DCE_HWIP IP_VERSION(3, 1, 2))
            Self::Dcn315 => &[(3, 1, 5)], // linux: n/a (DCE_HWIP IP_VERSION(3, 1, 5))
            Self::Dcn320 => &[(3, 2, 0)], // linux: n/a (DCN 3.2.0 path)
            Self::Dcn321 => &[(3, 2, 1)], // linux: n/a (DCN 3.2.1 path)
        };
        crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_DCN, versions, index, last)
            .map_err(|_| Error::Unsupported)
    }
}

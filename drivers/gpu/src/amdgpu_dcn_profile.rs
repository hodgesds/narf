//! Display layouts verified against Linux dcn_3_0_0/dcn_3_1_4/dcn_3_1_5
//! headers and dcn30/dcn314/dcn315 resource tables. Register compatibility
//! is block-specific.
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
use crate::{amdgpu, amdgpu_dcn_clk::Error, amdgpu_discovery as ip};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Navi22,
    Dcn302,
    Dcn303,
    Dcn314,
    /// Raphael (`1002:164E`). See the module doc for which blocks admit it.
    Dcn315,
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
            // linux: n/a (literal in dcn315_resource.c: res_cap_dcn315.num_ddc)
            Self::Dcn314 | Self::Dcn315 => 5,
        }
    }
    /// Whether this profile's timing generator, DCCG, stream encoder and
    /// clock manager are the DCN 3.1.4 implementations. False on DCN 3.1.5,
    /// whose blocks are the DCN31 originals at different offsets.
    pub fn is_dcn314(self) -> bool {
        self == Self::Dcn314
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
            // Bound to the one id that carries it, as the RDNA2 profiles are:
            // Linux's DCN 3.1.5 case covers no other shipping part.
            (3, 1, 5) if gpu.chip.vid == amdgpu::AMD_VENDOR && gpu.chip.did == amdgpu::RAPHAEL => {
                Ok(Self::Dcn315)
            }
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
            // linux: n/a (literal in dcn315_resource.c: res_cap_dcn315.num_timing_generator)
            Self::Dcn315 => 4,
        }
    }
    pub fn streams(self) -> u8 {
        match self {
            // linux: n/a (literal in dcn30_resource.c: res_cap_dcn3.num_stream_encoder)
            Self::Navi22 => 6,
            Self::Dcn302 => 5,
            Self::Dcn303 => 2,
            Self::Dcn314 => 5, // linux: n/a (DCN 3.1.4 path)
            // linux: n/a (literal in dcn315_resource.c: res_cap_dcn315.num_stream_encoder)
            Self::Dcn315 => 5,
        }
    }
    pub fn bank(self, gpu: &amdgpu::AmdGpu, index: usize, last: u32) -> Result<u64, Error> {
        let versions: &[(u8, u8, u8)] = match self {
            Self::Dcn302 => &[(3, 0, 2)],
            Self::Dcn303 => &[(3, 0, 3)],
            Self::Navi22 => &[(3, 0, 0)], // linux: n/a (DCE_HWIP IP_VERSION(3, 0, 0))
            Self::Dcn314 => &[(3, 1, 4)], // linux: n/a (DCN 3.1.4 path)
            Self::Dcn315 => &[(3, 1, 5)], // linux: n/a (DCE_HWIP IP_VERSION(3, 1, 5))
        };
        crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_DCN, versions, index, last)
            .map_err(|_| Error::Unsupported)
    }
}

//! Display layouts verified against Linux dcn_3_0_0/dcn_3_1_4 headers and
//! dcn30/dcn314 resource tables. Register compatibility is block-specific.
use crate::{amdgpu, amdgpu_dcn_clk::Error, amdgpu_discovery as ip};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Navi22,
    Dcn314,
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
}
impl Profile {
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
            (3, 0, 0) if gpu.chip.vid == amdgpu::AMD_VENDOR && gpu.chip.did == amdgpu::NAVI22 => {
                Ok(Self::Navi22)
            }
            (3, 1, 4) => Ok(Self::Dcn314),
            _ => Err(Error::Unsupported),
        }
    }
    pub fn pipes(self) -> u8 {
        match self {
            Self::Navi22 => 6,
            Self::Dcn314 => 4,
        }
    }
    pub fn streams(self) -> u8 {
        match self {
            Self::Navi22 => 6,
            Self::Dcn314 => 5,
        }
    }
    pub fn bank(self, gpu: &amdgpu::AmdGpu, index: usize, last: u32) -> Result<u64, Error> {
        let versions: &[(u8, u8, u8)] = match self {
            Self::Navi22 => &[(3, 0, 0)],
            Self::Dcn314 => &[(3, 1, 4)],
        };
        crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_DCN, versions, index, last)
            .map_err(|_| Error::Unsupported)
    }
}

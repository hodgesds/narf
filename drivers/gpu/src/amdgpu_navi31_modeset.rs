//! Navi31 / Navi32 (DCN 3.2.0) and Navi33 (DCN 3.2.1) modeset owner.
//!
//! The owner resolves the DCN profile from discovery, refuses anything
//! that is not DCN 3.2, bounds the pipe to the profile's four pipes, and
//! builds the DCN 3.2 modeset sequence for that pipe. It programs nothing
//! itself: callers execute the returned writes through
//! `amdgpu_dcn::execute_modeset` (or `apply_modeset_plan` on the KMS path).
//!
//! Out of scope: link training, DSC/MST, UHBR/HPO, clocks/DCCG and DML32
//! (lane 9), and HPD subscriptions (the IH lane). The sequence assumes the
//! panel/link is in its firmware-programmed state, as the DCN 2.0 path does.

use crate::amdgpu::AmdGpu;
use crate::amdgpu_dcn::{dcn32_modeset_sequence, DcnWrite, ModeTiming};
use crate::amdgpu_dcn_profile::Profile;
use crate::amdgpu_discovery::HW_ID_DCN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No DCN block in discovery, an ambiguous one, or a DCN version
    /// that is not 3.2.0 / 3.2.1.
    Unsupported,
    /// The DCN block is undiscoverable, so no register base exists.
    NoDcnBase,
    /// The pipe is not a DCN 3.2 pipe (`pipe >= profile.pipes()`).
    BadPipe,
}

/// A bound DCN 3.2 modeset owner for one pipe.
#[derive(Clone, Copy, Debug)]
pub struct Navi31Modeset {
    profile: Profile,
    dcn_base: u32,
    pipe: u8,
}

impl Navi31Modeset {
    /// Bind pipe `pipe` on `gpu`. Fails closed unless discovery reports
    /// a single DCN 3.2.0 / 3.2.1 block and the pipe is one of its four.
    pub fn for_gpu(gpu: &AmdGpu, pipe: u8) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu).map_err(|_| Error::Unsupported)?;
        if !profile.is_dcn32() {
            return Err(Error::Unsupported);
        }
        if pipe >= profile.pipes() {
            return Err(Error::BadPipe);
        }
        let dcn_base = gpu.ip_block_base(HW_ID_DCN, 0).ok_or(Error::NoDcnBase)?;
        Ok(Self {
            profile,
            dcn_base,
            pipe,
        })
    }

    /// The resolved DCN 3.2 profile (3.2.0 on Navi31/32, 3.2.1 on Navi33).
    /// Crate-visible only: `Profile` itself is `pub(crate)`.
    pub(crate) fn profile(&self) -> Profile {
        self.profile
    }

    /// The bound pipe.
    pub fn pipe(&self) -> u8 {
        self.pipe
    }

    /// Pipes on this DCN (4 on both 3.2.0 and 3.2.1).
    pub fn pipes(&self) -> u8 {
        self.profile.pipes()
    }

    /// The full modeset write sequence for `timing` on the bound pipe.
    /// `None` only when the bound pipe stopped being valid, which
    /// `for_gpu` already excluded — the `Option` is the sequence
    /// builder's fail-closed contract, not a second validation.
    pub fn sequence(
        &self,
        timing: &ModeTiming,
        surface_addr_bytes: u64,
        stride_pixels: u32,
    ) -> Option<alloc::vec::Vec<DcnWrite>> {
        dcn32_modeset_sequence(
            timing,
            surface_addr_bytes,
            stride_pixels,
            self.dcn_base,
            self.pipe,
        )
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use crate::amdgpu_dcn::timing_for_mode;
    use crate::amdgpu_discovery as ip;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn gpu_with_dcn(major: u8, minor: u8, revision: u8) -> AmdGpu {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut dcn = gpu.ip_blocks[0];
        dcn.hw_id = ip::HW_ID_DCN;
        dcn.instance = 0;
        dcn.major = major;
        dcn.minor = minor;
        dcn.revision = revision;
        dcn.num_bases = 4;
        dcn.base_addrs[..4].copy_from_slice(&[0, 0x1000, 0x4000, 0x9000]);
        gpu.ip_blocks.push(dcn);
        gpu
    }

    fn navi31_modeset_owner_binds_only_dcn32() -> TestResult {
        // DCN 3.2.0 binds pipes 0..3 and refuses pipe 4.
        let gpu = gpu_with_dcn(3, 2, 0);
        let owner = match Navi31Modeset::for_gpu(&gpu, 3) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("DCN 3.2.0 pipe 3 refused"),
        };
        if owner.profile() != Profile::Dcn320 || owner.pipe() != 3 || owner.pipes() != 4 {
            return TestResult::Fail("DCN 3.2.0 owner state wrong");
        }
        if !matches!(Navi31Modeset::for_gpu(&gpu, 4), Err(Error::BadPipe)) {
            return TestResult::Fail("pipe 4 admitted on a four-pipe DCN");
        }
        // DCN 3.2.1 binds too (Navi33), with the 3.2.1 profile.
        let gpu = gpu_with_dcn(3, 2, 1);
        match Navi31Modeset::for_gpu(&gpu, 0) {
            Ok(o) if o.profile() == Profile::Dcn321 => {}
            _ => return TestResult::Fail("DCN 3.2.1 did not bind"),
        }
        // DCN 3.1.4 / 3.0.0 / 3.5.0 are not DCN 3.2: refused.
        for (minor, revision) in [(1u8, 4u8), (0u8, 0u8), (5u8, 0u8)] {
            let gpu = gpu_with_dcn(3, minor, revision);
            if !matches!(Navi31Modeset::for_gpu(&gpu, 0), Err(Error::Unsupported)) {
                return TestResult::Fail("non-3.2 DCN admitted by the 3.2 owner");
            }
        }
        // No DCN block at all: refused.
        let gpu = crate::amdgpu_navi22_boot::tests::gpu();
        if !matches!(Navi31Modeset::for_gpu(&gpu, 0), Err(Error::Unsupported)) {
            return TestResult::Fail("missing DCN admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-navi31-modeset",
        navi31_modeset_owner_binds_only_dcn32
    );

    fn navi31_modeset_sequence_uses_the_bound_pipe() -> TestResult {
        let timing = match timing_for_mode(1920, 1080, 60) {
            Some(t) => t,
            None => return TestResult::Fail("FHD@60 missing"),
        };
        // The fixture DCN base is base_addrs[0] = 0.
        let gpu = gpu_with_dcn(3, 2, 0);
        let owner = match Navi31Modeset::for_gpu(&gpu, 2) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("DCN 3.2.0 pipe 2 refused"),
        };
        let seq = match owner.sequence(&timing, 0x8000_0000, 1920) {
            Some(s) => s,
            None => return TestResult::Fail("bound pipe produced no sequence"),
        };
        // Pipe 2's OTG_CONTROL sits at 0x1b41 + 2*0x80 = 0x1c41, and the
        // sequence ends by asserting MASTER_EN there.
        let last = match seq.last().copied() {
            Some(w) => w,
            None => return TestResult::Fail("sequence empty"),
        };
        if last.addr != 0x1b41 + 2 * 0x80 || last.value != crate::amdgpu_dcn::OTG_MASTER_EN {
            return TestResult::Fail("pipe-2 master enable at the wrong OTG");
        }
        // Pipe 2's HUBP blank strides by 2*0xdc from pipe 0's.
        if seq.first().copied()
            != Some(DcnWrite {
                addr: 0x05f3 + 2 * 0xdc,
                value: crate::amdgpu_dcn::HUBP_BLANK_FORCE,
            })
        {
            return TestResult::Fail("pipe-2 HUBP blank at the wrong stride");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-navi31-modeset",
        navi31_modeset_sequence_uses_the_bound_pipe
    );
}

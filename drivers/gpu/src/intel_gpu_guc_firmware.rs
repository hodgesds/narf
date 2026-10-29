//! Xe-LPG and discrete GuC image acquisition. Registry authority and device authentication
//! are separate: this module authorizes a bounded immutable copy; GuC boot ROM
//! must authenticate the vendor RSA signature before transport is enabled.

use crate::intel_gpu::Generation;
use crate::intel_gpu_gt::{GtPlatform, GuCProfile};
use crate::intel_gpu_guc::{CssImage, GuCError};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

pub const XE_LPG_GUC_NAME: &str = "i915/mtl_guc_70.bin";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    Unsupported,
    Revoked,
    Registry(narf_firmware::FirmwareError),
    Image(GuCError),
    Allocation,
}

#[derive(Debug)]
pub struct GuCFirmware {
    bytes: Vec<u8>,
    platform: GtPlatform,
    pub digest: [u8; 32],
    pub signer: Option<[u8; 32]>,
}

struct Open(GuCProfile);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<GuCFirmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0.firmware, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(FirmwareError::Registry(error))),
        };
        blob.invoke(CopyImage(self.0))
    }
}

struct CopyImage(GuCProfile);
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<GuCFirmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            validate(self.0, view.bytes)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(GuCFirmware {
                bytes,
                platform: self.0.platform,
                digest: view.sha256,
                signer: view.signer,
            })
        })())
    }
}

fn validate(profile: GuCProfile, bytes: &[u8]) -> Result<CssImage<'_>, FirmwareError> {
    let image = CssImage::parse(bytes, 70).map_err(FirmwareError::Image)?;
    // Pin each platform's baseline (MIT xe_uc_fw.c). A matching
    // major alone must not accept older firmware with missing actions/ABIs.
    if image.version < profile.minimum_version || image.signature.len() != 384 {
        return Err(FirmwareError::Image(GuCError::FirmwareVersion));
    }
    Ok(image)
}

impl GuCFirmware {
    pub fn open(
        generation: Generation,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        Self::open_for_platform(GtPlatform::Integrated(generation), authority)
    }

    pub fn open_for_platform(
        platform: GtPlatform,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        let profile = platform.guc().ok_or(FirmwareError::Unsupported)?;
        authority
            .invoke(Open(profile))
            .map_err(|_| FirmwareError::Revoked)?
    }

    pub fn platform(&self) -> GtPlatform {
        self.platform
    }

    pub fn image(&self) -> CssImage<'_> {
        validate(
            self.platform.guc().expect("authorized platform"),
            &self.bytes,
        )
        .expect("immutable authorized GuC image")
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::intel_gpu_uapi::put32;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_xelpg_firmware_authority_and_version() -> TestResult {
        let (write, read) = narf_firmware::bootstrap_authority();
        write.revoke();
        if !matches!(
            GuCFirmware::open(Generation::MeteorLake, &read),
            Err(FirmwareError::Revoked)
        ) || !matches!(
            GuCFirmware::open(Generation::PantherLake, &read),
            Err(FirmwareError::Unsupported)
        ) {
            return TestResult::Fail("firmware acquisition bypassed authority or generation");
        }
        // CSS 32dw + uCode 4dw + RSA96dw, optional modulus/exponent omitted.
        let mut bytes = alloc::vec![0; 528];
        for (offset, value) in [
            (0, 6),
            (4, 225),
            (8, 0x10000),
            (16, 0x8086),
            (24, 229),
            (28, 96),
            (32, 96),
            (36, 1),
            (64, 0x0046_3500),
        ] {
            put32(&mut bytes, offset, value);
        }
        let profile = GtPlatform::Integrated(Generation::MeteorLake)
            .guc()
            .unwrap();
        if validate(profile, &bytes).is_err() {
            return TestResult::Fail("supported CSS layout rejected");
        }
        put32(&mut bytes, 64, 0x0046_3400);
        if !matches!(
            validate(profile, &bytes),
            Err(FirmwareError::Image(GuCError::FirmwareVersion))
        ) {
            return TestResult::Fail("older Xe-LPG GuC firmware admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_firmware",
        smoke_xelpg_firmware_authority_and_version
    );
}

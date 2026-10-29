//! Xe-LPG GuC image acquisition. Registry authority and device authentication
//! are separate: this module authorizes a bounded immutable copy; GuC boot ROM
//! must authenticate the vendor RSA signature before transport is enabled.

use crate::intel_gpu::Generation;
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
    pub digest: [u8; 32],
    pub signer: Option<[u8; 32]>,
}

struct Open;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<GuCFirmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(XE_LPG_GUC_NAME, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(FirmwareError::Registry(error))),
        };
        blob.invoke(CopyImage)
    }
}

struct CopyImage;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<GuCFirmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            validate(view.bytes)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(GuCFirmware {
                bytes,
                digest: view.sha256,
                signer: view.signer,
            })
        })())
    }
}

fn validate(bytes: &[u8]) -> Result<CssImage<'_>, FirmwareError> {
    let image = CssImage::parse(bytes, 70).map_err(FirmwareError::Image)?;
    // Pin the supported MTL baseline (MIT i915 intel_uc_fw.c). A matching
    // major alone must not accept older firmware with missing actions/ABIs.
    if image.version < (70, 53, 0) || image.signature.len() != 384 {
        return Err(FirmwareError::Image(GuCError::FirmwareVersion));
    }
    Ok(image)
}

impl GuCFirmware {
    pub fn open(
        generation: Generation,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        // Arrow Lake is classified as MeteorLake in the canonical device table.
        if generation != Generation::MeteorLake {
            return Err(FirmwareError::Unsupported);
        }
        authority.invoke(Open).map_err(|_| FirmwareError::Revoked)?
    }

    pub fn image(&self) -> CssImage<'_> {
        validate(&self.bytes).expect("immutable authorized GuC image")
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
        if validate(&bytes).is_err() {
            return TestResult::Fail("supported CSS layout rejected");
        }
        put32(&mut bytes, 64, 0x0046_3400);
        if !matches!(
            validate(&bytes),
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

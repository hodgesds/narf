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

fn lookup_guc<T>(
    profile: GuCProfile,
    mut open: impl FnMut(&str) -> Result<T, narf_firmware::FirmwareError>,
) -> Result<T, narf_firmware::FirmwareError> {
    match open(profile.firmware) {
        // Linux 7.0-rc7 xe_uc_fw.c uses mmp_ver for NOVALAKE_S. Newer
        // firmware packages provide the major-version filename.
        Err(narf_firmware::FirmwareError::NotFound)
            if profile.platform == GtPlatform::NovaLakeS =>
        {
            open("xe/nvl_guc_70.55.4.bin")
        }
        result => result,
    }
}

impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<GuCFirmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match lookup_guc(self.0, |name| narf_firmware::open(name, cap)) {
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
    if image.version < profile.minimum_version {
        return Err(FirmwareError::Image(GuCError::FirmwareVersion));
    }
    if profile.rsa_transfer(image.signature.len()).is_none() {
        return Err(FirmwareError::Image(GuCError::FirmwareLayout));
    }
    Ok(image)
}

impl GuCFirmware {
    pub fn open(
        generation: Generation,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        let platform = match generation {
            Generation::TigerLake => {
                GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake)
            }
            Generation::RocketLake => {
                GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::RocketLake)
            }
            // ADL spans different firmware families; an ambiguous generation
            // cannot choose ADL-P versus ADL-S/N's asset. Use PCI identity.
            Generation::AlderLake => return Err(FirmwareError::Unsupported),
            // Gen11 spans different firmware families the same way
            // (ICL takes `icl_guc`, EHL/JSL take `ehl_guc`); an
            // ambiguous generation cannot choose. Use PCI identity
            // (`open_for_platform` with the `Gen11` sub-platform).
            Generation::IceLake => return Err(FirmwareError::Unsupported),
            // Gen9 spans different firmware families the same way
            // (SKL takes `skl_guc`, KBL/CFL/WHL take `kbl_guc`,
            // CML takes `kbl_guc` at rev < 5 and `cml_guc` at
            // rev >= 5); an ambiguous generation cannot choose.
            // Use PCI identity (`open_for_platform` with the
            // `Gen9` sub-platform).
            Generation::Skylake => return Err(FirmwareError::Unsupported),
            _ => GtPlatform::Integrated(generation),
        };
        Self::open_for_platform(platform, authority)
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

    /// Native-test image from fixture bytes, with the registry path's exact
    /// profile/version/signature validation. Not reachable in production.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn from_fixture(platform: GtPlatform, bytes: &[u8]) -> Result<Self, FirmwareError> {
        validate(platform.guc().ok_or(FirmwareError::Unsupported)?, bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            platform,
            digest: [0; 32],
            signer: None,
        })
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::intel_gpu_gt::Gen11Platform;
    use crate::intel_gpu_uapi::put32;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_nova_guc_firmware_names() -> TestResult {
        use narf_firmware::FirmwareError::{NotFound, SignatureInvalid};
        let nova = GtPlatform::NovaLakeS.guc().unwrap();
        for first in [Ok(1), Err(NotFound), Err(SignatureInvalid)] {
            let mut calls = 0;
            let found = lookup_guc(nova, |name| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(name, "xe/nvl_guc_70.bin");
                    first
                } else {
                    assert_eq!(name, "xe/nvl_guc_70.55.4.bin");
                    Ok(2)
                }
            });
            if first == Err(NotFound) {
                assert_eq!((found, calls), (Ok(2), 2));
            } else {
                assert_eq!((found, calls), (first, 1));
            }
        }
        let missing = lookup_guc(GtPlatform::WildcatLake.guc().unwrap(), |name| {
            assert_eq!(name, "xe/ptl_guc_70.bin");
            Err::<(), _>(NotFound)
        });
        assert_eq!(missing, Err(NotFound));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_firmware",
        smoke_nova_guc_firmware_names
    );

    fn smoke_xelpg_firmware_authority_and_version() -> TestResult {
        let (write, read) = narf_firmware::bootstrap_authority();
        write.revoke();
        if !matches!(
            GuCFirmware::open(Generation::MeteorLake, &read),
            Err(FirmwareError::Revoked)
        ) || !matches!(
            GuCFirmware::open(Generation::PantherLake, &read),
            Err(FirmwareError::Revoked)
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

    fn smoke_gen11_guc_firmware_minimum_version() -> TestResult {
        // Lane 7 item 1: Lane 1's Gen11 profiles, verified against Linux
        // `gt/uc/intel_uc_fw.c` `INTEL_GUC_FIRMWARE_DEFS` —
        // `guc_mmp(icl, 70, 1, 1)` / `guc_mmp(ehl, 70, 1, 1)`. For a
        // legacy `_mmp` entry the triple is both the filename suffix and
        // the minimum version (Linux `intel_uc_fw.c` `got_wanted`:
        // selected >= wanted), the same rule the TGL (70, 44, 1) pin
        // follows for its major-only blob.
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
            (64, 0x0046_0101),
        ] {
            put32(&mut bytes, offset, value);
        }
        for platform in [
            GtPlatform::Gen11(Gen11Platform::IceLake),
            GtPlatform::Gen11(Gen11Platform::ElkhartLake),
            GtPlatform::Gen11(Gen11Platform::JasperLake),
        ] {
            if GuCFirmware::from_fixture(platform, &bytes).is_err() {
                return TestResult::Fail("Gen11 GuC 70.1.1 firmware rejected");
            }
        }
        // One patch below the minimum is refused on every Gen11 profile.
        put32(&mut bytes, 64, 0x0046_0100);
        for platform in [
            GtPlatform::Gen11(Gen11Platform::IceLake),
            GtPlatform::Gen11(Gen11Platform::ElkhartLake),
            GtPlatform::Gen11(Gen11Platform::JasperLake),
        ] {
            if !matches!(
                GuCFirmware::from_fixture(platform, &bytes),
                Err(FirmwareError::Image(GuCError::FirmwareVersion))
            ) {
                return TestResult::Fail("Gen11 GuC 70.1.0 firmware admitted");
            }
        }
        // A newer patch is accepted: the tuple is a minimum, not an
        // exact pin.
        put32(&mut bytes, 64, 0x0046_0102);
        if GuCFirmware::from_fixture(GtPlatform::Gen11(Gen11Platform::IceLake), &bytes).is_err() {
            return TestResult::Fail("Gen11 GuC 70.1.2 firmware rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_firmware",
        smoke_gen11_guc_firmware_minimum_version
    );
}

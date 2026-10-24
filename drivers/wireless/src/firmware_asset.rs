// SPDX-License-Identifier: GPL-2.0-or-later
//! Current firmware capabilities terminate at an owned copy, never a borrowed
//! registry view. Executable developer policy stays with narf-firmware; board
//! identity/calibration/regulatory assets can require a verified signer.
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError, FirmwareRegistry};

#[derive(Debug)]
pub(crate) struct Asset {
    pub bytes: Vec<u8>,
    pub cap: Cap<FirmwareBlob, Read>,
    pub signer: Option<[u8; 32]>,
    pub digest: [u8; 32],
}
impl Asset {
    pub fn current(&self) -> bool {
        self.cap.invoke(NoopOp).is_ok()
    }
}
struct Open<'a>(&'a str);
impl CapOp<FirmwareRegistry, Read> for Open<'_> {
    type Output = Result<Cap<FirmwareBlob, Read>, FirmwareError>;
    fn execute(self, cap: &Cap<FirmwareRegistry, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::open(self.0, cap))
    }
}
struct Copy<'a> {
    name: &'a str,
    maximum: usize,
    signer: bool,
}
impl CapOp<FirmwareBlob, Read> for Copy<'_> {
    type Output = Result<Asset, FirmwareError>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap)?;
            if view.name != self.name || view.bytes.is_empty() || view.bytes.len() > self.maximum {
                return Err(FirmwareError::BadFormat);
            }
            if self.signer && view.signer.is_none() {
                return Err(FirmwareError::UnsignedRejected);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::OutOfMemory)?;
            bytes.extend_from_slice(view.bytes);
            Ok(Asset {
                bytes,
                cap: *cap,
                signer: view.signer,
                digest: view.sha256,
            })
        })())
    }
}
pub(crate) fn load(
    authority: &Cap<FirmwareRegistry, Read>,
    name: &str,
    maximum: usize,
    signer: bool,
) -> Result<Asset, FirmwareError> {
    let cap = authority
        .invoke(Open(name))
        .map_err(|_| FirmwareError::AuthorityRevoked)??;
    copy(&cap, name, maximum, signer)
}
fn copy(
    cap: &Cap<FirmwareBlob, Read>,
    name: &str,
    maximum: usize,
    signer: bool,
) -> Result<Asset, FirmwareError> {
    cap.invoke(Copy {
        name,
        maximum,
        signer,
    })
    .map_err(|_| FirmwareError::AuthorityRevoked)?
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    pub(crate) fn install(
        authority: &Cap<FirmwareRegistry, narf_capabilities::Write>,
        name: &'static str,
        payload: &[u8],
        signed: bool,
    ) -> Result<(), FirmwareError> {
        let mut bytes = payload.to_vec();
        if signed {
            let seed = [0x73; 32];
            let public = narf_crypto::ed25519::ed25519_public_key(&seed);
            let mut digest = narf_crypto::sha256::Sha256::new();
            digest.update(&public);
            let fingerprint = digest.finalize();
            narf_firmware::register_trusted_signer(fingerprint, public);
            bytes.extend_from_slice(&narf_crypto::ed25519::ed25519_sign(
                &seed,
                &narf_crypto::blake3_hash(payload),
            ));
            bytes.extend_from_slice(&fingerprint);
        } else {
            bytes.extend_from_slice(&[0; 96]);
        }
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(b"NRFW");
        struct Install<'a> {
            name: &'static str,
            bytes: &'a [u8],
        }
        impl CapOp<FirmwareRegistry, narf_capabilities::Write> for Install<'_> {
            type Output = Result<(), FirmwareError>;
            fn execute(
                self,
                cap: &Cap<FirmwareRegistry, narf_capabilities::Write>,
            ) -> Result<Self::Output, CapError> {
                Ok(narf_firmware::install(self.name, self.bytes, cap))
            }
        }
        authority
            .invoke(Install {
                name,
                bytes: &bytes,
            })
            .map_err(|_| FirmwareError::AuthorityRevoked)?
    }
    fn smoke_wireless_asset_real_registry_epochs_owned_copy_and_bounds() -> TestResult {
        let (_, read) = crate::brcmfmac::provision::tests::registry().unwrap();
        let name = "narf-test/brcm/fw";
        let asset = load(&read, name, 8, true).unwrap();
        if asset.bytes != [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6]
            || !asset.current()
            || asset.signer.is_none()
            || !matches!(load(&read, name, 7, true), Err(FirmwareError::BadFormat))
            || !matches!(
                copy(&asset.cap, "narf-test/brcm/nv", 8, true),
                Err(FirmwareError::BadFormat)
            )
        {
            return TestResult::Fail(
                "current owned asset copy ignored exact identity, signer or extent",
            );
        }
        asset.cap.revoke();
        if asset.current()
            || !matches!(
                copy(&asset.cap, name, 8, true),
                Err(FirmwareError::AuthorityRevoked)
            )
            || asset.bytes != [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6]
        {
            return TestResult::Fail(
                "revoked source cap remained usable or invalidated owned copy",
            );
        }
        read.revoke();
        if !matches!(
            load(&read, name, 8, true),
            Err(FirmwareError::AuthorityRevoked)
        ) {
            return TestResult::Fail("revoked registry authority opened firmware asset");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/firmware_asset",
        smoke_wireless_asset_real_registry_epochs_owned_copy_and_bounds
    );
}

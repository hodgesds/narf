// SPDX-License-Identifier: GPL-2.0-or-later
//! Immutable executable copies produced only inside current registry/blob ops.
use super::firmware_transport::Error;
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareRegistry};
struct Open<'a>(&'a str);
impl CapOp<FirmwareRegistry, Read> for Open<'_> {
    type Output = Result<Cap<FirmwareBlob, Read>, narf_firmware::FirmwareError>;
    fn execute(self, cap: &Cap<FirmwareRegistry, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::open(self.0, cap))
    }
}
struct Copy<'a>(&'a str);
impl CapOp<FirmwareBlob, Read> for Copy<'_> {
    type Output = Result<Vec<u8>, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| Error::Authority)?;
            if view.name != self.0 || view.bytes.is_empty() || view.bytes.len() > 16 * 1024 * 1024 {
                return Err(Error::InvalidFirmware);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
pub(super) fn load(authority: &Cap<FirmwareRegistry, Read>, name: &str) -> Result<Vec<u8>, Error> {
    let cap = authority
        .invoke(Open(name))
        .map_err(|_| Error::Authority)?
        .map_err(|_| Error::InvalidFirmware)?;
    copy(&cap, name)
}
fn copy(cap: &Cap<FirmwareBlob, Read>, name: &str) -> Result<Vec<u8>, Error> {
    cap.invoke(Copy(name)).map_err(|_| Error::Authority)?
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use super::*;
    use narf_capabilities::Write;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Install<'a>(&'a [u8]);
    impl CapOp<FirmwareRegistry, Write> for Install<'_> {
        type Output = Result<(), narf_firmware::FirmwareError>;
        fn execute(self, cap: &Cap<FirmwareRegistry, Write>) -> Result<Self::Output, CapError> {
            Ok(narf_firmware::install("narf-test/mt76/asset", self.0, cap))
        }
    }
    fn smoke_mt76_firmware_owned_copy_actual_registry_and_blob_epoch() -> TestResult {
        let payload = b"isolated-mt76-asset";
        let seed = [0x72; 32];
        let public = narf_crypto::ed25519::ed25519_public_key(&seed);
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(&public);
        let fingerprint = digest.finalize();
        narf_firmware::register_trusted_signer(fingerprint, public);
        let mut envelope = payload.to_vec();
        envelope.extend_from_slice(&narf_crypto::ed25519::ed25519_sign(
            &seed,
            &narf_crypto::blake3_hash(payload),
        ));
        envelope.extend_from_slice(&fingerprint);
        envelope.extend_from_slice(&[0; 4]);
        envelope.extend_from_slice(b"NRFW");
        let (write, read) = narf_firmware::bootstrap_authority();
        if !matches!(write.invoke(Install(&envelope)), Ok(Ok(()))) {
            return TestResult::Fail("MT76 signed registry fixture install");
        }
        let name = "narf-test/mt76/asset";
        let cap = read.invoke(Open(name)).unwrap().unwrap();
        let bytes = copy(&cap, name).unwrap();
        if bytes != payload || load(&read, name).as_deref() != Ok(payload.as_slice()) {
            return TestResult::Fail("MT76 registry copy changed exact payload");
        }
        cap.revoke();
        if !matches!(copy(&cap, name), Err(Error::Authority)) || bytes != payload {
            return TestResult::Fail("MT76 revoked source read or owned bytes invalidated");
        }
        read.revoke();
        if !matches!(load(&read, name), Err(Error::Authority)) {
            return TestResult::Fail("MT76 revoked registry was reopened");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/firmware",
        smoke_mt76_firmware_owned_copy_actual_registry_and_blob_epoch
    );
}

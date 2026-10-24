//! Signed deployment-policy bootstrap shared by independently booted drivers.
use super::{parse_policy, RegulatoryDomain};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError, FirmwareRegistry};

pub const NAME: &str = "wireless-regulatory.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    Firmware(FirmwareError),
    Unsigned,
    Format(&'static str),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Authority => f.write_str("regulatory firmware authority unavailable or revoked"),
            Self::Firmware(error) => write!(f, "regulatory firmware: {error:?}"),
            Self::Unsigned => f.write_str("regulatory policy must be signed"),
            Self::Format(reason) => f.write_str(reason),
        }
    }
}

fn decode(bytes: &[u8], signer: Option<[u8; 32]>) -> Result<RegulatoryDomain, Error> {
    if signer.is_none() {
        return Err(Error::Unsigned);
    }
    parse_policy(bytes).map_err(Error::Format)
}

struct ReadPolicy;
impl CapOp<FirmwareBlob, Read> for ReadPolicy {
    type Output = Result<RegulatoryDomain, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::view_of(cap)
            .map_err(Error::Firmware)
            .and_then(|view| decode(view.bytes, view.signer)))
    }
}

fn load_from(
    authority: &Cap<FirmwareRegistry, Read>,
    name: &str,
) -> Result<RegulatoryDomain, Error> {
    let blob = narf_firmware::open(name, authority).map_err(Error::Firmware)?;
    blob.invoke(ReadPolicy).map_err(|_| Error::Authority)?
}

/// Read the exact staged NRGD policy through current firmware capability
/// invocation. Signer metadata is mandatory even in unsigned development
/// builds. Parsing succeeds before any caller can install the result.
/// No country, calibration or transmit permission is synthesized here.
pub fn load() -> Result<RegulatoryDomain, Error> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive::<Read>().ok())
        .ok_or(Error::Authority)?;
    load_from(&authority, NAME)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "policy_tests.rs"]
mod tests;

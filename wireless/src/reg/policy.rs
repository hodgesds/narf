//! Authenticated regulatory bootstrap shared by independently booted drivers.
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

pub(super) fn load_bootstrap() -> Result<(RegulatoryDomain, super::db::Source), Error> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive::<Read>().ok())
        .ok_or(Error::Authority)?;
    bootstrap_from(&authority, NAME, narf_firmware::linux_regulatory_database())
}

fn bootstrap_from(
    authority: &Cap<FirmwareRegistry, Read>,
    name: &str,
    linux: &[u8],
) -> Result<(RegulatoryDomain, super::db::Source), Error> {
    match load_from(authority, name) {
        Ok(domain) => Ok((domain, super::db::Source::Deployment)),
        Err(Error::Firmware(FirmwareError::NotFound)) => {
            let (domain, dfs) = super::linux::country(linux, *b"00").map_err(Error::Format)?;
            Ok((domain, super::db::Source::Linux(dfs)))
        }
        Err(error) => Err(error),
    }
}

/// Prefer an explicitly staged signed NRGD policy. Only its absence selects
/// world 00 from the unmodified Linux database authenticated at image build.
/// A malformed, unsigned or inaccessible explicit policy never falls back.
pub fn load() -> Result<RegulatoryDomain, Error> {
    load_bootstrap().map(|(domain, _)| domain)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "policy_tests.rs"]
mod tests;

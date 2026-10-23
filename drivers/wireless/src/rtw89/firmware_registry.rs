//! Capability-authorized immutable firmware snapshots for the AX boot owner.
use super::{
    fw::FwError,
    mac::ChipId,
    prepared::{self, Files, PreparedFirmware},
};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareRegistry};

struct RegistryFiles {
    authority: Cap<FirmwareRegistry, Read>,
}
struct CopyBlob;
impl CapOp<FirmwareBlob, Read> for CopyBlob {
    type Output = Result<Vec<u8>, FwError>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| FwError::Authority)?;
            if view.bytes.len() > 16 * 1024 * 1024 {
                return Err(FwError::BadFormat);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FwError::NoMemory)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
impl Files for RegistryFiles {
    fn load(&mut self, name: &'static str) -> Result<Vec<u8>, FwError> {
        let blob = narf_firmware::open(name, &self.authority).map_err(|error| match error {
            narf_firmware::FirmwareError::NotFound => FwError::BlobMissing,
            narf_firmware::FirmwareError::OutOfMemory => FwError::NoMemory,
            _ => FwError::Authority,
        })?;
        blob.invoke(CopyBlob).map_err(|_| FwError::Authority)?
    }
}
/// This creates an owned validated snapshot; it neither enables DMA nor starts
/// firmware. The future power/secure-fuse/CH12 owner must consume that snapshot.
pub fn load(chip: ChipId, cut: u8) -> Result<PreparedFirmware, FwError> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive::<Read>().ok())
        .ok_or(FwError::Authority)?;
    prepared::load(&mut RegistryFiles { authority }, chip, cut)
}

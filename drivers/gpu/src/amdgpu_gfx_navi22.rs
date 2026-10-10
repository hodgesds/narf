//! Immutable capability-backed Navi22 graphics firmware set. Preparing the
//! complete set performs no device I/O; malformed/missing mandatory images
//! fail before PSP can receive any part of the set.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_gfx_firmware::{Image, Source},
};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    Allocation,
    Image(Source, crate::amdgpu_gfx_firmware::Error),
    Registry(Source, narf_firmware::FirmwareError),
}
#[derive(Debug)]
pub struct Firmware {
    bytes: [Option<Vec<u8>>; 7],
}
pub(crate) fn check_device(gpu: &AmdGpu) -> Result<(), Error> {
    crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?;
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_SDMA0, &[(5, 2, 2)], 0, 0)
        .map_err(|_| Error::Unsupported)?;
    Ok(())
}
struct Open(Source);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0.name(), cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(Error::Registry(self.0, error))),
        };
        blob.invoke(CopyImage(self.0))
    }
}
struct CopyImage(Source);
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|e| Error::Registry(self.0, e))?;
            Image::parse(self.0, view.bytes).map_err(|e| Error::Image(self.0, e))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
fn optional(source: Source, result: Result<Vec<u8>, Error>) -> Result<Option<Vec<u8>>, Error> {
    match result {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Registry(Source::Mec2, narf_firmware::FirmwareError::NotFound))
            if source == Source::Mec2 =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
impl Firmware {
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        check_device(gpu)?;
        let mut bytes = core::array::from_fn(|_| None);
        for (slot, source) in bytes.iter_mut().zip(Source::ORDER) {
            *slot = optional(
                source,
                authority.invoke(Open(source)).map_err(|_| Error::Revoked)?,
            )?;
        }
        Ok(Self { bytes })
    }
    /// Validated views in upload order. MEC2 alone may be absent.
    pub fn images(&self) -> Result<[Option<Image<'_>>; 7], Error> {
        let mut images = [None; 7];
        for ((slot, bytes), source) in images.iter_mut().zip(&self.bytes).zip(Source::ORDER) {
            if let Some(bytes) = bytes {
                *slot = Some(Image::parse(source, bytes).map_err(|e| Error::Image(source, e))?);
            } else if source != Source::Mec2 {
                return Err(Error::Invalid);
            }
        }
        Ok(images)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx_navi22_tests.rs"]
pub(crate) mod tests;

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
    bytes: [Option<Vec<u8>>; Source::ORDER.len()],
    /// Unharvested VCN instances whose PSP upload is part of this set.
    vcn: u8,
}
pub(crate) fn check_device(gpu: &AmdGpu) -> Result<(), Error> {
    crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?;
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_SDMA0, &[(5, 2, 2)], 0, 0)
        .map_err(|_| Error::Unsupported)?;
    // amdgpu_ucode_ip_version_decode: 3.0.16 is Dimgrey Cavefish, not Navy.
    crate::amdgpu_psp_ring::bank(
        gpu,
        discovery::HW_ID_VCN,
        &[(3, 0, 0), (3, 0, 64), (3, 0, 192)],
        0,
        0,
    )
    .map_err(|_| Error::Unsupported)?;
    vcn_instances(gpu)?;
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_DCN, &[(3, 0, 0)], 0, 0)
        .map_err(|_| Error::Unsupported)?;
    Ok(())
}
/// Discovered VCN instances as a mask (bit i = instance i). Navy Flounder
/// publishes VCN 3.0.0 (instance 0) and usually 3.0.1 (instance 1); Linux
/// keys firmware and IP selection on instance 0's version only. Duplicate or
/// out-of-range instances are refused rather than guessed.
pub(crate) fn vcn_instances(gpu: &AmdGpu) -> Result<u8, Error> {
    let mut mask = 0u8;
    for ip in gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == discovery::HW_ID_VCN)
    {
        let bit = 1u8.checked_shl(u32::from(ip.instance)).unwrap_or(0);
        if ip.instance > 1 || mask & bit != 0 || (ip.major, ip.minor) != (3, 0) {
            return Err(Error::Unsupported);
        }
        mask |= bit;
    }
    // Instance 0's version was checked above against the Navy Flounder set.
    if mask & 1 == 0 {
        return Err(Error::Unsupported);
    }
    Ok(mask)
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
    /// The validated bytes of one image; `None` only for an absent MEC2.
    pub(crate) fn source_bytes(&self, source: Source) -> Option<&[u8]> {
        self.bytes
            .iter()
            .zip(Source::ORDER)
            .find(|(_, s)| *s == source)
            .and_then(|(bytes, _)| bytes.as_deref())
    }
    pub(crate) fn dmcub_bytes(&self) -> Result<&[u8], Error> {
        self.bytes
            .iter()
            .zip(Source::ORDER)
            .find(|(_, source)| *source == Source::Dmcub)
            .and_then(|(bytes, _)| bytes.as_deref())
            .ok_or(Error::Invalid)
    }
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        check_device(gpu)?;
        let vcn = vcn_instances(gpu)?;
        let mut bytes = core::array::from_fn(|_| None);
        for (slot, source) in bytes.iter_mut().zip(Source::ORDER) {
            *slot = optional(
                source,
                authority.invoke(Open(source)).map_err(|_| Error::Revoked)?,
            )?;
        }
        Ok(Self { bytes, vcn })
    }
    /// Drop harvested VCN instances (`adev->vcn.harvest_config`) before any
    /// device I/O. With both harvested Linux disables the VCN block, so no
    /// VCN payload is sent; the image itself is still validated.
    pub fn harvest_vcn(&mut self, harvested: u8) {
        self.vcn &= !harvested;
    }
    /// VCN instances that PSP will receive firmware for.
    pub fn vcn_instances(&self) -> u8 {
        self.vcn
    }
    /// Size of the VCN container file (`adev->vcn.inst[i].fw->size`), which
    /// sizes VCPU cache window 0 in `vcn_v3_0_mc_resume`.
    pub(crate) fn vcn_size(&self) -> Option<usize> {
        self.bytes
            .iter()
            .zip(Source::ORDER)
            .find(|(_, source)| *source == Source::Vcn)
            .and_then(|(bytes, _)| bytes.as_ref().map(Vec::len))
    }
    /// Validated views in upload order. MEC2 alone may be absent.
    pub fn images(&self) -> Result<[Option<Image<'_>>; Source::ORDER.len()], Error> {
        let mut images = [None; Source::ORDER.len()];
        for ((slot, bytes), source) in images.iter_mut().zip(&self.bytes).zip(Source::ORDER) {
            if let Some(bytes) = bytes {
                let mut image = Image::parse(source, bytes).map_err(|e| Error::Image(source, e))?;
                if source == Source::Vcn {
                    image = image
                        .for_vcn_instances(self.vcn)
                        .map_err(|e| Error::Image(source, e))?;
                }
                *slot = Some(image);
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

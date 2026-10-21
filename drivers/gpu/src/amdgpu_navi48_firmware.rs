//! An RDNA4 die's complete signed IP firmware set. Linux amdgpu_ucode.{h,c},
//! amdgpu_mes.c, gfx_v12_0.c, sdma_v7_0.c and psp_gfx_if.h define these layouts.
//! Names come from the per-IP table in `amdgpu_rdna4` (GC 12.0.0 / 12.0.1,
//! MP 14.0.2 / 14.0.3, SDMA 7.0.0 / 7.0.1, kicker boards).
//! Registry capabilities authorize the immutable copy; PSP authenticates it.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MesMode {
    Separate,
    Unified,
}
pub use crate::amdgpu_navi48_ucode::{Image, Source};
impl Source {
    fn name(self, target: Target, mes: MesMode) -> &'static str {
        let set = &target.set;
        match self {
            Self::Smc => set.smu(),
            Self::Sdma => set.sdma,
            Self::Pfp => set.gc.pfp,
            Self::Me => set.gc.me,
            Self::Mec => set.gc.mec,
            Self::Mes | Self::Mes1 if mes == MesMode::Unified => set.gc.uni_mes,
            Self::Mes => set.gc.mes,
            Self::Mes1 => set.gc.mes1,
            Self::Imu => set.imu(),
            Self::Rlc => set.rlc(),
            Self::Vcn => crate::amdgpu_rdna4::VCN_5_0_0_FW,
            Self::Dmcub => crate::amdgpu_rdna4::DCN_4_0_1_DMCUB_FW,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    Allocation,
    Registry(Source, narf_firmware::FirmwareError),
    Image(Source, crate::amdgpu_navi48_ucode::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    set: crate::amdgpu_rdna4::FirmwareSet,
}
impl Target {
    pub(crate) fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        let die = crate::amdgpu_rdna4::Rdna4Chip::of(gpu).ok_or(Error::Unsupported)?;
        for (id, versions) in [
            (ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS),
            (ip::HW_ID_MP1, crate::amdgpu_rdna4::MP_VERSIONS),
            (ip::HW_ID_SDMA0, &[(7, 0, 0), (7, 0, 1)][..]),
            (ip::HW_ID_VCN, &[(5, 0, 0)][..]),
            // Linux normalizes the discovery 4.1.0 encoding to DCN4.0.1.
            (ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)][..]),
        ] {
            let index = usize::from(id == ip::HW_ID_MP1);
            bank(gpu, id, versions, index, 0).map_err(|_| Error::Unsupported)?;
        }
        if gpu
            .ip_blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_VCN)
            .count()
            != 1
        {
            return Err(Error::Unsupported);
        }
        let revision = |id| ip::find_ip(&gpu.ip_blocks, id, 0).map_or(u8::MAX, |b| b.revision);
        // amdgpu_ucode_ip_version_decode: each prefix from its own IP.
        let set = crate::amdgpu_rdna4::FirmwareSet::select(
            die.gc_version(),
            revision(ip::HW_ID_MP1),
            revision(ip::HW_ID_SDMA0),
            crate::amdgpu_rdna4::is_kicker(gpu.chip.did, gpu.chip.revision),
        )
        .ok_or(Error::Unsupported)?;
        Ok(Self { set })
    }
}
#[derive(Debug)]
pub struct Firmware {
    bytes: [Vec<u8>; 11],
    target: Target,
    mes: MesMode,
}
struct Open {
    source: Source,
    target: Target,
    mes: MesMode,
}
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.source.name(self.target, self.mes), cap) {
            Ok(blob) => blob,
            Err(e) => return Ok(Err(Error::Registry(self.source, e))),
        };
        blob.invoke(CopyImage(self.source))
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
impl Firmware {
    /// Validate and retain the entire mandatory set before any hardware upload.
    /// Unified mode uses the same image for both MES pipes, as Linux does.
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
        mes: MesMode,
    ) -> Result<Self, Error> {
        let target = Target::resolve(gpu)?;
        let mut bytes = core::array::from_fn(|_| Vec::new());
        for (slot, source) in bytes.iter_mut().zip(Source::ALL) {
            *slot = authority
                .invoke(Open {
                    source,
                    target,
                    mes,
                })
                .map_err(|_| Error::Revoked)??;
        }
        Ok(Self { bytes, target, mes })
    }
    pub fn mes_mode(&self) -> MesMode {
        self.mes
    }
    pub(crate) fn target(&self) -> Target {
        self.target
    }
    pub fn images(&self) -> Result<[Image<'_>; 11], Error> {
        let mut result = [Image::EMPTY; 11];
        for ((slot, bytes), source) in result.iter_mut().zip(&self.bytes).zip(Source::ALL) {
            *slot = Image::parse(source, bytes).map_err(|e| Error::Image(source, e))?;
        }
        Ok(result)
    }
    pub fn dmcub_bytes(&self) -> &[u8] {
        &self.bytes[10]
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) fn fixture() -> Firmware {
    Firmware {
        bytes: Source::ALL.map(crate::amdgpu_navi48_ucode::tests::container),
        target: Target {
            set: crate::amdgpu_rdna4::FirmwareSet::select((12, 0, 1), 3, 1, false).unwrap(),
        },
        mes: MesMode::Separate,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_firmware_tests.rs"]
pub(crate) mod tests;

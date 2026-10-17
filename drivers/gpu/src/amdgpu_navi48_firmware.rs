//! Navi48's complete signed IP firmware set. Linux amdgpu_ucode.{h,c},
//! amdgpu_mes.c, gfx_v12_0.c, sdma_v7_0.c and psp_gfx_if.h define these layouts.
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
        match self {
            Self::Smc if target.smu == 2 => "amdgpu/smu_14_0_2.bin",
            Self::Smc => "amdgpu/smu_14_0_3.bin",
            Self::Sdma if target.sdma == 0 => "amdgpu/sdma_7_0_0.bin",
            Self::Sdma => "amdgpu/sdma_7_0_1.bin",
            Self::Pfp => "amdgpu/gc_12_0_1_pfp.bin",
            Self::Me => "amdgpu/gc_12_0_1_me.bin",
            Self::Mec => "amdgpu/gc_12_0_1_mec.bin",
            Self::Mes | Self::Mes1 if mes == MesMode::Unified => "amdgpu/gc_12_0_1_uni_mes.bin",
            Self::Mes => "amdgpu/gc_12_0_1_mes.bin",
            Self::Mes1 => "amdgpu/gc_12_0_1_mes1.bin",
            Self::Imu => "amdgpu/gc_12_0_1_imu.bin",
            Self::Rlc => "amdgpu/gc_12_0_1_rlc.bin",
            Self::Vcn => "amdgpu/vcn_5_0_0.bin",
            Self::Dmcub => "amdgpu/dcn_4_0_1_dmcub.bin",
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
    smu: u8,
    sdma: u8,
}
impl Target {
    pub(crate) fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI48 {
            return Err(Error::Unsupported);
        }
        for (id, versions) in [
            (ip::HW_ID_GC, &[(12, 0, 1)][..]),
            (ip::HW_ID_MP1, &[(14, 0, 2), (14, 0, 3)][..]),
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
        Ok(Self {
            smu: ip::find_ip(&gpu.ip_blocks, ip::HW_ID_MP1, 0)
                .unwrap()
                .revision,
            sdma: ip::find_ip(&gpu.ip_blocks, ip::HW_ID_SDMA0, 0)
                .unwrap()
                .revision,
        })
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
        target: Target { smu: 3, sdma: 1 },
        mes: MesMode::Separate,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_firmware_tests.rs"]
pub(crate) mod tests;

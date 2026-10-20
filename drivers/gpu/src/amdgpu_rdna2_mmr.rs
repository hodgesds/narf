//! nv.c::nv_allowed_read_registers, GC 10.1 header shared by GC 10.3.
//! All Linux entries are unindexed: no GRBM selector writes are needed.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_filesystem::FsError;

use crate::amdgpu_rdna2::READ_MMR_GC as GC;
fn base(gpu: &AmdGpu, hw: u16) -> Option<u32> {
    let mut blocks = gpu
        .ip_blocks
        .iter()
        .filter(|b| b.hw_id == hw && b.instance == 0);
    let block = blocks.next()?;
    let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)?;
    let expected = if hw == discovery::HW_ID_GC {
        profile.gc_version
    } else {
        profile.sdma_version
    };
    (blocks.next().is_none()
        && block.num_bases > 0
        && (block.major, block.minor, block.revision) == expected)
        .then_some(block.base_addrs[0])
}
fn allowed(gpu: &AmdGpu, offset: u32) -> bool {
    let gc = base(gpu, discovery::HW_ID_GC);
    GC.iter()
        .any(|&r| gc.and_then(|b| b.checked_add(r)) == Some(offset))
        || [
            (discovery::HW_ID_SDMA0, 0x25),
            (discovery::HW_ID_SDMA1, 0x625),
        ]
        .iter()
        .any(|&(hw, r)| base(gpu, hw).and_then(|b| b.checked_add(r)) == Some(offset))
}

pub(crate) fn validate(payload: [u32; 4]) -> Result<(u32, u32), FsError> {
    let [offset, count, instance, _] = payload;
    let se = instance & 255;
    let sh = (instance >> 8) & 255;
    if (se != 255 && se >= 4) || (sh != 255 && sh >= 2) || count > 128 {
        return Err(FsError::InvalidData);
    }
    Ok((offset, count))
}
/// Caller holds the platform owner and a GFXOFF reference for this GPU.
pub(crate) fn read(
    gpu: &AmdGpu,
    authority: &Cap<narf_bus::BusDeviceCap, Write>,
    payload: [u32; 4],
    cached_gb: Option<u32>,
) -> Result<Vec<u8>, FsError> {
    let (offset, count) = validate(payload)?;
    let profile =
        crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did).ok_or(FsError::NoDevice)?;
    let gc = discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_GC, 0).ok_or(FsError::NoDevice)?;
    if (gc.major, gc.minor, gc.revision) != profile.gc_version
        || base(gpu, discovery::HW_ID_GC).is_none()
    {
        return Err(FsError::NoDevice);
    }
    // Validate the entire request before touching any register.
    for index in 0..count {
        let reg = offset.checked_add(index).ok_or(FsError::BadAddress)?;
        if !allowed(gpu, reg) || (u64::from(reg) + 1) * 4 > gpu.regs.len {
            return Err(FsError::BadAddress);
        }
    }
    struct Read<'a> {
        gpu: &'a AmdGpu,
        offset: u32,
        count: u32,
        cached_gb: Option<u32>,
    }
    impl CapOp<narf_bus::BusDeviceCap, Write> for Read<'_> {
        type Output = Vec<u8>;
        fn execute(self, _: &Cap<narf_bus::BusDeviceCap, Write>) -> Result<Vec<u8>, CapError> {
            let mut out = Vec::with_capacity(self.count as usize * 4);
            let gb = base(self.gpu, discovery::HW_ID_GC).and_then(|b| b.checked_add(0x13de));
            for i in 0..self.count {
                let reg = self.offset + i;
                let value = if Some(reg) == gb && self.cached_gb.is_some() {
                    self.cached_gb.unwrap()
                } else {
                    // SAFETY: entire allow-listed range bounded above, owner
                    // serializes GC accesses and caller keeps GC powered.
                    unsafe { self.gpu.regs.read32(u64::from(reg) * 4) }
                };
                out.extend_from_slice(&value.to_le_bytes());
            }
            Ok(out)
        }
    }
    authority
        .invoke(Read {
            gpu,
            offset,
            count,
            cached_gb,
        })
        .map_err(|_| FsError::NoDevice)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn rdna2_live_mmr_allowlist_and_authority() -> TestResult {
        for profile in crate::amdgpu_rdna2::PROFILES {
            let mut memory = alloc::vec![0u32; 0x20000];
            let mut gpu = crate::amdgpu_cp_navi22::tests::rdna2_gpu(profile, profile.pci_ids[0]);
            gpu.regs.virt = memory.as_mut_ptr() as u64;
            gpu.regs.len = memory.len() as u64 * 4;
            let gc = base(&gpu, discovery::HW_ID_GC).unwrap();
            let cap = Cap::bootstrap();
            for (index, &reg) in GC.iter().enumerate() {
                let at = gc + reg;
                memory[at as usize] = 0x1234 + index as u32;
                let expected = if reg == 0x13de {
                    0xbeef
                } else {
                    memory[at as usize]
                };
                if read(&gpu, &cap, [at, 1, 0xffff, 0], Some(0xbeef))
                    != Ok(expected.to_le_bytes().to_vec())
                {
                    return TestResult::Fail("allowed MMR register did not use live/cached source");
                }
            }
            let at = gc + 0x0e24;
            let expected: Vec<u8> = (0..6)
                .flat_map(|i| memory[(at + i) as usize].to_le_bytes())
                .collect();
            if read(&gpu, &cap, [at, 6, 0xffff, 0], None) != Ok(expected)
                || read(&gpu, &cap, [at, 7, 0xffff, 0], None) != Err(FsError::BadAddress)
                || read(&gpu, &cap, [u32::MAX, 2, 0xffff, 0], None) != Err(FsError::BadAddress)
                || validate([at, 129, 0xffff, 0]) != Err(FsError::InvalidData)
                || validate([at, 1, 0x200, 0]) != Err(FsError::InvalidData)
            {
                return TestResult::Fail("MMR allowlist or count/index bounds escaped");
            }
            cap.revoke();
            if read(&gpu, &cap, [at, 1, 0xffff, 0], None) != Err(FsError::NoDevice) {
                return TestResult::Fail("MMR read bypassed revoked PCI authority");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2",
        rdna2_live_mmr_allowlist_and_authority
    );
}

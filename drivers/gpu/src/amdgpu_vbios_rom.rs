//! Navi22/Navi48 ROM-register fallback, following amdgpu_soc15_read_bios_from_rom
//! and smuio_v11_0.c / smuio_v14_0_2.c. Reads leave the ROM_INDEX latch unchanged; no PCI ROM
//! decode, reset, flash programming or ATOM execution is involved.
use super::*;

const INDEX: u32 = 0xe4;
const DATA: u32 = 0xe5;
trait Io {
    fn read_index(&mut self) -> u32;
    fn write_index(&mut self, value: u32);
    /// ROM_DATA advances the byte-addressed index by one dword.
    fn read_data(&mut self) -> u32;
}
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read_index(&mut self) -> u32 {
        // SAFETY: exact SMUIO bank bounded through DATA at construction.
        unsafe { self.regs.read32(self.base + INDEX as u64 * 4) }
    }
    fn write_index(&mut self, value: u32) {
        // SAFETY: exclusively owned ROM read latch, same bounded bank.
        unsafe { self.regs.write32(self.base + INDEX as u64 * 4, value) };
    }
    fn read_data(&mut self) -> u32 {
        // SAFETY: same bounded bank; this is ROM read data, never a flash write.
        unsafe { self.regs.read32(self.base + DATA as u64 * 4) }
    }
}
fn chunk(io: &mut impl Io, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
    if offset % 4 != 0
        || bytes.len() % 4 != 0
        || offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > MAX_IMAGE)
    {
        return Err(Error::InvalidImage);
    }
    let index = io.read_index();
    if index == u32::MAX {
        return Err(Error::NotFound);
    }
    io.write_index(offset as u32);
    for word in bytes.chunks_exact_mut(4) {
        word.copy_from_slice(&io.read_data().to_le_bytes());
    }
    io.write_index(index);
    Ok(())
}
fn read(
    io: &mut impl Io,
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Vbios, Error> {
    // Enough for AMD's signature and the image-size byte, dword rounded.
    let mut header = [0; 64];
    cap.invoke(ReadOp(|| chunk(io, 0, &mut header)))
        .map_err(|_| Error::Revoked)??;
    if header[..2] != [0x55, 0xaa] || &header[0x30..0x3a] != b" 761295520" {
        return Err(Error::InvalidImage);
    }
    let length = header[2] as usize * 512;
    if !(512..=MAX_IMAGE).contains(&length) {
        return Err(Error::InvalidImage);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(length, 0);
    for (index, bytes) in bytes.chunks_mut(4096).enumerate() {
        cap.invoke(ReadOp(|| chunk(io, index * 4096, bytes)))
            .map_err(|_| Error::Revoked)??;
    }
    if bytes[..header.len()] != header {
        return Err(Error::InvalidImage);
    }
    validate(&bytes, device, true)?;
    Ok(Vbios {
        bytes,
        source: Source::RomRegisters,
    })
}
fn bank(gpu: &AmdGpu, device: &BusDevice) -> Result<u64, Error> {
    use crate::{amdgpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
    if gpu.chip.vid != amdgpu::AMD_VENDOR
        || device.id.vendor != gpu.chip.vid
        || device.id.device != gpu.chip.did
        || !matches!(device.addr, BusAddr::Pcie(_))
    {
        return Err(Error::Unsupported);
    }
    if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_some() {
        bank(gpu, ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS, 0, 0)
            .map_err(|_| Error::Unsupported)?;
        // nbio_v7_7 has no get_rom_offset override. SMUIO14.0.2 uses the
        // same two port offsets, at base index zero; no other SMUIO14
        // revision is admitted by this profile.
        bank(gpu, ip::HW_ID_NBIF, &[(7, 7, 0), (7, 7, 1)], 0, 0).map_err(|_| Error::Unsupported)?;
        return bank(gpu, ip::HW_ID_SMUIO, &[(14, 0, 2)], 0, DATA).map_err(|_| Error::Unsupported);
    }
    if gpu.chip.did != amdgpu::NAVI22 {
        return Err(Error::Unsupported);
    }
    bank(gpu, ip::HW_ID_GC, &[(10, 3, 2)], 0, 0).map_err(|_| Error::Unsupported)?;
    // nbio_v2_3 has no get_rom_offset override; the ROM starts at byte zero.
    bank(
        gpu,
        ip::HW_ID_NBIF,
        &[
            (2, 3, 0),
            (2, 3, 1),
            (2, 3, 2),
            (3, 3, 0),
            (3, 3, 1),
            (3, 3, 2),
            (3, 3, 3),
        ],
        2,
        0,
    )
    .map_err(|_| Error::Unsupported)?;
    bank(
        gpu,
        ip::HW_ID_SMUIO,
        &[
            (11, 0, 0),
            (11, 0, 2),
            (11, 0, 3),
            (11, 0, 4),
            (11, 0, 7),
            (11, 0, 8),
        ],
        0,
        DATA,
    )
    .map_err(|_| Error::Unsupported)
}
/// # Safety
/// Caller owns this physical GPU's permanent register mapping and ROM index
/// latch exclusively throughout the read; no reset, power or flash operations.
pub(super) unsafe fn read_discrete(
    gpu: &AmdGpu,
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Vbios, Error> {
    let base = bank(gpu, device)?;
    read(
        &mut Mmio {
            regs: gpu.regs,
            base,
        },
        device,
        cap,
    )
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vbios_rom_tests.rs"]
mod tests;

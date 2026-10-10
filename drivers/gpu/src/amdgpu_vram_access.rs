//! Bounded, read-only VRAM access before IP discovery.
//!
//! BAR0 can expose only a prefix of a discrete GPU's VRAM. Linux's
//! `amdgpu_device_vram_access` uses that aperture first, then
//! `amdgpu_device_mm_access` for the remainder. In memory mode MM_INDEX
//! takes a BYTE address with bit 31 set; MM_INDEX_HI holds address >> 31.
//! The latter is essential for the discovery table on a 12 GiB Navi 22.
//!
//! Reference: Linux v6.12, `amdgpu_device_mm_access` / `amdgpu_device_vram_access`:
//! https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c

use narf_bus::MmioRegion;

// Byte offsets in BAR5 (bif_4_1_d.h's dword register IDs multiplied by 4).
const MM_INDEX: u64 = 0;
const MM_DATA: u64 = 4;
const MM_INDEX_HI: u64 = 0x18;

/// The probe owns the index latch for the entire read, including transitions
/// between the direct aperture and indexed access. No concurrent register
/// access may interleave with these operations.
pub(crate) trait ReadIo {
    fn aperture_len(&self) -> u64;
    fn registers_len(&self) -> u64;
    fn read_aperture(&mut self, offset: u64) -> u32;
    fn read_register(&mut self, offset: u64) -> u32;
    fn write_register(&mut self, offset: u64, value: u32);
}

pub(crate) struct MmioReader<'a> {
    aperture: &'a MmioRegion,
    registers: &'a MmioRegion,
}

impl<'a> MmioReader<'a> {
    /// # Safety
    /// Both mappings must belong to the same AMD GPU and remain live. Caller
    /// holds current PCI authority and exclusive ownership of BAR0 and the
    /// BAR5 index latch until the reader is dropped.
    pub(crate) unsafe fn new(aperture: &'a MmioRegion, registers: &'a MmioRegion) -> Self {
        Self {
            aperture,
            registers,
        }
    }
}

impl ReadIo for MmioReader<'_> {
    fn aperture_len(&self) -> u64 {
        self.aperture.len
    }
    fn registers_len(&self) -> u64 {
        self.registers.len
    }
    fn read_aperture(&mut self, offset: u64) -> u32 {
        assert!(
            offset % 4 == 0
                && offset
                    .checked_add(4)
                    .is_some_and(|end| end <= self.aperture.len)
        );
        // SAFETY: read() checks alignment and the whole range; new() owns MMIO.
        unsafe { self.aperture.read32(offset) }
    }
    fn read_register(&mut self, offset: u64) -> u32 {
        assert!(matches!(offset, MM_INDEX | MM_DATA | MM_INDEX_HI));
        assert!(offset + 4 <= self.registers.len);
        // SAFETY: read() validates the register window before indexed access.
        unsafe { self.registers.read32(offset) }
    }
    fn write_register(&mut self, offset: u64, value: u32) {
        assert!(matches!(offset, MM_INDEX | MM_INDEX_HI));
        assert!(offset + 4 <= self.registers.len);
        // SAFETY: as above; only the two address latches are written.
        unsafe { self.registers.write32(offset, value) }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vram_access_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Unaligned,
    OutOfRange,
    RegisterWindowTooSmall,
}

/// Read aligned VRAM bytes without changing the aperture or writing VRAM.
/// Invalid requests fail before any device access or destination modification.
pub(crate) fn read(
    io: &mut impl ReadIo,
    vram_size: u64,
    offset: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    if offset % 4 != 0 || out.len() % 4 != 0 {
        return Err(Error::Unaligned);
    }
    let end = offset
        .checked_add(out.len() as u64)
        .ok_or(Error::OutOfRange)?;
    // The memory selector consumes bit 31 of the low word. The 32-bit high
    // latch can encode at most 63 address bits.
    if end > vram_size || end > (1u64 << 63) {
        return Err(Error::OutOfRange);
    }
    if out.is_empty() {
        return Ok(());
    }
    let aperture_end = io.aperture_len().min(vram_size) & !3;
    let indexed = end > aperture_end;
    if indexed && io.registers_len() < MM_INDEX_HI + 4 {
        return Err(Error::RegisterWindowTooSmall);
    }
    // Preserve the latches so a later register access cannot inherit the
    // memory-mode address (or a stale high address). Never write MM_DATA.
    let saved = indexed.then(|| (io.read_register(MM_INDEX), io.read_register(MM_INDEX_HI)));
    let mut high = None;
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        let pos = offset + i as u64 * 4;
        let word = if pos < aperture_end {
            io.read_aperture(pos)
        } else {
            io.write_register(MM_INDEX, pos as u32 | 0x8000_0000);
            let next_high = (pos >> 31) as u32;
            if high != Some(next_high) {
                io.write_register(MM_INDEX_HI, next_high);
                high = Some(next_high);
            }
            io.read_register(MM_DATA)
        };
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    if let Some((index, high)) = saved {
        io.write_register(MM_INDEX_HI, high);
        io.write_register(MM_INDEX, index);
    }
    Ok(())
}

//! Owned VBIOS snapshots from ACPI VFCT or an APU's firmware VRAM shadow.
//! Formats and source ordering follow Linux `amdgpu_bios.c` / `atombios.h`.
//! These reads neither enable a ROM BAR nor execute ATOM command tables.
use alloc::vec::Vec;
use narf_bus::{BusAddr, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

use crate::{amdgpu::AmdGpu, amdgpu_atombios::Atombios, atombios::header::parse_rom_header};

const MAX_IMAGE: usize = 256 * 1024;
const MAX_VFCT: usize = 2 * 1024 * 1024;
const VFCT_HEADER: usize = 76;
const IMAGE_HEADER: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotFound,
    Unsupported,
    InvalidTable,
    Ambiguous,
    InvalidImage,
    WrongDevice,
    Allocation,
    Revoked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Vfct,
    VramShadow,
}

/// Structurally validated data, not authority to reset a GPU or execute BIOS
/// code. Platform firmware is trusted as the source; this is not a signature
/// verification mechanism. Private storage prevents mutation after validation.
#[derive(Debug)]
pub struct Vbios {
    bytes: Vec<u8>,
    source: Source,
}
impl Vbios {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn source(&self) -> Source {
        self.source
    }
    pub fn version(&self) -> Option<alloc::string::String> {
        crate::atombios::parse(&self.bytes).ok()?.version
    }

    /// Select exactly one image for this PCI function. VFCT has no segment
    /// field: nonzero PCI segments and bus-renumbering guesses are rejected.
    /// Zero/all-ones subsystem IDs are unspecified; explicit IDs must match.
    pub fn from_vfct(table: &[u8], device: &BusDevice) -> Result<Self, Error> {
        let BusAddr::Pcie(addr) = device.addr else {
            return Err(Error::Unsupported);
        };
        if addr.segment != 0 || device.id.vendor != 0x1002 {
            return Err(Error::Unsupported);
        }
        if table.len() < VFCT_HEADER || &table[..4] != b"VFCT" {
            return Err(Error::InvalidTable);
        }
        let length = u32_at(table, 4) as usize;
        if !(VFCT_HEADER..=MAX_VFCT).contains(&length) || length > table.len() {
            return Err(Error::InvalidTable);
        }
        let table = &table[..length];
        if table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
            return Err(Error::InvalidTable);
        }
        let mut offset = u32_at(table, 0x34) as usize;
        let lib_offset = u32_at(table, 0x38) as usize;
        if offset == 0 {
            return Err(Error::NotFound);
        }
        let end = if lib_offset == 0 { length } else { lib_offset };
        if offset < VFCT_HEADER || offset >= end || end > length {
            return Err(Error::InvalidTable);
        }
        // `amdgpu_acpi_vfct_match`: vendor, device, slot and function must
        // match; the bus number is a **preference**, not a requirement.
        // "VFCT entries contain the PCI bus number as recorded during BIOS
        // POST. On systems where the kernel renumbers PCI buses (e.g.
        // pci=realloc or resource conflicts), the runtime bus number may
        // differ from the POST value."
        //
        // LINUX-GAP: this used to require an exact bus match, so on a machine
        // that renumbers buses no image matched and the VFCT path reported
        // NotFound — falling through to the VRAM shadow, or to nothing.
        let mut exact = None;
        let mut by_identity = None;
        while offset < end {
            let header_end = offset
                .checked_add(IMAGE_HEADER)
                .ok_or(Error::InvalidTable)?;
            if header_end > end {
                return Err(Error::InvalidTable);
            }
            let header = &table[offset..header_end];
            let size = u32_at(header, 24) as usize;
            let next = header_end.checked_add(size).ok_or(Error::InvalidTable)?;
            if next > end {
                return Err(Error::InvalidTable);
            }
            let identity = size != 0
                && u32_at(header, 4) == addr.device as u32
                && u32_at(header, 8) == addr.function as u32
                && u16_at(header, 12) == device.id.vendor
                && u16_at(header, 14) == device.id.device
                && subsystem_matches(u16_at(header, 16), device.id.subsystem_vendor)
                && subsystem_matches(u16_at(header, 18), device.id.subsystem_id);
            if identity {
                let slot = if u32_at(header, 0) == addr.bus as u32 {
                    &mut exact
                } else {
                    &mut by_identity
                };
                if slot.is_some() {
                    return Err(Error::Ambiguous);
                }
                *slot = Some(header_end..next);
            }
            offset = next;
        }
        // An exact bus match wins; otherwise accept a unique identity match.
        let selected = exact.or(by_identity);
        let image = &table[selected.ok_or(Error::NotFound)?];
        validate(image, device, false)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(image.len())
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(image);
        Ok(Self {
            bytes,
            source: Source::Vfct,
        })
    }
}

fn subsystem_matches(record: u16, device: u16) -> bool {
    record == 0 || record == u16::MAX || record == device
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn validate(bytes: &[u8], device: &BusDevice, require_pcir: bool) -> Result<(), Error> {
    if bytes.len() > MAX_IMAGE {
        return Err(Error::InvalidImage);
    }
    let header = parse_rom_header(bytes).map_err(|_| Error::InvalidImage)?;
    if header.master_data_table_offset == 0 {
        return Err(Error::InvalidImage);
    }
    let atom = Atombios::parse(bytes).map_err(|_| Error::InvalidImage)?;
    // Validate all present directory entries before retaining a loader image.
    // Zero entries denote absent tables, not pointers into the PCI header.
    for (directory, count, command) in [
        (
            header.master_data_table_offset,
            atom.data_table_count(),
            false,
        ),
        (
            header.master_command_table_offset,
            atom.cmd_table_count(),
            true,
        ),
    ] {
        for index in 0..count {
            if u16_at(bytes, directory as usize + 4 + index as usize * 2) == 0 {
                continue;
            }
            if command {
                atom.cmd_table(index)
            } else {
                atom.data_table(index)
            }
            .map_err(|_| Error::InvalidImage)?;
        }
    }
    // A VFCT header binds the image to the PCI function. A VRAM shadow has no
    // such wrapper, so require its PCI data structure to identify this GPU.
    let pcir = u16_at(bytes, 0x18) as usize;
    if pcir == 0 && !require_pcir {
        return Ok(());
    }
    let data = bytes.get(pcir..pcir + 24).ok_or(Error::InvalidImage)?;
    if &data[..4] != b"PCIR" || u16_at(data, 10) < 24 {
        return Err(Error::InvalidImage);
    }
    if pcir + u16_at(data, 10) as usize > bytes.len() {
        return Err(Error::InvalidImage);
    }
    if u16_at(data, 4) != device.id.vendor || u16_at(data, 6) != device.id.device {
        return Err(Error::WrongDevice);
    }
    Ok(())
}

struct ReadOp<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for ReadOp<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// # Safety
/// `mapping` must be this device's readable framebuffer BAR, held exclusively
/// against writes to the firmware shadow during the snapshot.
unsafe fn shadow(
    mapping: MmioRegion,
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Vbios, Error> {
    if mapping.len < MAX_IMAGE as u64 {
        return Err(Error::NotFound);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_IMAGE)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(MAX_IMAGE, 0);
    // Bound each authority invocation; no MMIO occurs outside invoke.
    for (index, chunk) in bytes.chunks_mut(4096).enumerate() {
        cap.invoke(ReadOp(|| {
            for (i, word) in chunk.chunks_exact_mut(4).enumerate() {
                // SAFETY: mapped length checked; caller holds shadow stable.
                word.copy_from_slice(
                    &unsafe { mapping.read32((index * 4096 + i * 4) as u64) }.to_le_bytes(),
                );
            }
        }))
        .map_err(|_| Error::Revoked)?;
    }
    validate(&bytes, device, true)?;
    Ok(Vbios {
        bytes,
        source: Source::VramShadow,
    })
}

/// # Safety
/// Boot firmware's cached RSDP/XSDT and child tables must remain readable via
/// the kernel physical mapping. The caller owns this GPU and its BAR mappings.
pub(crate) unsafe fn discover(
    gpu: &AmdGpu,
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Vbios, Error> {
    let vfct = cap
        .invoke(ReadOp(|| {
            let rsdp = narf_acpi::cached_rsdp().ok_or(Error::NotFound)?;
            // SAFETY: boot-provided ACPI mapping contract, read-only.
            let root = unsafe { narf_acpi::parse_rsdp(rsdp) }.map_err(|_| Error::InvalidTable)?;
            let mut found = None;
            // SAFETY: same retained boot ACPI mapping; walker validates root checksum.
            unsafe {
                narf_acpi::walk_xsdt(root, |phys, header| {
                    if &header.signature != b"VFCT" {
                        return;
                    }
                    if found.is_some() {
                        found = Some(Err(Error::Ambiguous));
                        return;
                    }
                    let len = header.length as usize;
                    if !(VFCT_HEADER..=MAX_VFCT).contains(&len)
                        || phys.checked_add(len as u64).is_none()
                    {
                        found = Some(Err(Error::InvalidTable));
                        return;
                    }
                    let table = core::slice::from_raw_parts(
                        narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
                        len,
                    );
                    found = Some(Vbios::from_vfct(table, device));
                })
            }
            .map_err(|_| Error::InvalidTable)?;
            found.unwrap_or(Err(Error::NotFound))
        }))
        .map_err(|_| Error::Revoked)?;
    match vfct {
        Err(Error::NotFound)
            if matches!(
                gpu.chip.family,
                crate::amdgpu::Family::Renoir | crate::amdgpu::Family::Phoenix
            ) =>
        {
            // SAFETY: the APU framebuffer mapping and exclusive probe ownership
            // are inherited; the copied shadow still requires matching PCIR IDs.
            unsafe { shadow(gpu.fb_bar, device, cap) }
        }
        result => result,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vbios_tests.rs"]
pub(crate) mod tests;

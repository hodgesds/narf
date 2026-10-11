//! Phoenix and Navi22 boot VRAM inventory. References: Linux amdgpu_ttm.c,
//! amdgpu_atomfirmware.c, atomfirmware.h and DCN 3.1.4 register headers.
//! Firmware metadata and explicit boot/client ranges precede allocation.
use alloc::vec::Vec;
use core::ops::Range;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

use crate::{amdgpu::AmdGpu, amdgpu_dmub, amdgpu_vram::Pool, atombios};

const ADDRESS_MASK: u32 = 0x1fff_ffff;
const ENABLE: u32 = 1 << 31;
const VGA_RESERVATION: u64 = 9 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    MissingVbios,
    MissingMetadata,
    Revoked,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    FirmwareTail,
    FirmwareUsage,
    DriverUsage,
    BootFramebuffer,
    Dmub,
    OtherClient,
    MemoryTraining,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protected {
    pub owner: Owner,
    /// Offsets within the complete VRAM aperture, before CPU-visible clipping.
    pub range: Range<u64>,
}

/// An inventory, not proof of ownership. Creating the allocator remains unsafe
/// until the caller accounts for every client and serializes GPU reconfiguration.
#[derive(Debug)]
pub struct Plan {
    mapping: MmioRegion,
    gpu_base: u64,
    vram_size: u64,
    protected: Vec<Protected>,
    training: Option<Training>,
}
/// Firmware's GDDR6 training exchange buffers, in VRAM-relative bytes.
/// They are reservations, not evidence that memory training has completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Training {
    pub p2c: u64,
    pub c2p: u64,
    pub size: u64,
}
impl Plan {
    /// Inventory a physical Navi22 using GMC10's full VRAM range and DCN3.0's
    /// inherited DMUB windows. `None` means this GPU has no boot framebuffer;
    /// every other live surface/client must still appear in `other_clients`.
    ///
    /// # Safety
    /// Same exclusive GPU, stable mappings, authority and complete client
    /// inventory contract as `read`. No hardware writes are performed.
    pub unsafe fn read_navi22(
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        boot_framebuffer: Option<Range<u64>>,
        other_clients: &[Range<u64>],
    ) -> Result<Self, Error> {
        use crate::{amdgpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
        if gpu.chip.vid != amdgpu::AMD_VENDOR || gpu.chip.did != amdgpu::NAVI22 {
            return Err(Error::Unsupported);
        }
        let gc =
            bank(gpu, ip::HW_ID_GC, &[(10, 3, 2)], 0, 0x16fd).map_err(|_| Error::Unsupported)?;
        let dcn =
            bank(gpu, ip::HW_ID_DCN, &[(3, 0, 0)], 2, 0x477).map_err(|_| Error::Unsupported)?;
        let vbios = gpu.vbios.as_ref().ok_or(Error::MissingVbios)?;
        authority
            .invoke(ReadOp(|| {
                // SAFETY: exact discovered banks bounded above, live authority.
                let fields = unsafe {
                    [
                        gpu.regs.read32(gc + 0x16fc * 4),
                        gpu.regs.read32(gc + 0x16fd * 4),
                        gpu.regs.read32(gc + 0x16e7 * 4),
                    ]
                };
                for (index, field) in fields.iter().enumerate() {
                    // DMUB's MC translation uses DCN's copy of these fields.
                    // An inconsistent display aperture cannot be inventoried.
                    // SAFETY: DCN's entire FB register triplet is bounded above.
                    let display = unsafe { gpu.regs.read32(dcn + (0x475 + index as u64) * 4) };
                    if display == u32::MAX || display & 0xff_ffff != field & 0xff_ffff {
                        return Err(Error::Invalid);
                    }
                }
                let mut plan = snapshot_with_fields(
                    gpu.fb_bar,
                    vbios.bytes(),
                    boot_framebuffer,
                    other_clients,
                    fields,
                    // SAFETY: DCN bank bounds every window register read.
                    |reg| unsafe { gpu.regs.read32(dcn + reg as u64 * 4) },
                )?;
                // The MC aperture must describe precisely the installed VRAM;
                // BAR0 may describe only a small CPU-visible prefix of it.
                if plan.vram_size != gpu.vram.size {
                    return Err(Error::Invalid);
                }
                plan.reserve_training(vbios.bytes())?;
                Ok(plan)
            }))
            .map_err(|_| Error::Revoked)?
    }

    pub fn training(&self) -> Option<Training> {
        self.training
    }

    fn reserve_training(&mut self, vbios: &[u8]) -> Result<(), Error> {
        let header = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
        let directory =
            atombios::tables::MasterDataTable::parse(vbios, &header).map_err(|_| Error::Invalid)?;
        // firmware_reservations has already validated FirmwareInfo 3.4/3.5.
        let info = directory.table_slice(4).ok_or(Error::MissingMetadata)?;
        if u32_at(info, 0x10) & 0x400 == 0 {
            return Ok(());
        }
        let tail = self
            .protected
            .iter()
            .find(|r| r.owner == Owner::FirmwareTail)
            .ok_or(Error::MissingMetadata)?
            .range
            .start;
        // Linux amdgpu_ttm: ALIGN(vram_size - fw_reserve - 1 MiB, 1 MiB).
        let c2p = tail
            .checked_sub(1 << 20)
            .and_then(|n| n.checked_add((1 << 20) - 1))
            .map(|n| n & !((1 << 20) - 1))
            .ok_or(Error::Invalid)?;
        let training = Training {
            p2c: self.vram_size.checked_sub(0x8000).ok_or(Error::Invalid)?,
            c2p,
            size: 0x1000,
        };
        let end = c2p.checked_add(training.size).ok_or(Error::Invalid)?;
        if self
            .protected
            .iter()
            .any(|r| c2p < r.range.end && r.range.start < end)
        {
            return Err(Error::Invalid);
        }
        self.protect(Owner::MemoryTraining, c2p, training.size)?;
        // P2C lies in the mandatory discovery/firmware tail, even when the
        // VBIOS reports no additional reservation.
        self.protect(Owner::MemoryTraining, training.p2c, training.size)?;
        self.training = Some(training);
        Ok(())
    }
    /// Snapshot firmware reservations and DMUB windows without changing hardware.
    /// `boot_framebuffer` is the PCI/bus-physical byte range from the bootloader;
    /// `other_clients` are GPU-address ranges, including other scanouts/cursors.
    ///
    /// # Safety
    /// Caller owns the GPU, its readable mappings, and matching PCI authority.
    /// Firmware/windows must remain stable while the snapshot is taken.
    pub unsafe fn read(
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        boot_framebuffer: Range<u64>,
        other_clients: &[Range<u64>],
    ) -> Result<Self, Error> {
        let ip = amdgpu_dmub::dcn314_ip(gpu).map_err(|_| Error::Unsupported)?;
        if ip.num_bases < 3 {
            return Err(Error::Unsupported);
        }
        let base = ip.base_addrs[2] as u64 * 4;
        if base
            .checked_add(0x478 * 4)
            .is_none_or(|end| end > gpu.regs.len)
        {
            return Err(Error::Invalid);
        }
        let vbios = gpu.vbios.as_ref().ok_or(Error::MissingVbios)?;
        authority
            .invoke(ReadOp(|| {
                // SAFETY: bounded register bank, stable readable mapping and live cap.
                snapshot(
                    gpu.fb_bar,
                    vbios.bytes(),
                    boot_framebuffer,
                    other_clients,
                    |reg| unsafe { gpu.regs.read32(base + reg as u64 * 4) },
                )
            }))
            .map_err(|_| Error::Revoked)?
    }

    pub fn protected(&self) -> &[Protected] {
        &self.protected
    }
    pub fn gpu_base(&self) -> u64 {
        self.gpu_base
    }
    pub fn vram_size(&self) -> u64 {
        self.vram_size
    }
    pub fn visible_size(&self) -> u64 {
        self.mapping.len
    }
    /// # Safety
    /// All existing allocations absent from firmware metadata must have been
    /// supplied to `read`, including boot surfaces, cursors, PSP/GART buffers
    /// and other pools. The remaining VRAM must be exclusively free and stay
    /// owned by this pool. No scanout/firmware change may grow outside the
    /// protected ranges; subsequent clients must allocate through this pool.
    /// The mapping is permanent, including for quarantined allocations.
    pub unsafe fn into_pool(self) -> Result<Pool, Error> {
        let mut exclusions = Vec::new();
        exclusions
            .try_reserve_exact(self.protected.len())
            .map_err(|_| Error::Allocation)?;
        for region in self.protected {
            let end = region.range.end.min(self.mapping.len);
            if region.range.start < end {
                exclusions.push(region.range.start..end);
            }
        }
        // SAFETY: caller establishes ownership of the unprotected aperture;
        // the pool retains all merged exclusions while reservations exist.
        unsafe { Pool::from_owned_aperture(self.mapping, self.gpu_base, &exclusions) }
            .map_err(|_| Error::Allocation)
    }
    fn protect(&mut self, owner: Owner, start: u64, size: u64) -> Result<(), Error> {
        if size == 0 {
            return Ok(());
        }
        let end = start
            .checked_add(size)
            .filter(|end| *end <= self.vram_size)
            .ok_or(Error::Invalid)?;
        self.protected
            .try_reserve(1)
            .map_err(|_| Error::Allocation)?;
        self.protected.push(Protected {
            owner,
            range: start..end,
        });
        Ok(())
    }
    fn protect_gpu(&mut self, owner: Owner, address: u64, size: u64) -> Result<(), Error> {
        let start = address.checked_sub(self.gpu_base).ok_or(Error::Invalid)?;
        self.protect(owner, start, size)
    }
}

struct ReadOp<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for ReadOp<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

fn snapshot(
    mapping: MmioRegion,
    vbios: &[u8],
    boot_framebuffer: Range<u64>,
    other_clients: &[Range<u64>],
    mut read: impl FnMut(u32) -> u32,
) -> Result<Plan, Error> {
    let fields = [read(0x475), read(0x476), read(0x477)];
    snapshot_with_fields(
        mapping,
        vbios,
        Some(boot_framebuffer),
        other_clients,
        fields,
        read,
    )
}
fn snapshot_with_fields(
    mut mapping: MmioRegion,
    vbios: &[u8],
    boot_framebuffer: Option<Range<u64>>,
    other_clients: &[Range<u64>],
    fields: [u32; 3],
    mut read: impl FnMut(u32) -> u32,
) -> Result<Plan, Error> {
    if fields.contains(&u32::MAX) {
        return Err(Error::Invalid);
    }
    let gpu_base = ((fields[0] & 0xff_ffff) as u64) << 24;
    let gpu_end = (((fields[1] & 0xff_ffff) as u64) + 1) << 24;
    let fb_offset = ((fields[2] & 0xff_ffff) as u64) << 24;
    let vram_size = gpu_end
        .checked_sub(gpu_base)
        .filter(|n| *n >= VGA_RESERVATION)
        .ok_or(Error::Invalid)?;
    mapping.len = mapping.len.min(vram_size);
    if mapping.len == 0
        || mapping.len % 4096 != 0
        || mapping.virt % 4096 != 0
        || mapping.phys.raw() % 4096 != 0
        || mapping.virt.checked_add(mapping.len).is_none()
        || mapping.phys.raw().checked_add(mapping.len).is_none()
    {
        return Err(Error::Invalid);
    }
    let fb_end = if let Some(boot_framebuffer) = boot_framebuffer {
        let fb_start = boot_framebuffer
            .start
            .checked_sub(mapping.phys.raw())
            .ok_or(Error::Invalid)?;
        let fb_end = boot_framebuffer
            .end
            .checked_sub(mapping.phys.raw())
            .ok_or(Error::Invalid)?;
        if fb_start >= fb_end || fb_end > mapping.len {
            return Err(Error::Invalid);
        }
        fb_end
    } else {
        0
    };
    let mut plan = Plan {
        mapping,
        gpu_base,
        vram_size,
        protected: Vec::new(),
        training: None,
    };
    // Retain the full prefix, including VGA emulation, firmware shadow and
    // the pre-OS framebuffer. Do not reclaim it while the boot console is live.
    plan.protect(Owner::BootFramebuffer, 0, VGA_RESERVATION.max(fb_end))?;
    firmware_reservations(&mut plan, vbios)?;
    for range in other_clients {
        let size = range
            .end
            .checked_sub(range.start)
            .filter(|size| *size != 0)
            .ok_or(Error::Invalid)?;
        plan.protect_gpu(Owner::OtherClient, range.start, size)?;
    }
    for reg in [0x19e, 0x19f, 0x1a0, 0x1a4] {
        let top = read(reg);
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE != 0 {
            return Err(Error::Unsupported);
        }
    }
    for index in 0..8 {
        let top = read(0x1ad + index);
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE == 0 {
            continue;
        }
        if matches!(index, 2 | 7) {
            // This DCN314 path does not implement those window layouts.
            return Err(Error::Unsupported);
        }
        let base = read(0x1a5 + index);
        let low = read(0x1b5 + index * 2);
        let high = read(0x1b6 + index * 2);
        if [base, low, high].contains(&u32::MAX) {
            return Err(Error::Invalid);
        }
        // Treat TOP as inclusive for exclusions (conservative also for the
        // Linux CW3..6 end convention). The allocator rounds outward to pages.
        let size = ((top & ADDRESS_MASK) as u64)
            .checked_sub((base & ADDRESS_MASK) as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Invalid)?;
        let mut address = ((high & 0xffff) as u64) << 32 | (low & 0xffff_ff00) as u64;
        if index <= 1 {
            address = address
                .checked_sub(fb_offset)
                .and_then(|n| n.checked_add(gpu_base))
                .ok_or(Error::Invalid)?;
        }
        plan.protect_gpu(Owner::Dmub, address, size)?;
    }
    // Region5 is the Linux trace alias. Other enabled region layouts are
    // unsupported; do not assume their address translation matches Region5.
    for index in 0..3 {
        let top = read(0x1a1 + index);
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE == 0 {
            continue;
        }
        if index != 1 {
            return Err(Error::Unsupported);
        }
        let low = read(0x196 + index * 2);
        let high = read(0x197 + index * 2);
        if low == u32::MAX || high == u32::MAX {
            return Err(Error::Invalid);
        }
        let address = ((high & 0xffff) as u64) << 32 | (low & 0xffff_ff00) as u64;
        plan.protect_gpu(Owner::Dmub, address, (top & ADDRESS_MASK) as u64 + 1)?;
    }
    Ok(plan)
}

fn firmware_reservations(plan: &mut Plan, vbios: &[u8]) -> Result<(), Error> {
    let header = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
    let directory =
        atombios::tables::MasterDataTable::parse(vbios, &header).map_err(|_| Error::Invalid)?;
    if (directory.format_revision, directory.content_revision) != (2, 1) {
        return Err(Error::Unsupported);
    }
    let info = directory.table_slice(4).ok_or(Error::MissingMetadata)?;
    if info.len() < 88 || info[2] != 3 || !matches!(info[3], 4 | 5) {
        return Err(Error::Unsupported);
    }
    // Both FirmwareInfo v3.4/v3.5 place fw_reserved_size_in_kb at +0x54.
    let mut tail = (u32_at(info, 0x54) as u64) << 10;
    if info[3] == 5 {
        // v3.5 additionally declares a write-protected region at the VRAM top.
        tail = tail.max((u32_at(info, 0x14) as u64) << 10);
    }
    tail = tail.max(crate::amdgpu_discovery::DISCOVERY_TMR_OFFSET);
    let start = plan.vram_size.checked_sub(tail).ok_or(Error::Invalid)?;
    plan.protect(Owner::FirmwareTail, start, tail)?;
    if directory.n_tables <= 11 || directory.table_offset(11).is_none() {
        return Ok(());
    }
    let usage = directory.table_slice(11).ok_or(Error::Invalid)?;
    if usage[2] != 2 {
        return Err(Error::Unsupported);
    }
    match usage[3] {
        1 if usage.len() >= 12 => {
            let raw = u32_at(usage, 4);
            let fw_size = (u16_at(usage, 8) as u64) << 10;
            let drv_size = (u16_at(usage, 10) as u64) << 10;
            let start = (raw as u64 & 0x3fff_ffff) << 10;
            match raw >> 30 {
                0 => {
                    plan.protect(Owner::FirmwareUsage, start, fw_size)?;
                    if drv_size != 0 {
                        plan.protect(
                            Owner::DriverUsage,
                            start.checked_sub(drv_size).ok_or(Error::Invalid)?,
                            drv_size,
                        )?;
                    }
                }
                1 => {}
                _ => return Err(Error::Unsupported), // SR-IOV is a separate policy.
            }
        }
        2 if usage.len() >= 48 => {
            for (owner, raw, size) in [
                (
                    Owner::FirmwareUsage,
                    u32_at(usage, 4),
                    (u16_at(usage, 8) as u64) << 10,
                ),
                (
                    Owner::DriverUsage,
                    u32_at(usage, 12),
                    (u32_at(usage, 16) as u64) << 10,
                ),
            ] {
                match raw >> 30 {
                    0 => plan.protect(owner, (raw as u64 & 0x3fff_ffff) << 10, size)?,
                    1 => {}
                    _ => return Err(Error::Unsupported),
                }
            }
        }
        _ => return Err(Error::Unsupported),
    }
    Ok(())
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vram_boot_tests.rs"]
mod tests;

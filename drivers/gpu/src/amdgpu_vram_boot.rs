//! Phoenix, Navi22 and Navi48 boot VRAM inventory. References: Linux
//! amdgpu_ttm.c, amdgpu_atomfirmware.c, atomfirmware.h and the DCN 3.1.4,
//! 3.0.0 and 4.1.0 register headers.
//! Firmware metadata and explicit boot/client ranges precede allocation.
use alloc::vec::Vec;
use core::ops::Range;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

use crate::{amdgpu::AmdGpu, amdgpu_dmub, amdgpu_vram::Pool, atombios};

// linux: DMCUB_REGION3_CW0_TOP_ADDRESS__DMCUB_REGION3_CW0_TOP_ADDRESS_MASK@dcn
const ADDRESS_MASK: u32 = 0x1fff_ffff;
// linux: DMCUB_REGION3_CW0_TOP_ADDRESS__DMCUB_REGION3_CW0_ENABLE_MASK@dcn
const ENABLE: u32 = 1 << 31;
const VGA_RESERVATION: u64 = 9 * 1024 * 1024; // linux: AMDGPU_VBIOS_VGA_ALLOCATION

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    MissingVbios,
    MissingMetadata,
    Revoked,
    Allocation,
    Busy,
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
    FirmwareRuntime,
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
    /// all six supported linear scanouts/cursors are included automatically.
    /// Active GFXHUB/MMHUB VM contexts and unsupported surfaces reject the
    /// inventory. Every additional client must appear in `other_clients`.
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
        if gpu.chip.did != crate::amdgpu::NAVI22 {
            return Err(Error::Unsupported);
        }
        // SAFETY: caller supplies the complete exclusive GPU/client contract.
        unsafe { Self::read_discrete(gpu, authority, boot_framebuffer, other_clients) }
    }
    /// Inventory Navi48's GMC12 aperture, four DCN4 scanouts/cursors and
    /// inherited DMUB windows. Both VM hubs must have no enabled contexts.
    ///
    /// # Safety
    /// Same stable mappings, exclusive GPU and complete client inventory
    /// contract as `read_navi22`. No hardware writes are performed.
    pub unsafe fn read_navi48(
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        boot_framebuffer: Option<Range<u64>>,
        other_clients: &[Range<u64>],
    ) -> Result<Self, Error> {
        if gpu.chip.did != crate::amdgpu::NAVI48 {
            return Err(Error::Unsupported);
        }
        // SAFETY: caller supplies the complete exclusive GPU/client contract.
        unsafe { Self::read_discrete(gpu, authority, boot_framebuffer, other_clients) }
    }
    unsafe fn read_discrete(
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        boot_framebuffer: Option<Range<u64>>,
        other_clients: &[Range<u64>],
    ) -> Result<Self, Error> {
        use crate::{amdgpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
        if gpu.chip.vid != amdgpu::AMD_VENDOR {
            return Err(Error::Unsupported);
        }
        let navi22 = gpu.chip.did == amdgpu::NAVI22;
        // GC MC_VM_FB_LOCATION_BASE/TOP and MC_VM_FB_OFFSET, then DCN's copy
        // DCN_VM_FB_LOCATION_BASE/TOP and DCN_VM_FB_OFFSET (BASE_IDX 2):
        // dcn_3_0_0_offset.h places them at 0x493..0x495, while DCN3.1+ and
        // DCN4 (dcn_4_1_0_offset.h) moved them to 0x475..0x477.
        let (gc_version, dcn_versions, fb_regs, dcn_fb): (_, &[_], _, u32) = match gpu.chip.did {
            // linux-lit: 0x16fc=mmGCMC_VM_FB_LOCATION_BASE@gc; 0x16fd=mmGCMC_VM_FB_LOCATION_TOP@gc
            // linux-lit: 0x16e7=mmGCMC_VM_FB_OFFSET@gc; 0x493=mmDCN_VM_FB_LOCATION_BASE@dcn
            amdgpu::NAVI22 => ((10, 3, 2), &[(3, 0, 0)], [0x16fc, 0x16fd, 0x16e7], 0x493),
            amdgpu::NAVI48 => (
                (12, 0, 1),
                &[(4, 0, 1), (4, 1, 0)],
                [0x1614, 0x1615, 0x15a7],
                0x475,
            ),
            _ => return Err(Error::Unsupported),
        };
        // linux-lit: 0=mmGCMC_VM_FB_LOCATION_BASE_BASE_IDX@gc
        let gc = bank(gpu, ip::HW_ID_GC, &[gc_version], 0, fb_regs[1])
            .map_err(|_| Error::Unsupported)?;
        // linux-lit: 2=mmDCN_VM_FB_LOCATION_BASE_BASE_IDX@dcn; 2=mmDCN_VM_FB_OFFSET - mmDCN_VM_FB_LOCATION_BASE
        let dcn = bank(gpu, ip::HW_ID_DCN, dcn_versions, 2, dcn_fb + 2)
            .map_err(|_| Error::Unsupported)?;
        let vbios = gpu.vbios.as_ref().ok_or(Error::MissingVbios)?;
        let inherited = crate::amdgpu_platform::boot_clients(gpu, authority)?;
        authority
            .invoke(ReadOp(|| {
                // SAFETY: exact discovered banks bounded above, live authority.
                let fields = unsafe {
                    [
                        gpu.regs.read32(gc + fb_regs[0] as u64 * 4),
                        gpu.regs.read32(gc + fb_regs[1] as u64 * 4),
                        gpu.regs.read32(gc + fb_regs[2] as u64 * 4),
                    ]
                };
                // SAFETY: DCN's entire FB register triplet is bounded above.
                let display: [u32; 3] = core::array::from_fn(|index| unsafe {
                    gpu.regs
                        .read32(dcn + (u64::from(dcn_fb) + index as u64) * 4)
                });
                if display.contains(&u32::MAX) {
                    return Err(Error::Invalid);
                }
                // Inherited scanout addresses are interpreted through the
                // display copy. Linux never reads either TOP (gmc_v10_0
                // derives fb_end from RCC_CONFIG_MEMSIZE) and programs DCN's
                // copy itself (hubbub3_init_dchub_sys_ctx), so on Navi22 an
                // unprogrammed (all-zero) copy is accepted and TOP ignored.
                let compared: &[usize] = if navi22 { &[0, 2] } else { &[0, 1, 2] };
                let unprogrammed = navi22 && display == [0; 3];
                if !unprogrammed
                    && compared
                        .iter()
                        // linux-lit: 0xff_ffff=DCN_VM_FB_LOCATION_BASE__FB_BASE_MASK@dcn
                        .any(|&i| display[i] & 0xff_ffff != fields[i] & 0xff_ffff)
                {
                    return Err(Error::Invalid);
                }
                let mut plan = snapshot_with_layout(
                    gpu.fb_bar,
                    vbios.bytes(),
                    boot_framebuffer,
                    other_clients,
                    SnapshotLayout {
                        fields,
                        region6: gpu.chip.did == amdgpu::NAVI48,
                        dcn30: navi22,
                        // amdgpu_gmc_vram_location: fb_end = fb_start +
                        // mc_vram_size - 1, mc_vram_size from MEMSIZE.
                        size: navi22.then_some(gpu.vram.size),
                    },
                    // SAFETY: DCN bank bounds every window register read.
                    |reg| unsafe { gpu.regs.read32(dcn + reg as u64 * 4) },
                )?;
                // The MC aperture must describe precisely the installed VRAM;
                // BAR0 may describe only a small CPU-visible prefix of it.
                if plan.vram_size != gpu.vram.size {
                    return Err(Error::Invalid);
                }
                for range in &inherited {
                    plan.protect_gpu(Owner::OtherClient, range.start, range.end - range.start)?;
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
        // PSP's runtime database is a 64 KiB window 1 MiB below the physical
        // VRAM end, independent of the discovery blob and training capability.
        // linux-lit: 0x10000=PSP_RUNTIME_DB_SIZE_IN_BYTES
        // (1 << 20) is PSP_RUNTIME_DB_OFFSET (0x100000, amdgpu_psp.h; psp_get_runtime_db_entry)
        self.protect(Owner::FirmwareRuntime, self.vram_size - (1 << 20), 0x10000)?;
        let header = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
        let directory =
            atombios::tables::MasterDataTable::parse(vbios, &header).map_err(|_| Error::Invalid)?;
        // firmware_reservations has already validated FirmwareInfo 3.4/3.5.
        // linux-lit: 4=offsetof(struct atom_master_list_of_data_tables_v2_1, firmwareinfo) / 2
        let info = directory.table_slice(4).ok_or(Error::MissingMetadata)?;
        // linux-lit: 0x10=offsetof(struct atom_firmware_info_v3_4, firmware_capability)
        // linux-lit: 0x400=ATOM_FIRMWARE_CAP_ENABLE_2STAGE_BIST_TRAINING
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
            .checked_sub(1 << 20) // linux: n/a (SZ_1M, amdgpu_ttm_init_vram_resv_regions)
            .and_then(|n| n.checked_add((1 << 20) - 1))
            .map(|n| n & !((1 << 20) - 1))
            .ok_or(Error::Invalid)?;
        let training = Training {
            // linux-lit: 0x8000=GDDR6_MEM_TRAINING_OFFSET
            p2c: self.vram_size.checked_sub(0x8000).ok_or(Error::Invalid)?,
            c2p,
            size: 0x1000, // linux: GDDR6_MEM_TRAINING_DATA_SIZE_IN_BYTES
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
    mapping: MmioRegion,
    vbios: &[u8],
    boot_framebuffer: Option<Range<u64>>,
    other_clients: &[Range<u64>],
    fields: [u32; 3],
    read: impl FnMut(u32) -> u32,
) -> Result<Plan, Error> {
    snapshot_with_layout(
        mapping,
        vbios,
        boot_framebuffer,
        other_clients,
        SnapshotLayout {
            fields,
            region6: false,
            dcn30: false,
            size: None,
        },
        read,
    )
}
struct SnapshotLayout {
    fields: [u32; 3],
    region6: bool,
    /// DCN3.0 (dmub_dcn30_setup_windows): CW2..CW7 and REGION4..7 carry
    /// untranslated GPU addresses; REGION0..2 have no VRAM offset at all.
    dcn30: bool,
    /// Physical VRAM size; None derives the end from FB_LOCATION_TOP.
    size: Option<u64>,
}
fn snapshot_with_layout(
    mut mapping: MmioRegion,
    vbios: &[u8],
    boot_framebuffer: Option<Range<u64>>,
    other_clients: &[Range<u64>],
    layout: SnapshotLayout,
    mut read: impl FnMut(u32) -> u32,
) -> Result<Plan, Error> {
    let fields = layout.fields;
    if fields.contains(&u32::MAX) {
        return Err(Error::Invalid);
    }
    let gpu_base = ((fields[0] & 0xff_ffff) as u64) << 24;
    let gpu_end = match layout.size {
        Some(size) => gpu_base.checked_add(size).ok_or(Error::Invalid)?,
        None => (((fields[1] & 0xff_ffff) as u64) + 1) << 24,
    };
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
    // REGION0..2 have no offset register, so they cannot name VRAM; Linux
    // never programs or reads them. REGION7 is inventoried below on DCN3.0.
    let refused: &[u32] = if layout.dcn30 {
        &[]
    } else {
        &[0x19e, 0x19f, 0x1a0, 0x1a4]
    };
    for &reg in refused {
        let top = read(reg);
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE != 0 {
            return Err(Error::Unsupported);
        }
    }
    for index in 0..8 {
        let top = read(0x1ad + index); // linux-lit: 0x1ad=mmDMCUB_REGION3_CW0_TOP_ADDRESS@dcn
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE == 0 {
            continue;
        }
        if matches!(index, 2 | 7) && !layout.dcn30 {
            // This DCN314 path does not implement those window layouts.
            // DCN3.0 maps CW2 (bss/data) itself and its CW2..CW7 offsets are
            // plain GPU addresses ("hardwired virtual addressing").
            return Err(Error::Unsupported);
        }
        let base = read(0x1a5 + index); // linux-lit: 0x1a5=mmDMCUB_REGION3_CW0_BASE_ADDRESS@dcn
                                        // linux-lit: 0x1b5=mmDMCUB_REGION3_CW0_OFFSET@dcn; 2=mmDMCUB_REGION3_CW1_OFFSET - mmDMCUB_REGION3_CW0_OFFSET
        let low = read(0x1b5 + index * 2);
        // linux-lit: 0x1b6=mmDMCUB_REGION3_CW0_OFFSET_HIGH@dcn
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
        // linux-lit: 0xffff=DMCUB_REGION3_CW0_OFFSET_HIGH__DMCUB_REGION3_CW0_OFFSET_HIGH_MASK@dcn
        // linux-lit: 0xffff_ff00=DMCUB_REGION3_CW0_OFFSET__DMCUB_REGION3_CW0_OFFSET_MASK@dcn
        let mut address = ((high & 0xffff) as u64) << 32 | (low & 0xffff_ff00) as u64;
        if index <= 1 {
            address = address
                .checked_sub(fb_offset)
                .and_then(|n| n.checked_add(gpu_base))
                .ok_or(Error::Invalid)?;
        }
        plan.protect_gpu(Owner::Dmub, address, size)?;
    }
    // Region5 is the trace alias. DCN4 additionally maps shared firmware state
    // into Region6, with a direct GPU offset and inclusive top (dmub_dcn401).
    // DCN3.0's uncached inbox is Region4 (dmub_dcn30_setup_windows); every
    // Region4..7 there is a direct GPU offset, so all are inventoried.
    // linux: n/a (DCN3.0 REGION4..7 count, dmub_dcn30_setup_windows)
    for index in 0..if layout.dcn30 { 4 } else { 3 } {
        let top = read(0x1a1 + index); // linux-lit: 0x1a1=mmDMCUB_REGION4_TOP_ADDRESS@dcn
        if top == u32::MAX {
            return Err(Error::Invalid);
        }
        if top & ENABLE == 0 {
            continue;
        }
        if index != 1 && !(index == 2 && layout.region6) && !layout.dcn30 {
            return Err(Error::Unsupported);
        }
        // linux-lit: 0x196=mmDMCUB_REGION4_OFFSET@dcn; 2=mmDMCUB_REGION5_OFFSET - mmDMCUB_REGION4_OFFSET
        let low = read(0x196 + index * 2);
        let high = read(0x197 + index * 2); // linux-lit: 0x197=mmDMCUB_REGION4_OFFSET_HIGH@dcn
        if low == u32::MAX || high == u32::MAX {
            return Err(Error::Invalid);
        }
        // linux-lit: 0xffff=DMCUB_REGION4_OFFSET_HIGH__DMCUB_REGION4_OFFSET_HIGH_MASK@dcn
        // linux-lit: 0xffff_ff00=DMCUB_REGION4_OFFSET__DMCUB_REGION4_OFFSET_MASK@dcn
        let address = ((high & 0xffff) as u64) << 32 | (low & 0xffff_ff00) as u64;
        plan.protect_gpu(Owner::Dmub, address, (top & ADDRESS_MASK) as u64 + 1)?;
    }
    Ok(plan)
}

fn firmware_reservations(plan: &mut Plan, vbios: &[u8]) -> Result<(), Error> {
    let header = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
    let directory =
        atombios::tables::MasterDataTable::parse(vbios, &header).map_err(|_| Error::Invalid)?;
    // linux: n/a (atom master data table revision 2.1)
    if (directory.format_revision, directory.content_revision) != (2, 1) {
        return Err(Error::Unsupported);
    }
    // linux-lit: 4=offsetof(struct atom_master_list_of_data_tables_v2_1, firmwareinfo) / 2
    let info = directory.table_slice(4).ok_or(Error::MissingMetadata)?;
    // linux-lit: 88=offsetof(struct atom_firmware_info_v3_4, fw_reserved_size_in_kb) + 4
    if info.len() < 88 || info[2] != 3 || !matches!(info[3], 4 | 5) {
        return Err(Error::Unsupported);
    }
    // Both FirmwareInfo v3.4/v3.5 place fw_reserved_size_in_kb at +0x54.
    // linux-lit: 0x54=offsetof(struct atom_firmware_info_v3_4, fw_reserved_size_in_kb)
    // linux-lit: 0x54=offsetof(struct atom_firmware_info_v3_5, fw_reserved_size_in_kb)
    let mut tail = (u32_at(info, 0x54) as u64) << 10;
    if info[3] == 5 {
        // v3.5 additionally declares a write-protected region at the VRAM top.
        // linux-lit: 0x14=offsetof(struct atom_firmware_info_v3_5, fw_protect_region_size_in_kb)
        tail = tail.max((u32_at(info, 0x14) as u64) << 10);
    }
    tail = tail.max(crate::amdgpu_discovery::DISCOVERY_TMR_OFFSET);
    let start = plan.vram_size.checked_sub(tail).ok_or(Error::Invalid)?;
    plan.protect(Owner::FirmwareTail, start, tail)?;
    // linux-lit: 11=offsetof(struct atom_master_list_of_data_tables_v2_1, vram_usagebyfirmware) / 2
    if directory.n_tables <= 11 || directory.table_offset(11).is_none() {
        return Ok(());
    }
    // linux-lit: 11=offsetof(struct atom_master_list_of_data_tables_v2_1, vram_usagebyfirmware) / 2
    let usage = directory.table_slice(11).ok_or(Error::Invalid)?;
    if usage[2] != 2 {
        // linux: n/a (vram_usagebyfirmware format revision 2)
        return Err(Error::Unsupported);
    }
    match usage[3] {
        // linux-lit: 12=sizeof(struct vram_usagebyfirmware_v2_1)
        1 if usage.len() >= 12 => {
            // linux-lit: 4=offsetof(struct vram_usagebyfirmware_v2_1, start_address_in_kb)
            let raw = u32_at(usage, 4);
            // linux-lit: 8=offsetof(struct vram_usagebyfirmware_v2_1, used_by_firmware_in_kb)
            let fw_size = (u16_at(usage, 8) as u64) << 10;
            // linux-lit: 10=offsetof(struct vram_usagebyfirmware_v2_1, used_by_driver_in_kb)
            let drv_size = (u16_at(usage, 10) as u64) << 10;
            // linux-lit: 0x3fff_ffff=~ATOM_VRAM_OPERATION_FLAGS_MASK & 0xffffffff
            let start = (raw as u64 & 0x3fff_ffff) << 10;
            // linux-lit: 30=ATOM_VRAM_OPERATION_FLAGS_SHIFT
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
                1 => {} // linux-lit: 1=ATOM_VRAM_BLOCK_NEEDS_NO_RESERVATION
                _ => return Err(Error::Unsupported), // SR-IOV is a separate policy.
            }
        }
        // linux-lit: 48=sizeof(struct vram_usagebyfirmware_v2_2)
        2 if usage.len() >= 48 => {
            for (owner, raw, size) in [
                (
                    Owner::FirmwareUsage,
                    // linux-lit: 4=offsetof(struct vram_usagebyfirmware_v2_2, fw_region_start_address_in_kb)
                    u32_at(usage, 4),
                    // linux-lit: 8=offsetof(struct vram_usagebyfirmware_v2_2, used_by_firmware_in_kb)
                    (u16_at(usage, 8) as u64) << 10,
                ),
                (
                    Owner::DriverUsage,
                    // linux-lit: 12=offsetof(struct vram_usagebyfirmware_v2_2, driver_region0_start_address_in_kb)
                    u32_at(usage, 12),
                    // linux-lit: 16=offsetof(struct vram_usagebyfirmware_v2_2, used_by_driver_region0_in_kb)
                    (u32_at(usage, 16) as u64) << 10,
                ),
            ] {
                // linux-lit: 30=ATOM_VRAM_OPERATION_FLAGS_SHIFT
                match raw >> 30 {
                    // linux-lit: 0x3fff_ffff=~ATOM_VRAM_OPERATION_FLAGS_MASK & 0xffffffff
                    0 => plan.protect(owner, (raw as u64 & 0x3fff_ffff) << 10, size)?,
                    1 => {} // linux-lit: 1=ATOM_VRAM_BLOCK_NEEDS_NO_RESERVATION
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

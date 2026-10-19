//! `DRM_IOCTL_AMDGPU_INFO` — `amdgpu_info_ioctl` (`amdgpu_kms.c`).
//!
//! This is the first substantive call any amdgpu userspace makes:
//! `libdrm_amdgpu`'s `amdgpu_device_initialize` runs DEV_INFO, MEMORY and a
//! handful of others before it will hand Mesa a device, and radeonsi reads the
//! CU count, wave size and cache geometry out of DEV_INFO to make
//! shader-compilation decisions.
//!
//! Everything reported here is sourced or refused. The graphics-core geometry
//! comes from the discovery binary's GC table (see
//! [`crate::amdgpu_discovery::parse_gc_info`]) rather than a per-ASIC table in
//! the driver, because Linux sources it the same way and for the same reason:
//! one IP version ships in several harvest configurations. The memory sizes
//! come from the VRAM aperture read at probe. A query whose answer this driver
//! does not have returns **EINVAL**, which is what `amdgpu_info_ioctl`'s
//! `default:` arm returns for a query it does not know — so an unanswered
//! query is indistinguishable from an unsupported one, and never a zero that
//! userspace would believe.
//!
//! LINUX-GAP: `ACCEL_WORKING` reports **false**. On a card that registers a
//! submitter (Navi48) the pieces exist — `AMDGPU_CS` queues jobs on the
//! kernel graphics, compute and SDMA rings with per-client VMIDs, and
//! `HW_IP_INFO` reports those rings — but none of it has run on hardware
//! yet, and rendering also needs eviction and invisible VRAM. Reporting
//! false keeps Mesa declining the device cleanly at initialisation instead
//! of coming up and failing at first draw; flipping it is the marker for
//! the submission path proving itself on silicon.
//!
//! LINUX-GAP: the queries that need subsystems this driver has not built are
//! refused rather than guessed. Navi48 answers FW_VERSION (CP firmware),
//! READ_MMR_REG (GB_ADDR_CONFIG only) and TIMESTAMP (SMUIO's golden TSC)
//! from what its platform publishes; other parts refuse them.
//!
//! `gpu_counter_freq` is the VBIOS reference clock amdgpu_atomfirmware
//! reads (smu_info, overridden by gfx_info on Navi and later), times ten.
//!
//! `vram_type` / `vram_bit_width` come from the VBIOS umc_info table on
//! discrete GC 12 parts, as amdgpu_gmc_get_vram_info reads them; other parts
//! report 0.
//!
//! On Navi48 the clocks (`max/min_engine_clock`, `max/min_memory_clock`)
//! are what its SMU owner publishes: the GFXCLK DPM range, and the UCLK DPM
//! range or, before display power enables UCLK DPM, the VBIOS boot UCLK.
//!
//! LINUX-GAP: other parts report zero clocks; their SMU owners do not
//! publish to this ioctl.

use alloc::vec;
use alloc::vec::Vec;

use narf_filesystem::FsError;

use crate::amdgpu::Family;
use crate::amdgpu_discovery::{self, GcInfo};
use crate::amdgpu_uapi as uapi;
use crate::drm_uapi;

/// `AMDGPU_GPU_PAGE_SIZE` — the GPU's own page granularity, 4 KiB on every
/// part this driver knows.
const AMDGPU_GPU_PAGE_SIZE: u32 = 4096;

/// `adev->gfx.config.max_hw_contexts`. Unlike the shader geometry this IS a
/// per-IP-version constant in Linux, and `gfx_v11_0_gpu_early_init` sets 8 for
/// every GFX 11 variant including 11.0.1. `gfx_v10_0_gpu_early_init`
/// also sets 8 for Navi 22 (GC 10.3.2).
const GFX_HW_CONTEXTS: u32 = 8;

/// `adev->family` — the `AMDGPU_FAMILY_*` value userspace matches on.
///
/// Mesa keys ASIC behaviour off this plus the device id, so a wrong value here
/// selects a different code path in the userspace driver.
fn family_id(snap: &Snapshot) -> Option<u32> {
    match snap.family {
        // Phoenix / Phoenix2 / HawkPoint are GFX 11.0.1.
        Family::Phoenix => Some(uapi::AMDGPU_FAMILY_GC_11_0_1),
        // Renoir / Cezanne / Lucienne / Barcelo are the Raven family line.
        Family::Renoir => Some(uapi::AMDGPU_FAMILY_RV),
        // The Navi2 bucket also contains Rembrandt, whose UAPI family is
        // different. Admit Navi 22 only with the matching discovery version.
        Family::Navi2 if snap.did == u32::from(crate::amdgpu::NAVI22) => {
            let gc = amdgpu_discovery::find_ip(&snap.ip_blocks, amdgpu_discovery::HW_ID_GC, 0)?;
            ((gc.major, gc.minor, gc.revision) == (10, 3, 2)).then_some(uapi::AMDGPU_FAMILY_NV)
        }
        Family::Navi4 if snap.did == u32::from(crate::amdgpu::NAVI48) => {
            let mut blocks = snap
                .ip_blocks
                .iter()
                .filter(|b| b.hw_id == amdgpu_discovery::HW_ID_GC && b.instance == 0);
            let gc = blocks.next()?;
            (blocks.next().is_none() && (gc.major, gc.minor, gc.revision) == (12, 0, 1))
                .then_some(uapi::AMDGPU_FAMILY_GC_12_0_0)
        }
        // Anything else has had no bring-up; refusing is better than naming a
        // family whose userspace path we have not exercised.
        _ => None,
    }
}

/// What `with_controller` can tell us, lifted out of the lock so the reply
/// builders are pure functions of it.
///
/// Public so a test can describe a device without one being bound: there is
/// no AMD GPU under QEMU, and the whole point of these replies is the values
/// they carry, which an "it returned 0" test would not check at all.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub did: u32,
    pub family: Family,
    /// Total physical VRAM, in bytes.
    pub vram_size: u64,
    /// VRAM the CPU can reach, bounded by the mapped BAR0 and real size.
    /// See `VramInfo::visible_size`.
    pub visible_vram_size: u64,
    /// Whether this part is an APU, which is what `AMDGPU_IDS_FLAGS_FUSION`
    /// reports.
    pub is_apu: bool,
    pub gc: Option<GcInfo>,
    pub ip_blocks: Vec<crate::amdgpu_discovery::IpBlock>,
    /// Navi 22 identity published by its cold-boot owner; default elsewhere.
    pub navi22: crate::amdgpu_info_navi22::Published,
    /// The GPU timestamp counter's reference clock in 10 kHz units (see
    /// [`reference_clock_10khz`]); 0 when the VBIOS does not say.
    pub reference_clock_10khz: u32,
    /// `AMDGPU_VRAM_TYPE_*` and the memory bus width in bits (see
    /// [`umc_vram`]); 0 where the VBIOS is not read for them.
    pub vram_type: u32,
    pub vram_bit_width: u32,
}

/// Navi 22 topology, PCI revision and boot observations, published by the
/// owners that read them (the Navi48 `publish_navi48_topology` pattern).
static NAVI22: narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_info_navi22::Published> =
    narf_lib::sync::IrqSafeSpinLock::new(crate::amdgpu_info_navi22::Published {
        topology: None,
        pci_revision: None,
        boot: None,
        vcn_harvest: None,
        media_rings: 0,
    });
/// From the cold boot's `ReadTopology` stage.
pub(crate) fn publish_navi22_topology(topology: crate::amdgpu_gfx10_topology::Topology) {
    NAVI22.lock().topology = Some(topology);
}
/// PCI config revision, read by the platform owner before the cold boot.
pub(crate) fn publish_navi22_pci_revision(revision: u8) {
    NAVI22.lock().pci_revision = Some(revision);
}
/// After a successful cold boot only.
pub(crate) fn publish_navi22_boot(boot: crate::amdgpu_info_navi22::Boot) {
    NAVI22.lock().boot = Some(boot);
}
/// The VCN harvest mask, read by the platform owner before the cold boot.
pub(crate) fn publish_navi22_vcn_harvest(harvest: u8) {
    NAVI22.lock().vcn_harvest = Some(harvest);
}
/// The media rings that take client jobs (0 when withdrawn).
pub(crate) fn publish_navi22_media_rings(rings: u8) {
    NAVI22.lock().media_rings = rings;
}

/// amdgpu_atomfirmware_get_clock_info's system reference clock, in 10 kHz:
/// smu_info's `core_refclk_10khz` (v3.x and v4.0, byte 16), which on Navi and
/// later the gfx_info table's timer reference replaces — v3.0 and v2.6
/// `golden_tsc_count_lower_refclk`, other v2.2+ `rlc_gpu_timer_refclk`, both
/// at byte 40.
pub fn reference_clock_10khz(vbios: &[u8], navi: bool) -> Option<u32> {
    use crate::atombios::{header::parse_rom_header, tables::MasterDataTable};
    let header = parse_rom_header(vbios).ok()?;
    let tables = MasterDataTable::parse(vbios, &header).ok()?;
    let word = |table: &[u8], at: usize| {
        table
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let revision = |table: &[u8]| Some((*table.get(2)?, *table.get(3)?));
    let mut clock = None;
    if let Some(smu) = tables.table_slice(8) {
        if matches!(revision(smu), Some((3 | 4, _))) {
            clock = word(smu, 16);
        }
    }
    if navi {
        if let Some(gfx) = tables.table_slice(14) {
            if matches!(revision(gfx), Some((3, _) | (2, 2..))) {
                clock = word(gfx, 40).or(clock);
            }
        }
    }
    clock
}

/// firmware_info v3's `bootup_mclk_in10khz` (byte 12), which
/// smu_v14_0_get_vbios_bootup_values reads for every v3 content revision.
pub fn boot_mclk_10khz(vbios: &[u8]) -> Option<u32> {
    use crate::atombios::{header::parse_rom_header, tables::MasterDataTable};
    let header = parse_rom_header(vbios).ok()?;
    let tables = MasterDataTable::parse(vbios, &header).ok()?;
    let info = tables.table_slice(4)?;
    if *info.get(2)? != 3 {
        return None;
    }
    info.get(12..16)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// amdgpu_atomfirmware_get_umc_info, which amdgpu_gmc_get_vram_info uses on
/// discrete GC 12.0.x: umc_info v4.0's `vram_type` (byte 26) as an
/// `AMDGPU_VRAM_TYPE_*`, and `channel_num << channel_width` (bytes 64, 65)
/// as the bus width in bits.
pub fn umc_vram(vbios: &[u8]) -> Option<(u32, u32)> {
    use crate::atombios::{header::parse_rom_header, tables::MasterDataTable};
    let header = parse_rom_header(vbios).ok()?;
    let tables = MasterDataTable::parse(vbios, &header).ok()?;
    let umc = tables.table_slice(24)?;
    if umc.get(2..4)? != [4, 0] {
        return None;
    }
    // convert_atom_mem_type_to_vram_type, dGPU arm.
    let vram_type = match *umc.get(26)? {
        0x50 => uapi::AMDGPU_VRAM_TYPE_GDDR5,
        0x60 | 0x61 | 0x80 => uapi::AMDGPU_VRAM_TYPE_HBM,
        0x70 => uapi::AMDGPU_VRAM_TYPE_GDDR6,
        0x81 => uapi::AMDGPU_VRAM_TYPE_HBM3E,
        _ => uapi::AMDGPU_VRAM_TYPE_UNKNOWN,
    };
    let (channels, width) = (u32::from(*umc.get(64)?), u32::from(*umc.get(65)?));
    Some((vram_type, channels.checked_shl(width).unwrap_or(0)))
}

fn snapshot() -> Option<Snapshot> {
    crate::amdgpu::info_snapshot()
}

impl Snapshot {
    pub(crate) fn from_gpu(gpu: &crate::amdgpu::AmdGpu) -> Self {
        // amdgpu_gmc_get_vram_info reads umc_info on discrete GC 12.0.x.
        // LINUX-GAP: other parts' vram_info / integrated_system_info are not
        // read; they report 0.
        let (vram_type, vram_bit_width) = gpu
            .vbios
            .as_ref()
            .filter(|_| gpu.chip.family == Family::Navi4 && !gpu.is_apu())
            .and_then(|v| umc_vram(v.bytes()))
            .unwrap_or((0, 0));
        Self {
            did: gpu.chip.did as u32,
            family: gpu.chip.family,
            vram_size: gpu.vram.size,
            visible_vram_size: gpu.vram.visible_size,
            is_apu: gpu.is_apu(),
            gc: gpu.gc_info,
            ip_blocks: gpu.ip_blocks.clone(),
            navi22: if gpu.chip.did == crate::amdgpu::NAVI22 {
                *NAVI22.lock()
            } else {
                Default::default()
            },
            reference_clock_10khz: gpu
                .vbios
                .as_ref()
                .and_then(|v| {
                    // Vega/Renoir predate the gfx_info override.
                    let navi = !matches!(gpu.chip.family, Family::Vega | Family::Renoir);
                    reference_clock_10khz(v.bytes(), navi)
                })
                .unwrap_or(0),
            vram_type,
            vram_bit_width,
        }
    }
}

/// A `#[repr(C)]` reply struct as the bytes the ioctl copies out.
///
/// The replies are built by filling the mirrored struct and taking its bytes,
/// never by writing at computed offsets. The mirror's layout is pinned
/// against the C header by a generated size test, so this cannot drift; an
/// offset table would be a second, unchecked copy of the same information.
pub(crate) fn as_bytes<T: Copy>(value: &T) -> Vec<u8> {
    // SAFETY: `T` is one of the `#[repr(C)]` UAPI mirrors — plain old data
    // with no padding we are not entitled to read, no references, and no
    // interior mutability. The slice borrows `value` for the duration of the
    // copy into the returned `Vec`.
    unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
            .to_vec()
    }
}

/// `drm_amdgpu_heap_info`.
///
/// `heap_usage` is zero because nothing allocates from these heaps yet. Linux
/// reports live usage from TTM; zero is accurate here rather than a stand-in.
fn heap_info(total: u64) -> uapi::DrmAmdgpuHeapInfo {
    uapi::DrmAmdgpuHeapInfo {
        total_heap_size: total,
        usable_heap_size: total,
        heap_usage: 0,
        // Linux reports three quarters of the usable heap.
        max_allocation: total / 4 * 3,
    }
}

/// `AMDGPU_INFO_DEV_INFO` → `struct drm_amdgpu_info_device`.
///
/// Field assignments follow `amdgpu_kms.c`'s `dev_info->` block one for one.
/// A field this driver cannot source is left at its zero rather than filled
/// with a plausible number, because Mesa makes code-generation decisions from
/// several of them and a wrong value is worse than an absent one.
static NAVI48_TOPOLOGY: narf_lib::sync::IrqSafeSpinLock<
    Option<crate::amdgpu_gfx12_topology::Topology>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
pub(crate) fn publish_navi48_topology(topology: crate::amdgpu_gfx12_topology::Topology) {
    *NAVI48_TOPOLOGY.lock() = Some(topology);
}
/// Navi48's CP firmware, `(fw_type, ver, feature)` for ME, PFP and MEC, as
/// amdgpu_firmware_info reports them — published when the platform opens
/// the firmware set.
static NAVI48_FIRMWARE: narf_lib::sync::IrqSafeSpinLock<Option<[(u32, u32, u32); 3]>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
pub(crate) fn publish_navi48_firmware(firmware: [(u32, u32, u32); 3]) {
    *NAVI48_FIRMWARE.lock() = Some(firmware);
}
/// `AMDGPU_INFO_FW_VERSION` → `drm_amdgpu_info_firmware { ver, feature }`
/// for the firmware types this card published; anything else is EINVAL,
/// amdgpu_firmware_info's default.
fn firmware_version(
    snap: &Snapshot,
    firmware: Option<[(u32, u32, u32); 3]>,
    fw_type: u32,
) -> Result<Vec<u8>, FsError> {
    let (_, ver, feature) = firmware
        .filter(|_| snap.did == u32::from(crate::amdgpu::NAVI48))
        .and_then(|f| f.into_iter().find(|(t, ..)| *t == fw_type))
        .ok_or(FsError::InvalidData)?;
    Ok(as_bytes(&uapi::DrmAmdgpuInfoFirmware { ver, feature }))
}
/// `AMDGPU_INFO_READ_MMR_REG` → `count` registers from `dword_offset`, as
/// soc24_read_register answers them: of its allow-list only
/// `GB_ADDR_CONFIG` (GC segment 0 + 0x13de), from the value
/// gfx_v12_0_gpu_early_init cached; any other offset is EFAULT. The SE/SH
/// selector and count are checked as amdgpu_info_ioctl does. Navi48 only.
fn read_mmr_reg(
    snap: &Snapshot,
    topology: Option<crate::amdgpu_gfx12_topology::Topology>,
    payload: [u32; 4],
) -> Result<Vec<u8>, FsError> {
    let [offset, count, instance, _flags] = payload;
    if snap.did != u32::from(crate::amdgpu::NAVI48) {
        return Err(FsError::InvalidData);
    }
    let se =
        (instance >> uapi::AMDGPU_INFO_MMR_SE_INDEX_SHIFT) & uapi::AMDGPU_INFO_MMR_SE_INDEX_MASK;
    let sh =
        (instance >> uapi::AMDGPU_INFO_MMR_SH_INDEX_SHIFT) & uapi::AMDGPU_INFO_MMR_SH_INDEX_MASK;
    // AMDGPU_GFX_MAX_SE and AMDGPU_GFX_MAX_SH_PER_SE; all-ones broadcasts.
    if (se != uapi::AMDGPU_INFO_MMR_SE_INDEX_MASK && se >= 4)
        || (sh != uapi::AMDGPU_INFO_MMR_SH_INDEX_MASK && sh >= 2)
        || count > 128
    {
        return Err(FsError::InvalidData);
    }
    let gb_addr_config =
        crate::amdgpu_discovery::find_ip(&snap.ip_blocks, crate::amdgpu_discovery::HW_ID_GC, 0)
            .filter(|gc| gc.num_bases > 0)
            .and_then(|gc| gc.base_addrs[0].checked_add(0x13de))
            .zip(topology.map(|t| t.gb_addr_config));
    let mut out = Vec::new();
    for i in 0..count {
        let reg = offset.checked_add(i).ok_or(FsError::BadAddress)?;
        match gb_addr_config {
            Some((at, value)) if at == reg => out.extend_from_slice(&value.to_le_bytes()),
            _ => return Err(FsError::BadAddress),
        }
    }
    Ok(out)
}
/// Navi48's GPU clock counter, published once its platform owns the device.
static NAVI48_CLOCK: narf_lib::sync::IrqSafeSpinLock<Option<crate::amdgpu_smuio14::ClockReader>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
pub(crate) fn publish_navi48_clock(clock: crate::amdgpu_smuio14::ClockReader) {
    *NAVI48_CLOCK.lock() = Some(clock);
}
/// Withdrawing under the same lock used by timestamp reads also drains
/// in-flight accesses before a mode1 reset removes BAR decoding.
pub(crate) fn withdraw_navi48_clock() {
    *NAVI48_CLOCK.lock() = None;
}
/// DEV_INFO's `[min_engine, max_engine, min_memory, max_memory]` clocks in
/// kHz, published by the Navi48 SMU owner whenever its DPM state changes.
static NAVI48_CLOCKS: narf_lib::sync::IrqSafeSpinLock<Option<[u32; 4]>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
pub(crate) fn publish_navi48_clocks(clocks: [u32; 4]) {
    *NAVI48_CLOCKS.lock() = Some(clocks);
}
/// `AMDGPU_INFO_TIMESTAMP` → amdgpu_gfx_get_gpu_clock_counter as a u64.
/// Without a reader (or once the device is gone) EINVAL, as amdgpu's
/// default arm.
fn timestamp(
    snap: &Snapshot,
    clock: Option<crate::amdgpu_smuio14::ClockReader>,
) -> Result<Vec<u8>, FsError> {
    clock
        .filter(|_| snap.did == u32::from(crate::amdgpu::NAVI48))
        .and_then(|c| c.read())
        .map(|t| t.to_le_bytes().to_vec())
        .ok_or(FsError::InvalidData)
}
fn dev_info(snap: &Snapshot) -> Result<Vec<u8>, FsError> {
    let topology = *NAVI48_TOPOLOGY.lock();
    let clocks = *NAVI48_CLOCKS.lock();
    dev_info_topology(snap, topology, clocks)
}
fn dev_info_topology(
    snap: &Snapshot,
    topology: Option<crate::amdgpu_gfx12_topology::Topology>,
    clocks: Option<[u32; 4]>,
) -> Result<Vec<u8>, FsError> {
    let navi48 = snap.family == Family::Navi4 && snap.did == u32::from(crate::amdgpu::NAVI48);
    let topology = topology.filter(|_| navi48);
    // amdgpu_info_ioctl's dpm_enabled arm; 0 until the SMU owner publishes.
    let [min_engine, max_engine, min_memory, max_memory] =
        clocks.filter(|_| navi48).unwrap_or([0; 4]);
    let family = family_id(snap).ok_or(FsError::InvalidData)?;
    // The shader geometry is not guessable. Refusing is better than reporting
    // a topology that would mis-compile shaders.
    let gc = snap.gc.ok_or(FsError::InvalidData)?;
    // Navi 22's gmc_v10_0_sw_init, gmc_v11_0_sw_init and Navi48's
    // gmc_v12_0_sw_init (GC 12.0.1) use the same
    // amdgpu_vm_adjust_size(256 * 1024, 9, 3, 48) geometry. Reusing these
    // address limits does not enable the GMC11 hardware programming path.
    let va = crate::amdgpu_vm::Geometry::GMC11.va_info();

    let info = uapi::DrmAmdgpuInfoDevice {
        device_id: snap.did,
        family,
        num_shader_engines: gc.num_se,
        num_shader_arrays_per_engine: gc.num_sa_per_se,
        // Navi48 shares a PCI ID across harvested SKUs. Discovery provides
        // maxima; gfx_v12_0_get_cu_info reads INACTIVE_WGPS to count enabled
        // CUs. Until that owner runs, report unknown rather than the maxima.
        cu_active_number: if snap.family == Family::Navi4 {
            topology.map_or(0, |t| t.active_cus)
        } else {
            gc.total_cus()
        },
        cu_bitmap: topology.map_or([[0; 4]; 4], |t| t.cu_bitmap),
        enabled_rb_pipes_mask: topology.map_or(0, |t| t.enabled_rb_mask),
        num_rb_pipes: gc.num_rb_per_se.saturating_mul(gc.num_se),
        num_hw_gfx_contexts: GFX_HW_CONTEXTS,
        // amdgpu_asic_get_xclk (10 kHz) * 10: kHz, Mesa's clock_crystal_freq.
        gpu_counter_freq: snap.reference_clock_10khz.saturating_mul(10),
        max_engine_clock: max_engine.into(),
        min_engine_clock: min_engine.into(),
        max_memory_clock: max_memory.into(),
        min_memory_clock: min_memory.into(),
        vram_type: snap.vram_type,
        vram_bit_width: snap.vram_bit_width,
        // FUSION means the GPU shares the CPU's memory — an APU. It used to
        // be claimed unconditionally, on the premise that "every part this
        // driver supports is an APU". A discrete card is not, and userspace
        // uses this to decide whether a buffer in system memory is as good as
        // one in VRAM.
        //
        // PREEMPTION, TMZ and GANG_SUBMIT are still deliberately NOT claimed:
        // each is a submission-path capability and there is no submission
        // path.
        ids_flags: if snap.is_apu {
            u64::from(uapi::AMDGPU_IDS_FLAGS_FUSION)
        } else {
            0
        },
        // Both are `max(PAGE_SIZE, AMDGPU_GPU_PAGE_SIZE)`, 4 KiB here.
        virtual_address_alignment: AMDGPU_GPU_PAGE_SIZE,
        gart_page_size: AMDGPU_GPU_PAGE_SIZE,
        // The address space, from the VM geometry. Two ranges, because the
        // space has a hole in its non-canonical middle.
        virtual_address_offset: va.low_offset,
        virtual_address_max: va.low_max,
        high_va_offset: va.high_offset,
        high_va_max: va.high_max,
        pte_fragment_size: va.pte_fragment_size as u32,
        // Straight from the GC table.
        wave_front_size: gc.wave_size,
        num_shader_visible_vgprs: gc.num_gprs,
        num_cu_per_sh: gc.num_cu_per_sa,
        num_tcc_blocks: gc.num_tccs,
        gs_vgt_table_depth: gc.gs_table_depth,
        gs_prim_buffer_depth: gc.gsprim_buff_depth,
        max_gs_waves_per_vgt: gc.num_max_gs_thds,
        gc_double_offchip_lds_buf: gc.double_offchip_lds_buffer,
        // v1.2 cache geometry; zero on an older table, as Linux reports it.
        tcp_cache_size: gc.tcp_l1_size,
        num_sqc_per_wgp: gc.num_sqc_per_wgp,
        sqc_data_cache_size: gc.sqc_data_cache_size,
        sqc_inst_cache_size: gc.sqc_inst_cache_size,
        gl1c_cache_size: gc.gl1c_size_per_instance.saturating_mul(gc.gl1c_per_sa),
        gl2c_cache_size: gc.gl2c_per_gpu,
        ..Default::default()
    };
    Ok(as_bytes(&info))
}

/// `AMDGPU_INFO_MEMORY` → `struct drm_amdgpu_memory_info`.
///
/// VRAM and CPU-accessible VRAM are the same number only on an APU. On a
/// discrete card the second is BAR0's length — 256 MiB against however many
/// gigabytes the card has, unless Resizable BAR is sized to VRAM. GTT is the
/// system memory GEM buffers may hold (`amdgpu_gem::gtt_limit`, half of RAM
/// as TTM's default) and what they hold now.
fn memory_info(snap: &Snapshot) -> Vec<u8> {
    let gtt = crate::amdgpu_gem::gtt_limit();
    as_bytes(&uapi::DrmAmdgpuMemoryInfo {
        vram: heap_info(snap.vram_size),
        cpu_accessible_vram: heap_info(snap.visible_vram_size),
        gtt: uapi::DrmAmdgpuHeapInfo {
            heap_usage: crate::amdgpu_gem::gtt_used(),
            ..heap_info(gtt)
        },
    })
}

/// `AMDGPU_INFO_MEMORY` for a card with a client VRAM heap, as
/// amdgpu_info_ioctl reports it: total VRAM is the hardware's, usable VRAM
/// what clients may take (the heap; the rest is the driver's, Linux's
/// pinned and reserved VRAM), usage what they hold now. CPU-accessible VRAM
/// is the BAR, of which clients may take the heap's visible pool.
fn memory_info_heap(snap: &Snapshot, heap: crate::amdgpu_gem::HeapUsage) -> Vec<u8> {
    let usable = heap.visible.0 + heap.unmapped.0;
    let gtt = crate::amdgpu_gem::gtt_limit();
    let info = |total: u64, usable: u64, usage: u64| uapi::DrmAmdgpuHeapInfo {
        total_heap_size: total,
        usable_heap_size: usable,
        heap_usage: usage,
        max_allocation: usable / 4 * 3,
    };
    as_bytes(&uapi::DrmAmdgpuMemoryInfo {
        vram: info(snap.vram_size, usable, heap.visible.1 + heap.unmapped.1),
        cpu_accessible_vram: info(
            snap.visible_vram_size,
            heap.visible.0.min(usable),
            heap.visible.1,
        ),
        gtt: info(gtt, gtt, crate::amdgpu_gem::gtt_used()),
    })
}

/// `AMDGPU_INFO_VRAM_GTT` for a card with a client VRAM heap: the usable
/// sizes, as amdgpu_info_ioctl subtracts pinned and reserved VRAM.
fn vram_gtt_heap(heap: crate::amdgpu_gem::HeapUsage) -> Vec<u8> {
    let usable = heap.visible.0 + heap.unmapped.0;
    as_bytes(&uapi::DrmAmdgpuInfoVramGtt {
        vram_size: usable,
        vram_cpu_accessible_size: heap.visible.0.min(usable),
        gtt_size: crate::amdgpu_gem::gtt_limit(),
    })
}

/// `AMDGPU_INFO_VRAM_GTT` → the older three-u64 form of the same thing.
fn vram_gtt(snap: &Snapshot) -> Vec<u8> {
    as_bytes(&uapi::DrmAmdgpuInfoVramGtt {
        vram_size: snap.vram_size,
        vram_cpu_accessible_size: snap.visible_vram_size,
        gtt_size: crate::amdgpu_gem::gtt_limit(),
    })
}

/// `AMDGPU_INFO_HW_IP_INFO` → `struct drm_amdgpu_info_hw_ip`.
///
/// `available_rings` is a bitmask of usable rings; it is zero here, and
/// `dispatch_for` sets it from the open's card (`available_rings`). Linux
/// returns success with a zero mask for an IP that exists but has no ring,
/// so userspace reads that as "present, unusable" rather than as an error.
fn hw_ip_info(snap: &Snapshot, ip_type: u32) -> Result<Vec<u8>, FsError> {
    let hw_id = hw_id_for_ip_type(ip_type).ok_or(FsError::InvalidData)?;
    let mut info = uapi::DrmAmdgpuInfoHwIp::default();
    if let Some(block) = amdgpu_discovery::find_ip(&snap.ip_blocks, hw_id, 0) {
        info.hw_ip_version_major = u32::from(block.major);
        info.hw_ip_version_minor = u32::from(block.minor);
        // 32 bytes is the GFX11 minimum and what Linux reports for the gfx
        // and compute rings.
        info.ib_start_alignment = 32;
        info.ib_size_alignment = 32;
        // `available_rings` is the open's card's (`dispatch_for`).
        info.ip_discovery_version =
            u32::from(block.major) << 16 | u32::from(block.minor) << 8 | u32::from(block.revision);
    }
    Ok(as_bytes(&info))
}

/// The rings of `ip_type` instance `ip_instance` that DRM card `card` runs
/// jobs on, as `amdgpu_hw_ip_info` sets a bit per ready ring: bit 0 when
/// the card's registered submitter serves that IP's ring 0.
pub fn available_rings(card: Option<u32>, ip_type: u32, ip_instance: u32) -> u32 {
    card.and_then(crate::amdgpu_cs::submitter)
        .and_then(|engine| engine.ring_for(ip_type, ip_instance, 0))
        .map_or(0, |_| 1)
}

/// `AMDGPU_HW_IP_*` → the discovery table's `HW_ID_*`.
fn hw_id_for_ip_type(ip_type: u32) -> Option<u16> {
    match ip_type {
        uapi::AMDGPU_HW_IP_GFX | uapi::AMDGPU_HW_IP_COMPUTE => Some(amdgpu_discovery::HW_ID_GC),
        uapi::AMDGPU_HW_IP_DMA => Some(amdgpu_discovery::HW_ID_SDMA0),
        _ => None,
    }
}

/// `AMDGPU_INFO_HW_IP_COUNT` → how many instances of this IP exist.
fn hw_ip_count(snap: &Snapshot, ip_type: u32) -> Result<Vec<u8>, FsError> {
    let hw_id = hw_id_for_ip_type(ip_type).ok_or(FsError::InvalidData)?;
    let n = snap.ip_blocks.iter().filter(|b| b.hw_id == hw_id).count() as u32;
    Ok(n.to_le_bytes().to_vec())
}

/// Build the reply for one `AMDGPU_INFO` query against the bound device.
///
/// No bound controller is ENODEV, not EINVAL: the ioctl is well formed and
/// the device is absent. That is the QEMU case.
pub fn query(query: u32, payload: [u32; 4]) -> Result<Vec<u8>, FsError> {
    let snap = snapshot().ok_or(FsError::NotFound)?;
    query_against(&snap, query, payload)
}

/// Whether `snap` is a Navi 22, whose queries `amdgpu_info_navi22` answers.
fn answers_navi22(snap: &Snapshot) -> bool {
    snap.family == Family::Navi2
        && snap.did == u32::from(crate::amdgpu::NAVI22)
        && family_id(snap).is_some()
}

/// The client VRAM heap of `vm`'s card, unless Navi 22 answers for it.
fn card_heap(vm: &crate::amdgpu_vm::VmState) -> Option<crate::amdgpu_gem::HeapUsage> {
    if snapshot().is_some_and(|snap| answers_navi22(&snap)) {
        return None;
    }
    vm.card().and_then(crate::amdgpu_gem::vram_heap_usage)
}

/// [`query`] against an explicit device description.
pub fn query_against(snap: &Snapshot, query: u32, payload: [u32; 4]) -> Result<Vec<u8>, FsError> {
    // Navi 22 answers its own identity, topology and firmware queries.
    if answers_navi22(snap) {
        if let Some(reply) = crate::amdgpu_info_navi22::query(snap, query, payload) {
            return reply;
        }
    }
    match query {
        // There is no submission path, so this is false. See the module
        // LINUX-GAP — reporting true would make Mesa fail later and worse.
        uapi::AMDGPU_INFO_ACCEL_WORKING => Ok(vec![0u8; 4]),
        uapi::AMDGPU_INFO_DEV_INFO => dev_info(snap),
        uapi::AMDGPU_INFO_MEMORY => Ok(memory_info(snap)),
        uapi::AMDGPU_INFO_VRAM_GTT => Ok(vram_gtt(snap)),
        // `query_hw_ip { type, ip_instance }` — type is word 0.
        uapi::AMDGPU_INFO_HW_IP_INFO => hw_ip_info(snap, payload[0]),
        uapi::AMDGPU_INFO_HW_IP_COUNT => hw_ip_count(snap, payload[0]),
        // `read_mmr_reg { dword_offset, count, instance, flags }`.
        uapi::AMDGPU_INFO_READ_MMR_REG => read_mmr_reg(snap, *NAVI48_TOPOLOGY.lock(), payload),
        uapi::AMDGPU_INFO_TIMESTAMP => timestamp(snap, *NAVI48_CLOCK.lock()),
        // `query_fw { fw_type, ip_instance, index }`.
        uapi::AMDGPU_INFO_FW_VERSION => firmware_version(snap, *NAVI48_FIRMWARE.lock(), payload[0]),
        // Everything else: `amdgpu_info_ioctl`'s default arm.
        _ => Err(FsError::InvalidData),
    }
}

/// `DRM_IOCTL_AMDGPU_*` dispatch for one open of an amdgpu node.
///
/// Returns `Unsupported` for a command this driver does not implement, so the
/// caller falls through to the generic DRM/KMS path exactly as the virtio-gpu
/// private dispatcher does.
pub fn dispatch(cmd: u32, arg: usize) -> Result<u64, FsError> {
    dispatch_for(cmd, arg, None)
}

/// `AMDGPU_INFO` for an open with address space `vm`: queries about the
/// open itself (`AMDGPU_INFO_GPUVM_FAULT`) answer from it.
pub fn dispatch_for(
    cmd: u32,
    arg: usize,
    vm: Option<&crate::amdgpu_vm::VmState>,
) -> Result<u64, FsError> {
    let nr = drm_uapi::ioc_nr(cmd);
    if nr != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_INFO {
        return Err(FsError::Unsupported);
    }

    // `struct drm_amdgpu_info`: return_pointer u64, return_size u32,
    // query u32, then the 16-byte union.
    let size = core::mem::size_of::<uapi::DrmAmdgpuInfo>();
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or kernel-owned on the test path); `copy_in` bounds-checks
    // the length and SMAP-brackets the read.
    let bytes = unsafe { crate::drm_ioctl_bridge::copy_in(arg, size)? };
    let return_pointer = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let return_size = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let which = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let mut payload = [0u32; 4];
    for (i, word) in payload.iter_mut().enumerate() {
        let at = 16 + i * 4;
        *word = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    }

    // `amdgpu_info_ioctl` rejects both of these before looking at `query`.
    if return_size == 0 || return_pointer == 0 {
        return Err(FsError::InvalidData);
    }

    let reply = match (which, vm) {
        // amdgpu_info_ioctl: the open's VM fault cache, under the PASID lock.
        (uapi::AMDGPU_INFO_GPUVM_FAULT, Some(vm)) => {
            let f = vm.fault();
            let mut out = alloc::vec::Vec::with_capacity(16);
            out.extend_from_slice(&f.addr.to_le_bytes());
            out.extend_from_slice(&f.status.to_le_bytes());
            out.extend_from_slice(&f.vmhub.to_le_bytes());
            out
        }
        // The open's card's client VRAM heap, where it has one; Navi 22
        // answers its own.
        (uapi::AMDGPU_INFO_MEMORY | uapi::AMDGPU_INFO_VRAM_GTT, Some(vm))
            if card_heap(vm).is_some() =>
        {
            let snap = snapshot().ok_or(FsError::NotFound)?;
            let heap = card_heap(vm).ok_or(FsError::NotFound)?;
            if which == uapi::AMDGPU_INFO_MEMORY {
                memory_info_heap(&snap, heap)
            } else {
                vram_gtt_heap(heap)
            }
        }
        // amdgpu_hw_ip_info: the rings the open's card can run its jobs on.
        (uapi::AMDGPU_INFO_HW_IP_INFO, Some(vm)) => {
            let mut reply = query(which, payload)?;
            let served = available_rings(vm.card(), payload[0], payload[1]);
            if let Some(field) = reply.get_mut(24..28) {
                // Navi 22 already answered Linux's multi-ring mask behind its
                // accel switch (`amdgpu_info_navi22`); keep it while the
                // card's submitter serves the IP, so a switched-on part
                // whose submitter failed to register reports no rings.
                let rings = if snapshot().is_some_and(|snap| answers_navi22(&snap)) {
                    let navi22 = u32::from_le_bytes(field[..].try_into().unwrap());
                    if served != 0 {
                        navi22
                    } else {
                        0
                    }
                } else {
                    served
                };
                field.copy_from_slice(&rings.to_le_bytes());
            }
            reply
        }
        // amdgpu_ring_max_ibs per IP type: what one CS may carry on the
        // rings the open's card runs, 0 for the rest.
        (uapi::AMDGPU_INFO_MAX_IBS, Some(vm)) => {
            let engine = vm
                .card()
                .and_then(crate::amdgpu_cs::submitter)
                .ok_or(FsError::InvalidData)?;
            (0..uapi::AMDGPU_HW_IP_NUM)
                .flat_map(|ip| {
                    engine
                        .ring_for(ip, 0, 0)
                        .map_or(0, |ring| engine.max_ibs(ring))
                        .to_le_bytes()
                })
                .collect()
        }
        _ => query(which, payload)?,
    };
    // Linux copies `min(size, sizeof(result))`: a userspace built against an
    // older header asks for fewer bytes and must get a short, valid answer
    // rather than EINVAL.
    let n = reply.len().min(return_size as usize);
    // SAFETY: `return_pointer` is the user out-pointer the caller supplied
    // and is non-zero here; we write at most the `return_size` bytes it
    // advertised. `copy_out` SMAP-brackets the write.
    unsafe { crate::drm_ioctl_bridge::copy_out(return_pointer as usize, &reply[..n])? };
    Ok(0)
}

#[cfg(feature = "kernel-test")]
mod topology_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn decode(bytes: &[u8]) -> uapi::DrmAmdgpuInfoDevice {
        assert_eq!(
            bytes.len(),
            core::mem::size_of::<uapi::DrmAmdgpuInfoDevice>()
        );
        // SAFETY: exact-sized POD reply; byte vectors need not be aligned.
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }
    }
    fn gfx12_dev_info_uses_harvesting_without_claiming_acceleration() -> TestResult {
        let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
        gpu.gc_info = Some(GcInfo {
            num_se: 4,
            num_sa_per_se: 2,
            num_cu_per_sa: 8,
            num_rb_per_se: 4,
            ..Default::default()
        });
        let snap = Snapshot::from_gpu(&gpu);
        let unknown = decode(&dev_info_topology(&snap, None, None).unwrap());
        let topology = crate::amdgpu_gfx12_topology::Topology {
            active_cus: 56,
            active_arrays: 0x7f,
            cu_bitmap: [
                [0xff, 0xff, 0, 0],
                [0xff, 0xff, 0, 0],
                [0xff, 0xff, 0, 0],
                [0xff, 0, 0, 0],
            ],
            enabled_rb_mask: 0x3fff,
            gb_addr_config: 0x2644_2043,
        };
        let known = decode(
            &dev_info_topology(
                &snap,
                Some(topology),
                Some([500_000, 3_100_000, 1_258_000, 1_258_000]),
            )
            .unwrap(),
        );
        if unknown.cu_active_number != 0
            || unknown.cu_bitmap != [[0; 4]; 4]
            || unknown.enabled_rb_pipes_mask != 0
            || known.cu_active_number != 56
            || known.cu_bitmap != topology.cu_bitmap
            || known.enabled_rb_pipes_mask != 0x3fff
            || known.num_rb_pipes != 16
            || unknown.max_engine_clock != 0
            || (known.min_engine_clock, known.max_engine_clock) != (500_000, 3_100_000)
            || (known.min_memory_clock, known.max_memory_clock) != (1_258_000, 1_258_000)
            || query_against(&snap, uapi::AMDGPU_INFO_ACCEL_WORKING, [0; 4]).unwrap() != [0; 4]
        {
            return TestResult::Fail("DEV_INFO lost harvesting or advertised acceleration");
        }
        let mut apu = snap;
        apu.family = Family::Phoenix;
        let apu_info = decode(&dev_info_topology(&apu, Some(topology), Some([1; 4])).unwrap());
        if apu_info.cu_active_number != 64
            || apu_info.enabled_rb_pipes_mask != 0
            || apu_info.max_engine_clock != 0
        {
            return TestResult::Fail("discrete topology leaked into an APU query");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        gfx12_dev_info_uses_harvesting_without_claiming_acceleration
    );

    /// MEMORY and VRAM_GTT for a card with a client heap: hardware totals,
    /// the heap as usable, its allocations as usage.
    fn info_memory_reports_the_card_heap() -> TestResult {
        let gpu = crate::amdgpu_navi48_firmware::tests::gpu();
        let mut snap = Snapshot::from_gpu(&gpu);
        snap.vram_size = 16 << 30;
        snap.visible_vram_size = 256 << 20;
        let heap = crate::amdgpu_gem::HeapUsage {
            visible: (192 << 20, 8 << 20),
            unmapped: ((15 << 30) + (512 << 20), 1 << 30),
        };
        let bytes = memory_info_heap(&snap, heap);
        // SAFETY: exact-sized POD reply; byte vectors need not be aligned.
        let m: uapi::DrmAmdgpuMemoryInfo =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
        let usable = (15 << 30) + (704 << 20);
        let bytes = vram_gtt_heap(heap);
        // SAFETY: as above.
        let v: uapi::DrmAmdgpuInfoVramGtt =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
        if m.vram.total_heap_size != 16 << 30
            || m.vram.usable_heap_size != usable
            || m.vram.heap_usage != (1 << 30) + (8 << 20)
            || m.vram.max_allocation != usable / 4 * 3
            || m.cpu_accessible_vram.total_heap_size != 256 << 20
            || m.cpu_accessible_vram.usable_heap_size != 192 << 20
            || m.cpu_accessible_vram.heap_usage != 8 << 20
            || m.gtt.total_heap_size != crate::amdgpu_gem::gtt_limit()
            || (v.vram_size, v.vram_cpu_accessible_size) != (usable, 192 << 20)
        {
            return TestResult::Fail("MEMORY / VRAM_GTT from the card's client heap");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/gfx12", info_memory_reports_the_card_heap);

    /// What Mesa's ac_query_gpu_info cannot start without on GFX12: the
    /// CP firmware versions, and `GB_ADDR_CONFIG` at dword 0x263e (GC
    /// segment 0 at 0x1260, plus 0x13de) — and nothing else of the
    /// register file.
    fn gfx12_info_answers_mesa_firmware_and_register_queries() -> TestResult {
        let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
        gpu.ip_blocks[0].base_addrs[0] = 0x1260;
        gpu.ip_blocks[0].num_bases = 2;
        let snap = Snapshot::from_gpu(&gpu);
        let topology = crate::amdgpu_gfx12_topology::Topology {
            active_cus: 64,
            active_arrays: 0xff,
            cu_bitmap: [[0xff, 0xff, 0, 0]; 4],
            enabled_rb_mask: 0xffff,
            gb_addr_config: 0x2644_2043,
        };
        let all = u32::MAX;
        let read =
            |offset, count, instance, t| read_mmr_reg(&snap, t, [offset, count, instance, 0]);
        if read(0x263e, 1, all, Some(topology)) != Ok(0x2644_2043u32.to_le_bytes().to_vec())
            || read(0x263e, 1, 0x0001_0103, Some(topology)).is_err()
            || read(0x263e, 0, all, Some(topology)) != Ok(Vec::new())
            || read(0x263e, 2, all, Some(topology)) != Err(FsError::BadAddress)
            || read(0x263d, 1, all, Some(topology)) != Err(FsError::BadAddress)
            || read(0x263e, 1, all, None) != Err(FsError::BadAddress)
            || read(0x263e, 1, 0x04, Some(topology)) != Err(FsError::InvalidData)
            || read(0x263e, 1, 0x0200, Some(topology)) != Err(FsError::InvalidData)
            || read(0x263e, 129, all, Some(topology)) != Err(FsError::InvalidData)
        {
            return TestResult::Fail("READ_MMR_REG allow-list");
        }
        let mut other = snap.clone();
        other.did = 0x73df;
        if read_mmr_reg(&other, Some(topology), [0x263e, 1, all, 0]) != Err(FsError::InvalidData) {
            return TestResult::Fail("READ_MMR_REG off Navi48");
        }
        let firmware = Some([
            (uapi::AMDGPU_INFO_FW_GFX_ME, 0x10, 0x2f),
            (uapi::AMDGPU_INFO_FW_GFX_PFP, 0x11, 0x2f),
            (uapi::AMDGPU_INFO_FW_GFX_MEC, 0x12, 0x30),
        ]);
        let fw = |t| firmware_version(&snap, firmware, t);
        if fw(uapi::AMDGPU_INFO_FW_GFX_MEC)
            != Ok(as_bytes(&uapi::DrmAmdgpuInfoFirmware {
                ver: 0x12,
                feature: 0x30,
            }))
            || fw(uapi::AMDGPU_INFO_FW_GFX_ME).is_err()
            || fw(uapi::AMDGPU_INFO_FW_VCN) != Err(FsError::InvalidData)
            || firmware_version(&snap, None, uapi::AMDGPU_INFO_FW_GFX_ME).is_ok()
            || firmware_version(&other, firmware, uapi::AMDGPU_INFO_FW_GFX_ME).is_ok()
        {
            return TestResult::Fail("FW_VERSION");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        gfx12_info_answers_mesa_firmware_and_register_queries
    );

    /// The reference clock comes from smu_info, and on Navi and later from
    /// gfx_info's timer reference instead, by table revision.
    fn info_reference_clock_follows_atomfirmware() -> TestResult {
        let image = |smu: Option<[u8; 2]>, gfx: Option<[u8; 2]>| {
            let mut b = alloc::vec![0u8; 1024];
            b[..2].copy_from_slice(&[0x55, 0xaa]);
            b[0x48..0x4a].copy_from_slice(&0x80u16.to_le_bytes());
            b[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
            b[0xa0..0xa2].copy_from_slice(&0xc0u16.to_le_bytes());
            // Master data table v2.1 with 16 entries.
            b[0xc0..0xc4].copy_from_slice(&[36, 0, 2, 1]);
            if let Some([f, c]) = smu {
                b[0xd4..0xd6].copy_from_slice(&0x100u16.to_le_bytes());
                b[0x100..0x104].copy_from_slice(&[64, 0, f, c]);
                b[0x110..0x114].copy_from_slice(&2_500u32.to_le_bytes());
            }
            if let Some([f, c]) = gfx {
                b[0xe0..0xe2].copy_from_slice(&0x200u16.to_le_bytes());
                b[0x200..0x204].copy_from_slice(&[64, 0, f, c]);
                b[0x228..0x22c].copy_from_slice(&10_000u32.to_le_bytes());
            }
            b
        };
        let both = image(Some([3, 1]), Some([3, 0]));
        if reference_clock_10khz(&both, true) != Some(10_000)
            || reference_clock_10khz(&both, false) != Some(2_500)
            || reference_clock_10khz(&image(Some([4, 0]), Some([2, 2])), true) != Some(10_000)
            || reference_clock_10khz(&image(Some([3, 1]), Some([2, 1])), true) != Some(2_500)
            || reference_clock_10khz(&image(Some([2, 0]), None), true).is_some()
            || reference_clock_10khz(&image(None, Some([3, 0])), true) != Some(10_000)
            || reference_clock_10khz(&[0; 64], true).is_some()
        {
            return TestResult::Fail("reference clock table selection");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        info_reference_clock_follows_atomfirmware
    );

    /// umc_info v4.0 gives the memory type and the bus width; other
    /// revisions and malformed widths give nothing to report.
    fn info_umc_vram_follows_atomfirmware() -> TestResult {
        let image = |revision: [u8; 2], kind: u8, channels: u8, width: u8| {
            let mut b = alloc::vec![0u8; 1024];
            b[..2].copy_from_slice(&[0x55, 0xaa]);
            b[0x48..0x4a].copy_from_slice(&0x80u16.to_le_bytes());
            b[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
            b[0xa0..0xa2].copy_from_slice(&0xc0u16.to_le_bytes());
            // Master data table v2.1 with 34 entries; umc_info is 24.
            b[0xc0..0xc4].copy_from_slice(&[72, 0, 2, 1]);
            b[0xf4..0xf6].copy_from_slice(&0x200u16.to_le_bytes());
            b[0x200..0x204].copy_from_slice(&[88, 0, revision[0], revision[1]]);
            b[0x200 + 26] = kind;
            b[0x200 + 64] = channels;
            b[0x200 + 65] = width;
            b
        };
        if umc_vram(&image([4, 0], 0x70, 16, 4)) != Some((uapi::AMDGPU_VRAM_TYPE_GDDR6, 256))
            || umc_vram(&image([4, 0], 0x81, 8, 7)) != Some((uapi::AMDGPU_VRAM_TYPE_HBM3E, 1024))
            || umc_vram(&image([4, 0], 0x33, 4, 4)) != Some((uapi::AMDGPU_VRAM_TYPE_UNKNOWN, 64))
            || umc_vram(&image([4, 0], 0x70, 16, 40)) != Some((uapi::AMDGPU_VRAM_TYPE_GDDR6, 0))
            || umc_vram(&image([3, 3], 0x70, 16, 4)).is_some()
            || umc_vram(&[0; 64]).is_some()
        {
            return TestResult::Fail("umc_info VRAM type/width");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/gfx12", info_umc_vram_follows_atomfirmware);

    /// firmware_info v3's boot mclk, whatever its content revision.
    fn info_boot_mclk_follows_atomfirmware() -> TestResult {
        let image = |revision: [u8; 2]| {
            let mut b = alloc::vec![0u8; 1024];
            b[..2].copy_from_slice(&[0x55, 0xaa]);
            b[0x48..0x4a].copy_from_slice(&0x80u16.to_le_bytes());
            b[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
            b[0xa0..0xa2].copy_from_slice(&0xc0u16.to_le_bytes());
            b[0xc0..0xc4].copy_from_slice(&[36, 0, 2, 1]);
            // firmwareinfo is master data table 4.
            b[0xcc..0xce].copy_from_slice(&0x200u16.to_le_bytes());
            b[0x200..0x204].copy_from_slice(&[64, 0, revision[0], revision[1]]);
            b[0x208..0x20c].copy_from_slice(&250_000u32.to_le_bytes());
            b[0x20c..0x210].copy_from_slice(&125_800u32.to_le_bytes());
            b
        };
        if boot_mclk_10khz(&image([3, 4])) != Some(125_800)
            || boot_mclk_10khz(&image([3, 5])) != Some(125_800)
            || boot_mclk_10khz(&image([2, 1])).is_some()
            || boot_mclk_10khz(&[0; 64]).is_some()
        {
            return TestResult::Fail("firmware_info boot mclk");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/gfx12", info_boot_mclk_follows_atomfirmware);
}

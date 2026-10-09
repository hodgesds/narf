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
//! LINUX-GAP: `ACCEL_WORKING` reports **false**. Not because the pieces are
//! absent — `AMDGPU_CS` parses and validates, the rings and their doorbells
//! exist, the MQDs are built and written, the page tables are materialised —
//! but because the MES has not been brought up, so no queue is registered with
//! the firmware and no submitted work executes. That is the honest answer and it is also the
//! useful one: Mesa declines the device cleanly at initialisation instead of
//! coming up and failing at first draw. Flipping this flag is the milestone
//! marker for the last link in the submission path landing, and the reason it
//! is still a gap is in `amdgpu_cs`.
//!
//! LINUX-GAP: the queries that need subsystems this driver has not built are
//! refused rather than guessed — TIMESTAMP (no GFX clock-counter read),
//! FW_VERSION (loaded microcode versions are parsed during the PSP sequence
//! but not retained) and READ_MMR_REG (no register whitelist).
//!
//! LINUX-GAP: clocks (`max/min_engine_clock`, `max/min_memory_clock`,
//! `gpu_counter_freq`) need an SMU metrics read, and `vram_type` /
//! `vram_bit_width` need the GMC memory configuration. Both exist elsewhere in
//! the tree — `amdgpu_smu`, and the platform inventory's memory type and
//! channel count — but are not plumbed to this ioctl yet; they are zero, not
//! invented.

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
/// every GFX 11 variant including 11.0.1.
const GFX11_HW_CONTEXTS: u32 = 8;

/// `adev->family` — the `AMDGPU_FAMILY_*` value userspace matches on.
///
/// Mesa keys ASIC behaviour off this plus the device id, so a wrong value here
/// selects a different code path in the userspace driver.
fn family_id(family: Family) -> Option<u32> {
    match family {
        // Phoenix / Phoenix2 / HawkPoint are GFX 11.0.1.
        Family::Phoenix => Some(uapi::AMDGPU_FAMILY_GC_11_0_1),
        // Renoir / Cezanne / Lucienne / Barcelo are the Raven family line.
        Family::Renoir => Some(uapi::AMDGPU_FAMILY_RV),
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
    /// Visible VRAM aperture, in bytes.
    pub vram_size: u64,
    pub gc: Option<GcInfo>,
    pub ip_blocks: Vec<crate::amdgpu_discovery::IpBlock>,
}

fn snapshot() -> Option<Snapshot> {
    crate::amdgpu::with_controller(|gpu| Snapshot {
        did: gpu.chip.did as u32,
        family: gpu.chip.family,
        vram_size: gpu.vram.size,
        gc: gpu.gc_info,
        ip_blocks: gpu.ip_blocks.clone(),
    })
}

/// A `#[repr(C)]` reply struct as the bytes the ioctl copies out.
///
/// The replies are built by filling the mirrored struct and taking its bytes,
/// never by writing at computed offsets. The mirror's layout is pinned
/// against the C header by a generated size test, so this cannot drift; an
/// offset table would be a second, unchecked copy of the same information.
fn as_bytes<T: Copy>(value: &T) -> Vec<u8> {
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
fn dev_info(snap: &Snapshot) -> Result<Vec<u8>, FsError> {
    let family = family_id(snap.family).ok_or(FsError::InvalidData)?;
    // The shader geometry is not guessable. Refusing is better than reporting
    // a topology that would mis-compile shaders.
    let gc = snap.gc.ok_or(FsError::InvalidData)?;
    // Every GMC 11 part has the same VM layout; it comes out of
    // `gmc_v11_0_sw_init`'s `amdgpu_vm_adjust_size` arguments, not out of
    // anything the VM manager has to have initialised first.
    let va = crate::amdgpu_vm::Geometry::GMC11.va_info();

    let info = uapi::DrmAmdgpuInfoDevice {
        device_id: snap.did,
        family,
        num_shader_engines: gc.num_se,
        num_shader_arrays_per_engine: gc.num_sa_per_se,
        cu_active_number: gc.total_cus(),
        num_rb_pipes: gc.num_rb_per_se.saturating_mul(gc.num_se),
        num_hw_gfx_contexts: GFX11_HW_CONTEXTS,
        // Every part this driver supports is an APU, which is what
        // AMDGPU_IDS_FLAGS_FUSION means. PREEMPTION, TMZ and GANG_SUBMIT are
        // deliberately NOT claimed: each is a submission-path capability and
        // there is no submission path.
        ids_flags: u64::from(uapi::AMDGPU_IDS_FLAGS_FUSION),
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
/// The aperture read at probe is the visible VRAM, so VRAM and
/// CPU-accessible VRAM are the same number on these APUs. GTT is zero: there
/// is no GART or system-memory heap manager, and claiming a size for a heap
/// nothing can allocate from would be worse than reporting none.
fn memory_info(snap: &Snapshot) -> Vec<u8> {
    as_bytes(&uapi::DrmAmdgpuMemoryInfo {
        vram: heap_info(snap.vram_size),
        cpu_accessible_vram: heap_info(snap.vram_size),
        gtt: heap_info(0),
    })
}

/// `AMDGPU_INFO_VRAM_GTT` → the older three-u64 form of the same thing.
fn vram_gtt(snap: &Snapshot) -> Vec<u8> {
    as_bytes(&uapi::DrmAmdgpuInfoVramGtt {
        vram_size: snap.vram_size,
        vram_cpu_accessible_size: snap.vram_size,
        gtt_size: 0,
    })
}

/// `AMDGPU_INFO_HW_IP_INFO` → `struct drm_amdgpu_info_hw_ip`.
///
/// `available_rings` is a bitmask of usable rings and it is **zero** for every
/// IP, which is the truth: no ring has been brought up. Linux returns success
/// with a zero mask for an IP that exists but has no ring, so userspace reads
/// this as "present, unusable" rather than as an error.
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
        // `available_rings` stays zero — see the doc comment.
        info.ip_discovery_version =
            u32::from(block.major) << 16 | u32::from(block.minor) << 8 | u32::from(block.revision);
    }
    Ok(as_bytes(&info))
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

/// [`query`] against an explicit device description.
pub fn query_against(snap: &Snapshot, query: u32, payload: [u32; 4]) -> Result<Vec<u8>, FsError> {
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

    let reply = query(which, payload)?;
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

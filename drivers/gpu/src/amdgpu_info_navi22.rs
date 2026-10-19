//! Navi 22 (GC 10.3.2) `AMDGPU_INFO` replies, as Linux `amdgpu_kms.c`
//! answers them for this ASIC.
//!
//! [`crate::amdgpu_info`] routes a bound Navi 22 here. The identity and
//! topology fields come from three published sources, never from a per-board
//! table:
//!
//! - the discovery GC table (maxima), already in the [`Snapshot`];
//! - [`Topology`], sampled by the cold boot's `ReadTopology` stage from the
//!   fuse/user-disable registers, GB_ADDR_CONFIG and the NBIO revision strap
//!   (the same publish-from-boot-owner pattern Navi48 uses for GFX12);
//! - [`Boot`], the firmware versions of the set the cold boot loaded, plus
//!   the SMU version and GFX DPM range it observed, published only after the
//!   cold boot completed.
//!
//! A field whose source has not been published is zero, as Navi48 reports an
//! unread harvest; Mesa then declines the device (`external_rev` 0 is not a
//! Navi 22) rather than mis-compiling for a guessed topology.
//!
//! ## The submission switch
//!
//! [`SUBMISSION`] is the one place that decides whether userspace is told the
//! GPU accepts work: `ACCEL_WORKING`, every `available_rings` mask,
//! `HW_IP_COUNT` and `AMDGPU_IDS_FLAGS_GANG_SUBMIT` all derive from it, as do
//! the DRM version minor and whether `amdgpu_navi22_cs` registers the card's
//! submitter.
//!
//! LINUX-GAP: `gpu_counter_freq` (VBIOS gfx_info refclk), `vram_type` /
//! `vram_bit_width` (VBIOS vram_info), memory clocks (SMU UCLK range),
//! `pcie_gen` / `pcie_num_lanes`, and `mall_size` (discovery MALL table) are
//! zero; Mesa uses them for heuristics only on GFX10.3. Pinned-VRAM
//! accounting is zero until GEM owns VRAM placement; GTT is zero until GART.
//! READ_MMR_REG answers GB_ADDR_CONFIG only; the live-status registers of
//! `nv_allowed_read_registers` need GC MMIO the cold-boot owner holds, and
//! return EFAULT. See `drivers/gpu/research/navi22-mesa-abi.md`.

use alloc::vec::Vec;

use narf_filesystem::FsError;

use crate::amdgpu_discovery::{self as discovery, IpBlock};
use crate::amdgpu_gfx10_topology::Topology;
use crate::amdgpu_info::{as_bytes, Snapshot};
use crate::amdgpu_uapi as uapi;

/// Whether `AMDGPU_CS` executes client work on the native queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// Queues may be verified, but no client IB runs on them yet.
    NotWired,
    /// CS submits to the native GFX/compute/SDMA queues under per-client
    /// VMIDs and returns accurate fences.
    Wired,
}

/// THE switch. `Wired` since `AMDGPU_CS` runs client IBs on the verified
/// kernel queues in each client's GPUVM with fences (`amdgpu_navi22_cs` on
/// the generic `amdgpu_cs` path, `amdgpu_navi22_submit`; register-model proof
/// `navi22_submit_gfx_user_vmid_ib_executes_and_fences`). Even wired,
/// nothing is advertised unless the cold boot's ring/IB tests passed
/// ([`Boot::queues_verified`]). Setting it to `NotWired` withdraws
/// ACCEL_WORKING, every ring mask, HW_IP_COUNT, GANG_SUBMIT, DRM minor 64 and
/// the render ioctls at once.
pub const SUBMISSION: Submission = Submission::Wired;

static ACCEL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Boot-time opt-in (`amdgpu.navi22_accel`, set by the fb handoff before the
/// cold boot runs). Not yet validated on hardware, so off by default.
pub fn set_accel(enabled: bool) {
    ACCEL.store(enabled, core::sync::atomic::Ordering::Release);
}
/// The switch as this boot applies it: wired code is advertised only with
/// `amdgpu.navi22_accel`, so the first bare-metal boots prove firmware,
/// queues and display without userspace picking the native path.
pub fn submission() -> Submission {
    if SUBMISSION == Submission::Wired && ACCEL.load(core::sync::atomic::Ordering::Acquire) {
        Submission::Wired
    } else {
        Submission::NotWired
    }
}

/// `amdgpu` 3.64.0 (`KMS_DRIVER_{MAJOR,MINOR,PATCHLEVEL}`) once submissions
/// run; 3.0.0 before, which Mesa (minor ≥ 54) declines.
pub fn drm_version() -> (u32, u32, u32) {
    if submission() == Submission::Wired {
        (3, 64, 0)
    } else {
        (3, 0, 0)
    }
}

/// `AMDGPU_VM_RESERVED_VRAM`.
const VM_RESERVED_VRAM: u64 = 8 << 20; // linux: AMDGPU_VM_RESERVED_VRAM
/// `F32_CE_PROGRAM_RAM_SIZE` (`gfx_v10_0_sw_init`).
const CE_RAM_SIZE: u32 = 65536; // linux: F32_CE_PROGRAM_RAM_SIZE
/// `gfx_v10_0_gpu_early_init`.
const MAX_HW_CONTEXTS: u32 = 8; // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_gpu_early_init)
/// `nv_common_early_init`, GC 10.3.2: `external_rev_id = rev_id + 0x32`.
/// `amdgpu_info_ioctl`: `AMDGPU_GFX_MAX_SE` / `AMDGPU_GFX_MAX_SH_PER_SE`.
const MMR_MAX_SE: u32 = 4; // linux: AMDGPU_GFX_MAX_SE
const MMR_MAX_SH: u32 = 2; // linux: AMDGPU_GFX_MAX_SH_PER_SE
/// `GB_ADDR_CONFIG` dword offset within GC segment 0.
const GB_ADDR_CONFIG: u32 = 0x13de;

/// One `drm_amdgpu_info_firmware`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Version {
    pub ver: u32,
    pub feature: u32,
}

/// The `adev->*_fw_version` / `*_feature_version` values Linux derives from
/// the firmware files it requested, for the Navi 22 set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Firmware {
    pub me: Version,
    pub pfp: Version,
    pub ce: Version,
    pub mec: Version,
    /// Zero when `navy_flounder_mec2.bin` is absent, as Linux leaves it.
    pub mec2: Version,
    pub rlc: Version,
    pub rlc_srlc: Version,
    pub rlc_srlg: Version,
    pub rlc_srls: Version,
    pub rlcp: Version,
    pub rlcv: Version,
    /// Both SDMA instances load the same file.
    pub sdma: Version,
    pub sos: Version,
    pub vcn: Version,
    pub dmcub: Version,
}

fn word(bytes: &[u8], at: usize) -> Result<u32, FirmwareError> {
    bytes
        .get(at..at + 4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .ok_or(FirmwareError)
}
/// `header.ucode_version` (+16) and the feature word at +32 that every
/// v1 gfx/sdma/psp and v2 rlc header carries.
fn header(bytes: &[u8]) -> Result<Version, FirmwareError> {
    Ok(Version {
        ver: word(bytes, 16)?,
        feature: word(bytes, 32)?,
    })
}
fn pair(bytes: &[u8], at: usize) -> Result<Version, FirmwareError> {
    Ok(Version {
        ver: word(bytes, at)?,
        feature: word(bytes, at + 4)?,
    })
}

/// A firmware header too short for the version words it must carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareError;

/// The raw files of the cold-boot set, after their structural validation.
#[derive(Debug)]
pub struct Files<'a> {
    pub me: &'a [u8],
    pub pfp: &'a [u8],
    pub ce: &'a [u8],
    pub mec: &'a [u8],
    pub mec2: Option<&'a [u8]>,
    pub rlc: &'a [u8],
    pub sdma: &'a [u8],
    pub sos: &'a [u8],
    pub vcn: &'a [u8],
    pub dmcub: &'a [u8],
}

impl Firmware {
    /// `amdgpu_gfx_cp_init_microcode`, `amdgpu_gfx_rlc_init_microcode`
    /// (v2.0, v2.1 when minor ≥ 1, v2.3 when minor ≥ 3),
    /// `amdgpu_sdma_init_microcode`, `psp_init_sos_base_fw`,
    /// `amdgpu_vcn_early_init` and `dm_dmub_sw_init`.
    pub fn parse(files: &Files<'_>) -> Result<Self, FirmwareError> {
        let rlc_minor = u16::from_le_bytes(
            files
                .rlc
                .get(10..12)
                .ok_or(FirmwareError)?
                .try_into()
                .unwrap(),
        );
        let since = |minor: u16, at: usize| -> Result<Version, FirmwareError> {
            if rlc_minor >= minor {
                pair(files.rlc, at)
            } else {
                Ok(Version::default())
            }
        };
        Ok(Self {
            me: header(files.me)?,
            pfp: header(files.pfp)?,
            ce: header(files.ce)?,
            mec: header(files.mec)?,
            mec2: files.mec2.map(header).transpose()?.unwrap_or_default(),
            rlc: header(files.rlc)?,
            rlc_srlc: since(1, 108)?,
            rlc_srlg: since(1, 124)?,
            rlc_srls: since(1, 140)?,
            rlcp: since(3, 172)?,
            rlcv: since(3, 188)?,
            sdma: header(files.sdma)?,
            sos: header(files.sos)?,
            vcn: Version {
                ver: word(files.vcn, 16)?,
                feature: 0,
            },
            dmcub: Version {
                ver: word(files.dmcub, 16)?,
                feature: 0,
            },
        })
    }
}

/// What the completed cold boot observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Boot {
    pub firmware: Firmware,
    /// `GetSmuVersion`, which `smu_cmn_check_fw_version` stores as
    /// `adev->pm.fw_version`.
    pub smc: u32,
    /// `GetMin/MaxDpmFreq(GFXCLK)` in MHz, when protected DPM was set up.
    pub gfx_mhz: Option<(u16, u16)>,
    /// The kernel GFX, compute and SDMA ring/IB tests passed.
    pub queues_verified: bool,
    pub sdma_rings: u8,
}

/// Everything published for the bound Navi 22.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Published {
    pub topology: Option<Topology>,
    /// PCI config revision (offset 0x08), `pdev->revision`.
    pub pci_revision: Option<u8>,
    pub boot: Option<Boot>,
    /// `adev->vcn.harvest_config` (discovery harvest table plus the Navy
    /// Flounder quirk), published by the platform owner before the boot.
    pub vcn_harvest: Option<u8>,
    /// Media rings that take client jobs (bit `MediaRing::index()`: dec,
    /// enc0, enc1, JPEG), published by `amdgpu_vcn_navi22_cs::register`.
    pub media_rings: u8,
}

/// `available_rings` per IP once [`SUBMISSION`] is wired: Linux's
/// `(1 << min(amdgpu_ctx_num_entities[ip], ready rings)) - 1` for GC 10.3.2
/// (2 gfx rings, 8 KCQs, 2 SDMA instances).
const LINUX_RINGS: [(u32, u32); 3] = [
    (uapi::AMDGPU_HW_IP_GFX, 0x1),
    (uapi::AMDGPU_HW_IP_COMPUTE, 0xf),
    (uapi::AMDGPU_HW_IP_DMA, 0x3),
];
fn accepting(published: &Published, submission: Submission) -> bool {
    submission == Submission::Wired && published.boot.is_some_and(|b| b.queues_verified)
}
fn available_rings(published: &Published, submission: Submission, ip: u32) -> u32 {
    if !accepting(published, submission) {
        return 0;
    }
    if let Some(mask) = media_available_rings(published, ip) {
        return mask;
    }
    if ip == uapi::AMDGPU_HW_IP_DMA {
        return published.boot.map_or(0, |b| u32::from(b.sdma_rings));
    }
    LINUX_RINGS
        .iter()
        .find(|(t, _)| *t == ip)
        .map_or(0, |(_, mask)| *mask)
}
/// `amdgpu_hw_ip_info` for the media IPs: `(1 << min(1 entity, ready
/// rings)) - 1` over the rings that passed their tests and take client
/// jobs — VCN instance 0's decode ring, its encode rings, the JPEG ring.
fn media_available_rings(published: &Published, ip: u32) -> Option<u32> {
    let rings = published.media_rings;
    let ready = match ip {
        uapi::AMDGPU_HW_IP_VCN_DEC => rings & 1 != 0,
        uapi::AMDGPU_HW_IP_VCN_ENC => rings & 0b110 != 0,
        uapi::AMDGPU_HW_IP_VCN_JPEG => rings & 0b1000 != 0,
        _ => return None,
    };
    Some(u32::from(ready))
}

fn gc(snap: &Snapshot) -> Option<&IpBlock> {
    discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_GC, 0)
}
fn ip_version(block: &IpBlock) -> u32 {
    u32::from(block.major) << 16 | u32::from(block.minor) << 8 | u32::from(block.revision)
}

/// `AMDGPU_INFO_DEV_INFO`, field for field as `amdgpu_kms.c`.
fn dev_info(snap: &Snapshot, submission: Submission) -> Result<Vec<u8>, FsError> {
    let table = snap.gc.ok_or(FsError::InvalidData)?;
    let topology = snap.navi22.topology;
    let va = crate::amdgpu_vm::Geometry::GMC11.va_info();
    let (min_sclk, max_sclk) = snap
        .navi22
        .boot
        .and_then(|b| b.gfx_mhz)
        .map_or((0, 0), |(lo, hi)| {
            (u64::from(lo) * 1000, u64::from(hi) * 1000)
        });
    let info = uapi::DrmAmdgpuInfoDevice {
        device_id: snap.did,
        chip_rev: topology.map_or(0, |t| t.rev_id),
        external_rev: topology.map_or(0, |t| {
            t.rev_id
                + crate::amdgpu_rdna2::for_pci_id(crate::amdgpu::AMD_VENDOR, snap.did as u16)
                    .map_or(0, |p| match p.gc_version.2 {
                        0 => 0x28,
                        2 => 0x32,
                        4 => 0x3c,
                        5 => 0x46,
                        _ => 0,
                    })
        }),
        pci_rev: snap.navi22.pci_revision.map_or(0, u32::from),
        family: uapi::AMDGPU_FAMILY_NV,
        num_shader_engines: table.num_se,
        num_shader_arrays_per_engine: table.num_sa_per_se,
        max_engine_clock: max_sclk,
        min_engine_clock: min_sclk,
        cu_active_number: topology.map_or(0, |t| t.active_cus),
        cu_ao_mask: topology.map_or(0, |t| t.ao_cu_mask),
        cu_bitmap: topology.map_or([[0; 4]; 4], |t| t.cu_bitmap),
        cu_ao_bitmap: topology.map_or([[0; 4]; 4], |t| t.ao_cu_bitmap),
        enabled_rb_pipes_mask: topology.map_or(0, |t| t.enabled_rb_mask),
        num_rb_pipes: table.num_rb_per_se.saturating_mul(table.num_se),
        num_hw_gfx_contexts: MAX_HW_CONTEXTS,
        // Discrete; MCBP and TMZ are off by default on GC 10.3.2 and
        // CONFORMANT_TRUNC_COORD is GFX11-only. Linux claims GANG_SUBMIT on
        // every bare-metal device; here only once submissions run.
        ids_flags: if accepting(&snap.navi22, submission) {
            u64::from(uapi::AMDGPU_IDS_FLAGS_GANG_SUBMIT)
        } else {
            0
        },
        virtual_address_offset: va.low_offset,
        virtual_address_max: va.low_max,
        high_va_offset: va.high_offset,
        high_va_max: va.high_max,
        virtual_address_alignment: 4096,
        gart_page_size: 4096,
        pte_fragment_size: va.pte_fragment_size as u32,
        ce_ram_size: CE_RAM_SIZE,
        gc_double_offchip_lds_buf: table.double_offchip_lds_buffer,
        wave_front_size: table.wave_size,
        num_shader_visible_vgprs: table.num_gprs,
        num_cu_per_sh: table.num_cu_per_sa,
        num_tcc_blocks: table.num_tccs,
        gs_vgt_table_depth: table.gs_table_depth,
        gs_prim_buffer_depth: table.gsprim_buff_depth,
        max_gs_waves_per_vgt: table.num_max_gs_thds,
        // gfx_v10_0_init_pa_sc_tile_steering_override: 0 for GC >= 10.3.
        pa_sc_tile_steering_override: 0,
        tcc_disabled_mask: topology.map_or(0, |t| t.tcc_disabled_mask),
        tcp_cache_size: table.tcp_l1_size,
        num_sqc_per_wgp: table.num_sqc_per_wgp,
        sqc_data_cache_size: table.sqc_data_cache_size,
        sqc_inst_cache_size: table.sqc_inst_cache_size,
        gl1c_cache_size: table
            .gl1c_size_per_instance
            .saturating_mul(table.gl1c_per_sa),
        gl2c_cache_size: table.gl2c_per_gpu,
        ..Default::default()
    };
    Ok(as_bytes(&info))
}

/// The IP block `amdgpu_hw_ip_info` finds for a UAPI type: (block major,
/// block minor, discovery block, IB start/size alignment).
fn block(snap: &Snapshot, ip: u32) -> Option<(u32, u32, Option<&IpBlock>, u32, u32)> {
    let vcn = || discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_VCN, 0);
    match ip {
        // gfx_v10_0_ip_block is 10.0 for every GC 10.x.
        uapi::AMDGPU_HW_IP_GFX | uapi::AMDGPU_HW_IP_COMPUTE => Some((10, 0, gc(snap), 32, 32)),
        uapi::AMDGPU_HW_IP_DMA => Some((
            5,
            2,
            discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_SDMA0, 0),
            256,
            4,
        )),
        // vcn_v3_0_ip_block and jpeg_v3_0_ip_block; versions are UVD_HWIP's.
        uapi::AMDGPU_HW_IP_VCN_DEC => vcn().map(|b| (3, 0, Some(b), 256, 64)),
        uapi::AMDGPU_HW_IP_VCN_ENC => vcn().map(|b| (3, 0, Some(b), 256, 4)),
        uapi::AMDGPU_HW_IP_VCN_JPEG => vcn().map(|b| (3, 0, Some(b), 256, 64)),
        // UVD, VCE, UVD_ENC and VPE blocks do not exist on Navi 22.
        _ => None,
    }
}

/// `amdgpu_hw_ip_info`.
fn hw_ip_info(
    snap: &Snapshot,
    submission: Submission,
    ip: u32,
    instance: u32,
) -> Result<Vec<u8>, FsError> {
    if instance >= uapi::AMDGPU_HW_IP_INSTANCE_MAX_COUNT || ip >= uapi::AMDGPU_HW_IP_NUM {
        return Err(FsError::InvalidData);
    }
    let mut info = uapi::DrmAmdgpuInfoHwIp::default();
    // An absent block is success with an all-zero reply.
    if let Some((major, minor, discovered, start, size)) = block(snap, ip) {
        info.hw_ip_version_major = major;
        info.hw_ip_version_minor = minor;
        info.ip_discovery_version = discovered.map_or(0, ip_version);
        info.ib_start_alignment = start;
        info.ib_size_alignment = size;
        info.available_rings = available_rings(&snap.navi22, submission, ip);
    }
    Ok(as_bytes(&info))
}

/// `AMDGPU_INFO_HW_IP_COUNT`: `count` for an existing block, gated by the
/// same switch as its rings.
fn hw_ip_count(snap: &Snapshot, submission: Submission, ip: u32) -> Result<Vec<u8>, FsError> {
    if block(snap, ip).is_none() {
        return Err(FsError::InvalidData);
    }
    let count = if available_rings(&snap.navi22, submission, ip) == 0 {
        0
    } else {
        match ip {
            uapi::AMDGPU_HW_IP_DMA => snap
                .ip_blocks
                .iter()
                .filter(|b| {
                    matches!(
                        b.hw_id,
                        discovery::HW_ID_SDMA0
                            | discovery::HW_ID_SDMA1
                            | discovery::HW_ID_SDMA2
                            | discovery::HW_ID_SDMA3
                    )
                })
                .count() as u32,
            // `adev->vcn.num_vcn_inst`: every discovered instance, harvested
            // ones included; JPEG is `num_jpeg_inst * num_jpeg_rings` = 1.
            uapi::AMDGPU_HW_IP_VCN_DEC | uapi::AMDGPU_HW_IP_VCN_ENC => {
                snap.ip_blocks
                    .iter()
                    .filter(|b| b.hw_id == discovery::HW_ID_VCN)
                    .count() as u32
            }
            _ => 1,
        }
    };
    Ok(count.to_le_bytes().to_vec())
}

/// `amdgpu_firmware_info` for the Navi 22 set.
fn fw_version(snap: &Snapshot, payload: [u32; 4]) -> Result<Vec<u8>, FsError> {
    let [fw_type, instance, index, _] = payload;
    if instance != 0 {
        return Err(FsError::InvalidData);
    }
    let boot = snap.navi22.boot.ok_or(FsError::InvalidData)?;
    let fw = boot.firmware;
    let zero = Version::default();
    let v = match fw_type {
        uapi::AMDGPU_INFO_FW_GFX_ME => fw.me,
        uapi::AMDGPU_INFO_FW_GFX_PFP => fw.pfp,
        uapi::AMDGPU_INFO_FW_GFX_CE => fw.ce,
        uapi::AMDGPU_INFO_FW_GFX_MEC => match index {
            0 => fw.mec,
            1 => fw.mec2,
            _ => return Err(FsError::InvalidData),
        },
        uapi::AMDGPU_INFO_FW_GFX_RLC => fw.rlc,
        uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_CNTL => fw.rlc_srlc,
        uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_GPM_MEM => fw.rlc_srlg,
        uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_SRM_MEM => fw.rlc_srls,
        uapi::AMDGPU_INFO_FW_GFX_RLCP => fw.rlcp,
        uapi::AMDGPU_INFO_FW_GFX_RLCV => fw.rlcv,
        uapi::AMDGPU_INFO_FW_SDMA if index < 2 => fw.sdma,
        uapi::AMDGPU_INFO_FW_SDMA => return Err(FsError::InvalidData),
        uapi::AMDGPU_INFO_FW_SOS => fw.sos,
        uapi::AMDGPU_INFO_FW_SMC => Version {
            ver: boot.smc,
            feature: 0,
        },
        uapi::AMDGPU_INFO_FW_VCN => fw.vcn,
        uapi::AMDGPU_INFO_FW_DMCUB => fw.dmcub,
        // Not loaded for MP0 11.0.11 / GC 10.3.2: Linux reports zeros.
        uapi::AMDGPU_INFO_FW_VCE
        | uapi::AMDGPU_INFO_FW_UVD
        | uapi::AMDGPU_INFO_FW_GMC
        | uapi::AMDGPU_INFO_FW_ASD
        | uapi::AMDGPU_INFO_FW_DMCU
        | uapi::AMDGPU_INFO_FW_TOC
        | uapi::AMDGPU_INFO_FW_CAP
        | uapi::AMDGPU_INFO_FW_MES_KIQ
        | uapi::AMDGPU_INFO_FW_MES
        | uapi::AMDGPU_INFO_FW_IMU
        | uapi::AMDGPU_INFO_FW_VPE => zero,
        // TA versions live in navy_flounder_ta.bin, which this driver does
        // not open; refused rather than reported as zero.
        _ => return Err(FsError::InvalidData),
    };
    Ok(as_bytes(&uapi::DrmAmdgpuInfoFirmware {
        ver: v.ver,
        feature: v.feature,
    }))
}

/// `nv_read_register` for the allowlist entry that needs no live MMIO.
fn read_mmr_reg(snap: &Snapshot, payload: [u32; 4]) -> Result<Vec<u8>, FsError> {
    let [offset, count, instance, _flags] = payload;
    let se = instance & uapi::AMDGPU_INFO_MMR_SE_INDEX_MASK;
    let sh =
        (instance >> uapi::AMDGPU_INFO_MMR_SH_INDEX_SHIFT) & uapi::AMDGPU_INFO_MMR_SH_INDEX_MASK;
    if (se != uapi::AMDGPU_INFO_MMR_SE_INDEX_MASK && se >= MMR_MAX_SE)
        || (sh != uapi::AMDGPU_INFO_MMR_SH_INDEX_MASK && sh >= MMR_MAX_SH)
        || count > 128
    {
        return Err(FsError::InvalidData);
    }
    let gb_addr = gc(snap)
        .filter(|b| b.num_bases > 0)
        .map(|b| b.base_addrs[0] + GB_ADDR_CONFIG)
        .ok_or(FsError::InvalidData)?;
    let mut out = Vec::new();
    for i in 0..count {
        // Any other offset, or one that needs a live GC read: "unallowed
        // offset", -EFAULT.
        if offset.checked_add(i) != Some(gb_addr) {
            return Err(FsError::BadAddress);
        }
        let value = snap
            .navi22
            .topology
            .ok_or(FsError::InvalidData)?
            .gb_addr_config;
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

fn heap(total: u64, usable: u64) -> uapi::DrmAmdgpuHeapInfo {
    uapi::DrmAmdgpuHeapInfo {
        total_heap_size: total,
        usable_heap_size: usable,
        heap_usage: 0,
        max_allocation: usable * 3 / 4,
    }
}
/// `real_vram_size - vram_pin_size - AMDGPU_VM_RESERVED_VRAM`, pins zero.
fn usable_vram(snap: &Snapshot) -> u64 {
    snap.vram_size.saturating_sub(VM_RESERVED_VRAM)
}
fn memory(snap: &Snapshot) -> Vec<u8> {
    let usable = usable_vram(snap);
    as_bytes(&uapi::DrmAmdgpuMemoryInfo {
        vram: heap(snap.vram_size, usable),
        cpu_accessible_vram: heap(snap.visible_vram_size, snap.visible_vram_size.min(usable)),
        gtt: heap(0, 0),
    })
}
fn vram_gtt(snap: &Snapshot) -> Vec<u8> {
    let usable = usable_vram(snap);
    as_bytes(&uapi::DrmAmdgpuInfoVramGtt {
        vram_size: usable,
        vram_cpu_accessible_size: snap.visible_vram_size.min(usable),
        gtt_size: 0,
    })
}

/// `AMDGPU_INFO_VIDEO_CAPS` (`nv_query_video_codecs`) with this card's
/// `harvest_config`: the published harvest table (VCN1 harvested on the RX
/// 6750 XT, so decode reports `sc_video_codecs_decode_vcn0`, AV1 included),
/// plus every VCN instance absent from discovery. Linux answers it whether
/// or not media rings run; Mesa acts on it once VCN rings are advertised.
fn video_caps(snap: &Snapshot, kind: u32) -> Result<Vec<u8>, FsError> {
    let mut harvested = snap.navi22.vcn_harvest.unwrap_or(0) & 3;
    for inst in 0..2u8 {
        if discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_VCN, inst).is_none() {
            harvested |= 1 << inst;
        }
    }
    let vcn = discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_VCN, 0)
        .or_else(|| discovery::find_ip(&snap.ip_blocks, discovery::HW_ID_VCN, 1))
        .ok_or(FsError::InvalidData)?;
    crate::amdgpu_video_caps_navi22::caps_for(kind, harvested, (vcn.major, vcn.minor, vcn.revision))
        .map(|caps| as_bytes(&caps))
        .ok_or(FsError::InvalidData)
}

/// `AMDGPU_INFO_MAX_IBS`: `u32[AMDGPU_HW_IP_NUM]`, the IBs one CS may carry
/// per ring type; the native queues take `amdgpu_navi22_submit::MAX_IBS`.
fn max_ibs(published: &Published, submission: Submission) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * uapi::AMDGPU_HW_IP_NUM as usize);
    for ip in 0..uapi::AMDGPU_HW_IP_NUM {
        let n = if available_rings(published, submission, ip) != 0 {
            crate::amdgpu_navi22_submit::MAX_IBS as u32
        } else {
            0
        };
        out.extend_from_slice(&n.to_le_bytes());
    }
    out
}

/// The Navi 22 reply, or `None` for a query the generic path answers.
pub(crate) fn query(
    snap: &Snapshot,
    which: u32,
    payload: [u32; 4],
) -> Option<Result<Vec<u8>, FsError>> {
    query_with(snap, submission(), which, payload)
}

/// [`query`] with an explicit switch position, for tests of both sides.
pub fn query_with(
    snap: &Snapshot,
    submission: Submission,
    which: u32,
    payload: [u32; 4],
) -> Option<Result<Vec<u8>, FsError>> {
    Some(match which {
        uapi::AMDGPU_INFO_ACCEL_WORKING => Ok(u32::from(accepting(&snap.navi22, submission))
            .to_le_bytes()
            .to_vec()),
        uapi::AMDGPU_INFO_DEV_INFO => dev_info(snap, submission),
        uapi::AMDGPU_INFO_HW_IP_INFO => hw_ip_info(snap, submission, payload[0], payload[1]),
        uapi::AMDGPU_INFO_HW_IP_COUNT => hw_ip_count(snap, submission, payload[0]),
        uapi::AMDGPU_INFO_FW_VERSION => fw_version(snap, payload),
        uapi::AMDGPU_INFO_READ_MMR_REG => read_mmr_reg(snap, payload),
        uapi::AMDGPU_INFO_MEMORY => Ok(memory(snap)),
        uapi::AMDGPU_INFO_VIDEO_CAPS => video_caps(snap, payload[0]),
        uapi::AMDGPU_INFO_MAX_IBS => Ok(max_ibs(&snap.navi22, submission)),
        uapi::AMDGPU_INFO_VRAM_GTT => Ok(vram_gtt(snap)),
        _ => return None,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_info_navi22_tests.rs"]
mod tests;

//! Read GC 11.0.1 harvesting and address configuration under exclusive GRBM
//! index ownership, for `AMDGPU_INFO`.
//!
//! Sources: Linux `gfx_v11_0_gpu_early_init` (GB_ADDR_CONFIG),
//! `gfx_v11_0_setup_rb` / `gfx_v11_0_get_rb_active_bitmap`,
//! `gfx_v11_0_get_cu_info` / `gfx_v11_0_get_wgp_active_bitmap_per_sh`,
//! `gfx_v11_0_get_tcc_info` and `nbio_v7_2_get_rev_id`. Offsets are the ones
//! `gfx_v11_0.c` uses: `gc_11_0_0_offset.h` / `gc_11_0_0_sh_mask.h`.
//!
//! Differences from GFX10 (`amdgpu_gfx10_topology`), all verified against
//! those headers:
//! - The GC_USER_* registers moved to BASE_IDX 1: `GC_USER_SHADER_ARRAY_CONFIG`
//!   0x5b90, `GC_USER_SA_UNIT_DISABLE` 0x5b92, `GC_USER_RB_BACKEND_DISABLE`
//!   0x5b94, `CGTS_USER_TCC_DISABLE` 0x5b96 (GFX10 has them at 0x1010 /
//!   0x0fea / 0x147f / 0x5007 on BASE_IDX 0/1). The CC_* registers keep
//!   their GFX10 addresses on BASE_IDX 0.
//! - CU activity is WGP-based: `INACTIVE_WGPS` (bits[31:16] of the shader
//!   array config) disables two CUs per bit, not one per bit.
//! - GC11 supports up to 8 SEs; the DRM `cu_bitmap[4][4]` folds SEs 4–7
//!   into columns 2–3 (`bitmap[se % 4][sh + (se / 4) * 2]`), as
//!   `gfx_v11_0_get_cu_info` does.
//! - The SA-disable mask is 16 bits (8 SEs x 2 SH), and Linux always
//!   applies it — there is no GFX10-style whole-SA skip list.
//! - The RB disable field is `BACKEND_DISABLE` at bits[31:4] (GFX10 reads
//!   bits[23:16]); Linux reads it once as a global mask in `setup_rb`, so
//!   the derive uses the SE0/SH0 sample.
//!
//! The NBIO strap register is the 7.x default `RCC_DEV0_EPF0_STRAP0`
//! (0x0011, `amdgpu_nbio_v7_2::strap0`'s default arm); Phoenix's NBIO
//! version is discovery-driven and unpinned, so the bank resolve is
//! version-ungated like the GMC owner's — a future NBIO audit can tighten
//! both the version and the strap here.
//!
//! Strix Point's NBIO is 7.11, whose strap register is
//! `RCC_STRAP1_RCC_DEV0_EPF0_STRAP0` — 0x0015 on 7.11.0–7.11.3
//! (`nbio_7_11_0_offset.h`, `nbio_v7_11_get_rev_id`) and 0x0021 on
//! 7.11.4–7.11.5 (`nbio_7_11_5_offset.h`, `nbio_v7_11_5_get_rev_id`) —
//! not the 7.x default 0x0011. `read_strix` resolves the dword from the
//! discovered NBIO version and fails closed on any other version; the
//! `strap0` sample and the revision sample both use it. The `(strap >>
//! 24) & 0xf` extraction is the same on both: `REV_ID` is mask
//! 0x0F000000, shift 0x18, in both headers.
//!
//! The derivation is a pure function of the raw samples ([`derive`]) so the
//! values Mesa sees are tested against hand-derived Linux results without a
//! register model in the loop.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_cp_navi22::regs::{Reg, GRBM_GFX_INDEX},
    amdgpu_discovery as ip,
    amdgpu_discovery::GcInfo,
    amdgpu_psp_ring::bank,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
}

/// `mmGB_ADDR_CONFIG` (BASE_IDX 0).
pub const GB_ADDR_CONFIG: Reg = Reg(0, 0x13de);
const CC_RB_BACKEND_DISABLE: Reg = Reg(0, 0x13dd);
const GC_USER_RB_BACKEND_DISABLE: Reg = Reg(1, 0x5b94);
const CC_GC_SHADER_ARRAY_CONFIG: Reg = Reg(0, 0x100f);
const GC_USER_SHADER_ARRAY_CONFIG: Reg = Reg(1, 0x5b90);
/// `mmCGTS_TCC_DISABLE` / `mmCGTS_USER_TCC_DISABLE` (BASE_IDX 1).
const CGTS_TCC_DISABLE: Reg = Reg(1, 0x5006);
const CGTS_USER_TCC_DISABLE: Reg = Reg(1, 0x5b96);
const CC_GC_SA_UNIT_DISABLE: Reg = Reg(0, 0x0fe9);
const GC_USER_SA_UNIT_DISABLE: Reg = Reg(1, 0x5b92);
/// `mmRCC_DEV0_EPF0_STRAP0` (NBIO BASE_IDX 2).
const RCC_DEV0_EPF0_STRAP0: u32 = 0x0011;
/// `mmRCC_STRAP1_RCC_DEV0_EPF0_STRAP0` (NBIO BASE_IDX 2) on NBIO
/// 7.11.0–7.11.3 (`nbio_7_11_0_offset.h`, `nbio_v7_11_get_rev_id`).
const RCC_STRAP1_711: u32 = 0x0015;
/// The same register on NBIO 7.11.4–7.11.5 (`nbio_7_11_5_offset.h`,
/// `nbio_v7_11_5_get_rev_id`).
const RCC_STRAP1_711_5: u32 = 0x0021;
/// SE/SA/instance broadcast, the selector every GRBM user leaves behind.
const BROADCAST: u32 = 0xe000_0000;
/// `AMDGPU_GFX_MAX_SE` x `AMDGPU_GFX_MAX_SH_PER_SE` for GFX11
/// (`disable_masks[8 * 2]` in `gfx_v11_0_get_cu_info`).
const MAX_SE: u32 = 8;
const MAX_SH: u32 = 2;

/// Linux's `adev->gfx.config` / `cu_info` values that `AMDGPU_INFO` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topology {
    /// `adev->rev_id`, `STRAP_ATI_REV_ID`. `external_rev` is this + 0x32.
    pub rev_id: u32,
    /// `adev->gfx.config.gb_addr_config`, answered for READ_MMR_REG 0x263e.
    pub gb_addr_config: u32,
    /// `cu_info.number`.
    pub active_cus: u32,
    /// `cu_info.bitmap[0][se][sh]`, the DRM `cu_bitmap` layout (SEs 4–7
    /// folded into columns 2–3).
    pub cu_bitmap: [[u32; 4]; 4],
    /// `cu_info.ao_cu_bitmap[se][sh]`.
    pub ao_cu_bitmap: [[u32; 4]; 4],
    /// `cu_info.ao_cu_mask`.
    pub ao_cu_mask: u32,
    /// `gfx.config.backend_enable_mask`.
    pub enabled_rb_mask: u32,
    /// `gfx.config.tcc_disabled_mask`.
    pub tcc_disabled_mask: u64,
}

/// The raw registers, OR-combined exactly where Linux ORs them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub disabled_sa: u16,
    pub strap0: u32,
    pub gb_addr_config: u32,
    /// `CC_RB_BACKEND_DISABLE | GC_USER_RB_BACKEND_DISABLE` per [se][sh].
    /// Linux reads this once as a global mask; the SE0/SH0 entry is the one
    /// the derive uses.
    pub rb_disable: [[u32; MAX_SH as usize]; MAX_SE as usize],
    /// `CC_GC_SHADER_ARRAY_CONFIG | GC_USER_SHADER_ARRAY_CONFIG` per [se][sh].
    pub wgp_disable: [[u32; MAX_SH as usize]; MAX_SE as usize],
    /// `CGTS_TCC_DISABLE | CGTS_USER_TCC_DISABLE`.
    pub tcc_disable: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    engines: u32,
    arrays: u32,
    cus: u32,
    backends: u32,
}
impl Limits {
    /// The GC table maxima, bounded to what GFX11's DRM layout can carry.
    pub fn from_gc(gc: &GcInfo) -> Result<Self, Error> {
        if !(1..=MAX_SE).contains(&gc.num_se)
            || !(1..=MAX_SH).contains(&gc.num_sa_per_se)
            || !(2..=32).contains(&gc.num_cu_per_sa)
            || gc.num_cu_per_sa % 2 != 0
            || gc.num_rb_per_se == 0
            || gc.num_rb_per_se % gc.num_sa_per_se != 0
            || gc.num_rb_per_se * gc.num_se > 32
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            engines: gc.num_se,
            arrays: gc.num_sa_per_se,
            cus: gc.num_cu_per_sa,
            backends: gc.num_rb_per_se,
        })
    }
}

/// `amdgpu_gfx_create_bitmask`.
fn bitmask(width: u32) -> u32 {
    ((1u64 << width) - 1) as u32
}

/// Linux's derivation of every reported value from the raw registers.
pub fn derive(limits: Limits, sample: &Sample) -> Result<Topology, Error> {
    // Mesa asserts a 256-byte pipe interleave (PIPE_INTERLEAVE_SIZE == 0) and
    // a posted GC never reads zero here; either means the GC was not reached.
    if sample.gb_addr_config == 0 || sample.gb_addr_config & 0x38 != 0 {
        return Err(Error::Invalid);
    }
    let rb_width = limits.backends / limits.arrays;
    let mut topology = Topology {
        rev_id: (sample.strap0 & 0x0f00_0000) >> 24,
        gb_addr_config: sample.gb_addr_config,
        active_cus: 0,
        cu_bitmap: [[0; 4]; 4],
        ao_cu_bitmap: [[0; 4]; 4],
        ao_cu_mask: 0,
        enabled_rb_mask: 0,
        // REG_GET_FIELD(TCC_DISABLE) | REG_GET_FIELD(HI_TCC_DISABLE) << 16
        tcc_disabled_mask: u64::from(
            (sample.tcc_disable >> 16) | (((sample.tcc_disable >> 8) & 0xff) << 16),
        ),
    };
    // `gfx_v11_0_setup_rb`: the per-SA active RB bitmap, ANDed with the
    // global active RB bitmap from the BACKEND_DISABLE field.
    let global_rb_disable = (sample.rb_disable[0][0] & 0xffff_fff0) >> 4;
    let global_active_rb = bitmask(limits.backends * limits.engines) & !global_rb_disable;
    let mut active_rb = 0;
    for se in 0..limits.engines {
        for sh in 0..limits.arrays {
            let (i, j) = (se as usize, sh as usize);
            if sample.disabled_sa & (1 << (se * limits.arrays + sh)) != 0 {
                continue;
            }
            active_rb |= bitmask(rb_width) << ((se * limits.arrays + sh) * rb_width);
            // gfx_v11_0_get_wgp_active_bitmap_per_sh: no amdgpu_disable_cu
            // mask is applied, so GC_USER_SHADER_ARRAY_CONFIG is not written.
            let disabled = !bitmask(limits.cus >> 1) | (sample.wgp_disable[i][j] >> 16);
            let wgps = !disabled;
            let mut bitmap = 0;
            for wgp in 0..16 {
                if wgps & (1 << wgp) != 0 {
                    bitmap |= 3 << (2 * wgp);
                }
            }
            // GFX11 folds SEs 4–7 into bitmap columns 2–3.
            let (bi, bj) = ((se % 4) as usize, (sh + (se / 4) * 2) as usize);
            topology.cu_bitmap[bi][bj] = bitmap;
            // Every active CU below max_cu_per_sh is always-on on GFX11.
            let mut ao = 0;
            let mut counter = 0;
            for k in 0..limits.cus {
                if bitmap & (1 << k) != 0 {
                    if counter < limits.cus {
                        ao |= 1 << k;
                    }
                    counter += 1;
                }
            }
            topology.active_cus += counter;
            if se < 2 && sh < 2 {
                // u32 shift as in C: SE1/SH1 (bit 24) loses its top bits.
                topology.ao_cu_mask |= ao << (se * 16 + sh * 8);
            }
            topology.ao_cu_bitmap[bi][bj] = ao;
        }
    }
    topology.enabled_rb_mask = active_rb & global_active_rb;
    if topology.active_cus == 0 || topology.enabled_rb_mask == 0 {
        return Err(Error::Invalid);
    }
    Ok(topology)
}

trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
}
struct Mmio(narf_bus::MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout::resolve bounded every GC/NBIO bank to BAR5 and the
        // caller invokes this under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: sole GRBM owner; only GRBM_GFX_INDEX is written.
        unsafe { self.0.write32(address, value) };
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
/// GC BASE_IDX 0/1 and NBIO BASE_IDX 2 bank byte offsets in BAR5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    gc: [u64; 2],
    nbio: u64,
}
impl Layout {
    fn resolve_phoenix(gpu: &AmdGpu) -> Result<Self, Error> {
        if !matches!(
            (gpu.chip.vid, gpu.chip.did),
            (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX_HAWKPOINT1)
                | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX1)
                | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX2)
        ) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            gc: [
                bank(gpu, ip::HW_ID_GC, &[(11, 0, 1)], 0, 0x13de)
                    .map_err(|_| Error::Unsupported)?,
                bank(gpu, ip::HW_ID_GC, &[(11, 0, 1)], 1, 0x5b96)
                    .map_err(|_| Error::Unsupported)?,
            ],
            nbio: nbio_bank(gpu, RCC_DEV0_EPF0_STRAP0)?,
        })
    }
    fn resolve_strix(gpu: &AmdGpu) -> Result<Self, Error> {
        if !matches!(
            (gpu.chip.vid, gpu.chip.did),
            (crate::amdgpu::AMD_VENDOR, crate::amdgpu::STRIX_POINT)
        ) {
            return Err(Error::Unsupported);
        }
        // Every topology register is identical between GC 11.0.0 and
        // 11.5.0 (`gc_11_5_0_offset.h`), so the bank bounds are the
        // Phoenix ones; only the strap dword differs (see `strap_dword`).
        Ok(Self {
            gc: [
                bank(gpu, ip::HW_ID_GC, &[(11, 5, 0)], 0, 0x13de)
                    .map_err(|_| Error::Unsupported)?,
                bank(gpu, ip::HW_ID_GC, &[(11, 5, 0)], 1, 0x5b96)
                    .map_err(|_| Error::Unsupported)?,
            ],
            nbio: nbio_bank(gpu, RCC_STRAP1_711_5)?,
        })
    }
    fn reg(self, reg: Reg) -> u64 {
        self.gc[reg.0 as usize] + u64::from(reg.1) * 4
    }
    fn nbio(self, dword: u32) -> u64 {
        self.nbio + u64::from(dword) * 4
    }
}
/// The NBIO strap dword for Strix Point, from the discovered NBIO
/// version: 7.11.0–7.11.3 read `RCC_STRAP1` at 0x0015, 7.11.4–7.11.5 at
/// 0x0021 (`amdgpu_discovery.c` gives the two ranges `nbio_v7_11_funcs`
/// and `nbio_v7_11_5_funcs`). Any other NBIO version fails closed.
fn strap_dword(gpu: &AmdGpu) -> Result<u32, Error> {
    let nbif = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
    match (nbif.major, nbif.minor, nbif.revision) {
        (7, 11, 0..=3) => Ok(RCC_STRAP1_711),
        (7, 11, 4..=5) => Ok(RCC_STRAP1_711_5),
        _ => Err(Error::Unsupported),
    }
}
/// Resolve the NBIF bank without gating on an NBIO version (see the GMC
/// owner): BASE_IDX 2, bounded by the BAR. `last` is the highest strap
/// dword the caller reads (0x0011 Phoenix, 0x0021 Strix).
fn nbio_bank(gpu: &AmdGpu, last: u32) -> Result<u64, Error> {
    let ip = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
    if ip.num_bases < 3 {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[2] as u64 * 4;
    if base
        .checked_add((u64::from(last) + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    Ok(base)
}
fn sample_revision(io: &mut impl Io, layout: &Layout, strap: u32) -> Result<u8, Error> {
    Ok(((checked(io.read(layout.nbio(strap)))? >> 24) & 0xf) as u8)
}
fn sample(io: &mut impl Io, layout: &Layout, limits: Limits, strap: u32) -> Result<Sample, Error> {
    let index = layout.reg(GRBM_GFX_INDEX);
    let mut raw = Sample {
        strap0: checked(io.read(layout.nbio(strap)))?,
        gb_addr_config: checked(io.read(layout.reg(GB_ADDR_CONFIG)))?,
        ..Sample::default()
    };
    // `gfx_v11_0_get_sa_active_bitmap`: always applied on GC11, from the
    // SA_DISABLE fields (bits[23:8]) of both registers.
    raw.disabled_sa = (((checked(io.read(layout.reg(CC_GC_SA_UNIT_DISABLE)))?
        | checked(io.read(layout.reg(GC_USER_SA_UNIT_DISABLE)))?)
        >> 8)
        & 0xffff) as u16;
    let result = (|| {
        for se in 0..limits.engines {
            for sh in 0..limits.arrays {
                if raw.disabled_sa & (1 << (se * limits.arrays + sh)) != 0 {
                    continue;
                }
                // gfx_v11_0_select_se_sh(se, sh, 0xffffffff)
                let selector = (1 << 30) | (se << 16) | (sh << 8);
                io.write(index, selector);
                // Like gfx_v10_0_select_se_sh, do not require the selector
                // to echo writes. The physical RX 6750 XT returns zero here
                // under Linux's locked amdgpu_regs2 interface, including
                // after SE/SA/instance broadcast. Validate the harvest data.
                let (i, j) = (se as usize, sh as usize);
                raw.rb_disable[i][j] = checked(io.read(layout.reg(CC_RB_BACKEND_DISABLE)))?
                    | checked(io.read(layout.reg(GC_USER_RB_BACKEND_DISABLE)))?;
                raw.wgp_disable[i][j] = checked(io.read(layout.reg(CC_GC_SHADER_ARRAY_CONFIG)))?
                    | checked(io.read(layout.reg(GC_USER_SHADER_ARRAY_CONFIG)))?;
            }
        }
        Ok(())
    })();
    // Restore broadcast even after a failed read, inside the same capability
    // operation that owns the selector.
    io.write(index, BROADCAST);
    result?;
    // TCCs are global, not instanced.
    raw.tcc_disable = checked(io.read(layout.reg(CGTS_TCC_DISABLE)))?
        | checked(io.read(layout.reg(CGTS_USER_TCC_DISABLE)))?;
    Ok(raw)
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
/// Read the NBIO chip revision independently of GC power and harvesting,
/// as `soc21.c`'s early init does before `gfx_v11_0_constants_init`.
///
/// # Safety
/// The caller exclusively owns the permanent BAR mapping and PCI device.
/// The strap is read-only and needs no GRBM selection or powered GC.
pub unsafe fn read_revision_phoenix(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<u8, Error> {
    let layout = Layout::resolve_phoenix(gpu).map_err(|_| Error::Unsupported)?;
    authority
        .invoke(Op(|| {
            sample_revision(&mut Mmio(gpu.regs), &layout, RCC_DEV0_EPF0_STRAP0)
        }))
        .map_err(|_| Error::Revoked)?
}
/// Sample and derive Phoenix's topology.
///
/// # Safety
/// Physical Phoenix with RLC booted and GFX powered (GFXOFF and clock
/// gating off). The caller owns GRBM indexing, GC and the permanent
/// register mapping exclusively, with no concurrent queue setup, reset or
/// power transition. Reads fused and inherited user-disable masks; never
/// changes them.
pub unsafe fn read_phoenix(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<Topology, Error> {
    let limits = Limits::from_gc(gpu.gc_info.as_ref().ok_or(Error::Invalid)?)?;
    let layout = Layout::resolve_phoenix(gpu).map_err(|_| Error::Unsupported)?;
    let raw = authority
        .invoke(Op(|| {
            sample(&mut Mmio(gpu.regs), &layout, limits, RCC_DEV0_EPF0_STRAP0)
        }))
        .map_err(|_| Error::Revoked)??;
    derive(limits, &raw)
}
/// Read the NBIO chip revision independently of GC power and harvesting,
/// as `soc21.c`'s early init does before `gfx_v11_0_constants_init`.
///
/// # Safety
/// The caller exclusively owns the permanent BAR mapping and PCI device.
/// The strap is read-only and needs no GRBM selection or powered GC.
pub unsafe fn read_revision_strix(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<u8, Error> {
    let layout = Layout::resolve_strix(gpu).map_err(|_| Error::Unsupported)?;
    let strap = strap_dword(gpu)?;
    authority
        .invoke(Op(|| sample_revision(&mut Mmio(gpu.regs), &layout, strap)))
        .map_err(|_| Error::Revoked)?
}
/// Sample and derive Strix Point's topology: the Phoenix reader with GC
/// 11.5.0 banks and the NBIO 7.11 strap dword. Every sampled register is
/// identical between GC 11.0.0 and 11.5.0, and `gfx_v11_0.c` has no
/// 11.5-specific arms in `get_cu_info` / `setup_rb` / `kiq_setting` or
/// the ring setup — so the same sample/derive runs.
///
/// # Safety
/// Physical Strix Point with RLC booted and GFX powered (GFXOFF and clock
/// gating off). The caller owns GRBM indexing, GC and the permanent
/// register mapping exclusively, with no concurrent queue setup, reset or
/// power transition. Reads fused and inherited user-disable masks; never
/// changes them.
pub unsafe fn read_strix(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<Topology, Error> {
    let limits = Limits::from_gc(gpu.gc_info.as_ref().ok_or(Error::Invalid)?)?;
    let layout = Layout::resolve_strix(gpu).map_err(|_| Error::Unsupported)?;
    let strap = strap_dword(gpu)?;
    let raw = authority
        .invoke(Op(|| sample(&mut Mmio(gpu.regs), &layout, limits, strap)))
        .map_err(|_| Error::Revoked)??;
    derive(limits, &raw)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx11_topology_tests.rs"]
mod tests;

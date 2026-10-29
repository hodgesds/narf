//! Read GC 10.3.2 harvesting and address configuration under exclusive GRBM
//! index ownership, for `AMDGPU_INFO`.
//!
//! Sources: Linux `gfx_v10_0_gpu_early_init` (GB_ADDR_CONFIG),
//! `gfx_v10_0_setup_rb` / `gfx_v10_0_get_rb_active_bitmap`,
//! `gfx_v10_0_get_cu_info` / `gfx_v10_0_get_wgp_active_bitmap_per_sh`,
//! `gfx_v10_0_get_tcc_info` and `nbio_v2_3_get_rev_id`. Offsets are the ones
//! `gfx_v10_0.c` uses: `gc_10_1_0_offset.h` plus its local
//! `mmCGTS_(USER_)TCC_DISABLE_gc_10_3`; NBIO is `nbio_2_3_offset.h`.
//!
//! The discovery GC table gives the maxima (`max_shader_engines`,
//! `max_sh_per_se`, `max_cu_per_sh`, `max_backends_per_se`); the fuse and
//! user-disable registers sampled here say which of those are present on this
//! board. Every value is read, never assumed: one PCI ID ships in several
//! harvest configurations. GC 10.3.2 is not one of the versions whose
//! `gfx_v10_3_get_disabled_sa` whole-SA skip applies (10.3.0/3/6/7), so every
//! SA is sampled, as Linux does.
//!
//! The derivation is a pure function of the raw samples ([`derive`]) so the
//! values Mesa sees are tested against hand-derived Linux results without a
//! register model in the loop.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_cp_navi22::regs::{Reg, GRBM_GFX_INDEX},
    amdgpu_cp_navi22::Layout,
    amdgpu_discovery::GcInfo,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    Readback,
}

/// `mmGB_ADDR_CONFIG` (BASE_IDX 0).
pub const GB_ADDR_CONFIG: Reg = Reg(0, 0x13de);
const CC_RB_BACKEND_DISABLE: Reg = Reg(0, 0x13dd);
const GC_USER_RB_BACKEND_DISABLE: Reg = Reg(0, 0x147f);
const CC_GC_SHADER_ARRAY_CONFIG: Reg = Reg(0, 0x100f);
const GC_USER_SHADER_ARRAY_CONFIG: Reg = Reg(0, 0x1010);
/// `mmCGTS_TCC_DISABLE_gc_10_3` / `mmCGTS_USER_TCC_DISABLE_gc_10_3` (BASE_IDX 1).
const CGTS_TCC_DISABLE: Reg = Reg(1, 0x5006);
const CGTS_USER_TCC_DISABLE: Reg = Reg(1, 0x5007);
/// `mmRCC_DEV0_EPF0_STRAP0` (NBIO BASE_IDX 2).
const CC_GC_SA_UNIT_DISABLE: Reg = Reg(0, 0x0fe9);
const GC_USER_SA_UNIT_DISABLE: Reg = Reg(0, 0x0fea);
const RCC_DEV0_EPF0_STRAP0: u32 = 0x0011;
/// SE/SA/instance broadcast, the selector every GRBM user leaves behind.
const BROADCAST: u32 = 0xe000_0000;
/// GRBM_GFX_INDEX has five reserved bits between the SE selector and the
/// broadcast flags. Their read values are not part of the selected instance.
// linux: GRBM_GFX_INDEX__INSTANCE_INDEX_MASK | GRBM_GFX_INDEX__SA_INDEX_MASK | GRBM_GFX_INDEX__SE_INDEX_MASK | GRBM_GFX_INDEX__SA_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__INSTANCE_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__SE_BROADCAST_WRITES_MASK
const INDEX_FIELDS: u32 = 0xe0ff_ffff;
/// `AMDGPU_GFX_MAX_SE` x `AMDGPU_GFX_MAX_SH_PER_SE` for GFX10
/// (`disable_masks[4 * 2]` in `gfx_v10_0_get_cu_info`).
const MAX_SE: u32 = 4;
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
    /// `cu_info.bitmap[0][se][sh]`, the DRM `cu_bitmap` layout.
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
    pub disabled_sa: u8,
    pub strap0: u32,
    pub gb_addr_config: u32,
    /// `CC_RB_BACKEND_DISABLE | GC_USER_RB_BACKEND_DISABLE` per [se][sh].
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
    /// The GC table maxima, bounded to what GFX10's DRM layout can carry.
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
    for se in 0..limits.engines {
        for sh in 0..limits.arrays {
            let (i, j) = (se as usize, sh as usize);
            if sample.disabled_sa & (1 << (se * limits.arrays + sh)) != 0 {
                continue;
            }
            // gfx_v10_0_get_rb_active_bitmap
            let rbs = !((sample.rb_disable[i][j] & 0x00ff_0000) >> 16) & bitmask(rb_width);
            topology.enabled_rb_mask |= rbs << ((se * limits.arrays + sh) * rb_width);
            // gfx_v10_0_get_wgp_active_bitmap_per_sh: no amdgpu_disable_cu
            // mask is applied, so GC_USER_SHADER_ARRAY_CONFIG is not written.
            let disabled = !bitmask(limits.cus >> 1) | (sample.wgp_disable[i][j] >> 16);
            let wgps = !disabled;
            let mut bitmap = 0;
            for wgp in 0..16 {
                if wgps & (1 << wgp) != 0 {
                    bitmap |= 3 << (2 * wgp);
                }
            }
            topology.cu_bitmap[i][j] = bitmap;
            // Every active CU below max_cu_per_sh is always-on on GFX10.
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
            topology.ao_cu_bitmap[i][j] = ao;
        }
    }
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
fn sample(io: &mut impl Io, layout: &Layout, limits: Limits) -> Result<Sample, Error> {
    let index = layout.reg(GRBM_GFX_INDEX);
    let mut raw = Sample {
        strap0: checked(io.read(layout.nbio(RCC_DEV0_EPF0_STRAP0)))?,
        gb_addr_config: checked(io.read(layout.reg(GB_ADDR_CONFIG)))?,
        ..Sample::default()
    };
    if layout.profile.gc_version == (10, 3, 0) {
        raw.disabled_sa = (((checked(io.read(layout.reg(CC_GC_SA_UNIT_DISABLE)))?
            | checked(io.read(layout.reg(GC_USER_SA_UNIT_DISABLE)))?)
            >> 8)
            & 0xff) as u8;
    }
    let result = (|| {
        for se in 0..limits.engines {
            for sh in 0..limits.arrays {
                if raw.disabled_sa & (1 << (se * limits.arrays + sh)) != 0 {
                    continue;
                }
                // gfx_v10_0_select_se_sh(se, sh, 0xffffffff)
                let selector = (1 << 30) | (se << 16) | (sh << 8);
                io.write(index, selector);
                if checked(io.read(index))? & INDEX_FIELDS != selector {
                    return Err(Error::Readback);
                }
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
    if checked(io.read(index))? & INDEX_FIELDS != BROADCAST {
        return Err(Error::Readback);
    }
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
/// Sample and derive this board's topology.
///
/// # Safety
/// Physical Navi22 with RLC booted and GFX powered (GFXOFF and clock gating
/// off). The caller owns GRBM indexing, GC and the permanent register mapping
/// exclusively, with no concurrent queue setup, reset or power transition.
/// Reads fused and inherited user-disable masks; never changes them.
pub unsafe fn read(gpu: &AmdGpu, authority: &Cap<BusDeviceCap, Write>) -> Result<Topology, Error> {
    let limits = Limits::from_gc(gpu.gc_info.as_ref().ok_or(Error::Invalid)?)?;
    let layout = Layout::resolve_rdna2(gpu).map_err(|_| Error::Unsupported)?;
    let raw = authority
        .invoke(Op(|| sample(&mut Mmio(gpu.regs), &layout, limits)))
        .map_err(|_| Error::Revoked)??;
    derive(limits, &raw)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx10_topology_tests.rs"]
pub(crate) mod tests;

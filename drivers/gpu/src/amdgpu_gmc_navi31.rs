//! GFX11 (Navi31/32/33 + Phoenix) GMC v11 owner: VMID0 bring-up for an
//! owned VRAM test aperture, client VMID setup, TLB flush, and PASID
//! mapping.
//!
//! Linux `gmc_v11_0.c` / `gfxhub_v3_0.c` (+ `gfxhub_v3_0_3.c` for Navi32)
//! / `mmhub_v3_0.c` (+ `mmhub_v3_0_1.c` for Phoenix). No clock gating,
//! KIQ/MES invalidation, retry-fault recovery, GART bind/unbind, or
//! implicit reset — the GART table and the GPUVM stack are the follow-up;
//! this owner brings up VMID0, arms the client VMIDs, and owns the
//! TLB/PASID surface the submitter will use.
//!
//! ## Per-die parameters (corrected pairing, lane 1)
//!
//! | die     | GC version | GFXHUB table | MMHUB |
//! |---------|------------|--------------|-------|
//! | Navi31  | 11.0.0     | `gfxhub_v3_0` (`GFXHUB_V3_0`) | 3.0.0 |
//! | Navi32  | 11.0.3     | `gfxhub_v3_0_3` (`GFXHUB_V3_0_3`) | 3.0.0 |
//! | Navi33  | 11.0.2     | `gfxhub_v3_0` (`GFXHUB_V3_0`) | 3.0.0 |
//! | Phoenix | 11.0.1     | `gfxhub_v3_0` (`GFXHUB_V3_0`) | 3.0.1, BASE_IDX 1 |
//!
//! Navi33 shares the 11.0.0 function table because
//! `gmc_v11_0_set_gfxhub_funcs` selects the default `gfxhub_v3_0_funcs`
//! for every GC version except 11.0.3 and the 11.5/11.7 APUs. Navi32's
//! GFXHUB registers sit 0x10 higher (`gc_11_0_3_offset.h`), which is why
//! it has its own table. MMHUB 3.0.0 for all three discrete dies is the
//! `amdgpu_platform::MMHUB_WINDOWS` attribution ("Navi3x"); the
//! discovery blob is the only source that could contradict it, and the
//! owner fails closed (`Unsupported`) if a die reports another version.
//! Phoenix's MMHUB is 3.0.1 on BASE_IDX 1: Linux's `mmhub_v3_0_1.c`
//! differs from `mmhub_v3_0.c` only in its client-ID table — the
//! programming backend and register offsets are the same, so Phoenix
//! reuses the `MM` table and the `MMHUB_V3_0` VM-hub table.
//!
//! ## VMID split (`gmc_v11_0_sw_init`)
//!
//! VMID 0 is the system context. Graphics/compute use VMIDs 1–7;
//! KFD uses VMIDs 8–15 (`first_kfd_vmid = 8`). The hardware programming
//! is identical for all fifteen (`setup_vmid_config` loops contexts
//! 1..15 the same way); the split is a reservation policy, recorded
//! here so the submitter cannot hand a KFD VMID to a graphics client.
//!
//! ## NBIO / HDP flush
//!
//! The NBIO bank is resolved without gating on an NBIO version: no
//! Linux source maps a Navi3x die to an NBIO version (versions come from
//! the firmware discovery blob), so the owner takes discovery's NBIF
//! block at BASE_IDX 2 and validates it with the remap magic — the
//! `REMAP_HDP_MEM_FLUSH_CNTL` dword is 0x12d on every NBIO generation
//! NARF has (`nbio_2_3`, `nbio_6_3_2`, `nbio_7_2_0`, `nbio_7_7_0`
//! offset headers), and the initialize path refuses to proceed unless
//! the dword reads back the remap hole `0x7f000`, exactly as the Navi22
//! and Navi48 owners do.

use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vm::Geometry as VmGeometry,
    amdgpu_vmhub_regs::{self as hub, VmHubRegs, GFXHUB_V3_0, GFXHUB_V3_0_3, MMHUB_V3_0},
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_gmc_navi31_regs.rs"]
mod regs;
use regs::{HubRegs, GFX, GFX_11_0_3, MM};

/// `gmc_v11_0_mc_init`: `amdgpu_gmc_set_gart_size(adev, SZ_512M)`.
pub const GART_SIZE: u64 = 512 << 20;
/// GART table pages at 4 KiB: the table itself is 1 MiB.
pub const GART_TABLE_PAGES: u64 = GART_SIZE / 4096;
/// PT, default page, source page, destination page, then the empty root
/// directory every idle client context points at.
const BYTES: u64 = 20480;
const EMPTY_ROOT: u64 = 16384;
const APERTURE_SIZE: u64 = 2 << 20; // 512 flat PTEs; only two are present
const LIMIT: u64 = 1 << 48;

/// The GFX11 die discovery describes, by GC version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gfx11Die {
    Navi31,
    Navi32,
    Navi33,
    Phoenix,
}

impl Gfx11Die {
    /// All GC versions Linux's `gmc_v11_0` drives: the discrete RDNA3
    /// dies plus Phoenix 11.0.1, whose GMC programming reuses the same
    /// GFXHUB tables and aperture registers (only the MMHUB version and
    /// window differ — see `Layout::resolve`).
    pub const GC_VERSIONS: &[(u8, u8, u8)] = &[(11, 0, 0), (11, 0, 2), (11, 0, 3), (11, 0, 1)];

    pub const fn from_gc(version: (u8, u8, u8)) -> Option<Self> {
        match version {
            (11, 0, 0) => Some(Self::Navi31),
            (11, 0, 3) => Some(Self::Navi32),
            (11, 0, 2) => Some(Self::Navi33),
            (11, 0, 1) => Some(Self::Phoenix),
            _ => None,
        }
    }

    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Self::Navi31 => (11, 0, 0),
            Self::Navi32 => (11, 0, 3),
            Self::Navi33 => (11, 0, 2),
            Self::Phoenix => (11, 0, 1),
        }
    }

    /// The die discovery describes: exactly one GC instance 0, of a
    /// GFX11 GC version. Duplicate or absent GC fails closed.
    pub fn from_ip_blocks(blocks: &[ip::IpBlock]) -> Option<Self> {
        let mut gc = blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_GC && b.instance == 0);
        let first = gc.next()?;
        if gc.next().is_some() {
            return None;
        }
        Self::from_gc((first.major, first.minor, first.revision))
    }

    /// The GFX11 die this probed AMD GPU is, or `None` for every other
    /// part. A device id the PCI table assigns to another family is
    /// refused even with GFX11 discovery: the identity would be
    /// self-contradictory — a Navi3 DID reporting GC 11.0.1, or a
    /// Phoenix DID reporting a discrete GC version, is refused the same
    /// way. Phoenix is DID-gated on top of the family check: Strix
    /// shares `Family::Phoenix` but is RDNA3.5, not GC 11.0.1, and must
    /// not take this path.
    pub fn of(gpu: &AmdGpu) -> Option<Self> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR {
            return None;
        }
        let die = Self::from_ip_blocks(&gpu.ip_blocks)?;
        match crate::amdgpu::family_for_pci_id(gpu.chip.vid, gpu.chip.did)? {
            crate::amdgpu::Family::Navi3 => {
                if die == Self::Phoenix {
                    return None;
                }
                Some(die)
            }
            crate::amdgpu::Family::Phoenix => {
                if die != Self::Phoenix
                    || !matches!(
                        gpu.chip.did,
                        crate::amdgpu::PHOENIX_HAWKPOINT1
                            | crate::amdgpu::PHOENIX1
                            | crate::amdgpu::PHOENIX2
                    )
                {
                    return None;
                }
                Some(die)
            }
            _ => None,
        }
    }
}

/// `gmc_v11_0_sw_init`: VMID 0 is the system context, 1–7 are
/// graphics/compute, 8–15 are KFD (`first_kfd_vmid = 8` unless the
/// kernel queue is disabled, in which case it is 1 — this owner never
/// disables the KQ, so 8 is the split it enforces).
pub const FIRST_KFD_VMID: u8 = 8;
/// A VMID in the graphics/compute range 1..=`FIRST_KFD_VMID` - 1.
pub const fn is_gfx_vmid(vmid: u8) -> bool {
    vmid >= 1 && vmid < FIRST_KFD_VMID
}
/// A VMID in the KFD range `FIRST_KFD_VMID`..=15.
pub const fn is_kfd_vmid(vmid: u8) -> bool {
    vmid >= FIRST_KFD_VMID && vmid < 16
}
/// The client VMIDs, 1..=15 (VMID0 is the kernel's).
const CLIENT_VMIDS: u16 = 0xfffe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hub {
    Gfx,
    Mm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Invalidating(Hub),
    Ready,
    /// VMIDs 1..15 enabled on both hubs, each at the empty root until a
    /// submission's VM flush gives it a client's page tables.
    PreparingClients,
    ClientsReady,
    Failed,
}
impl State {
    /// VMID0's translations are live: initialized, with or without the
    /// client contexts.
    pub fn vmid0_ready(self) -> bool {
        matches!(self, State::Ready | State::ClientsReady)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aperture {
    pub start: u64,
    pub size: u64,
    pub source: u64,
    pub destination: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    die: Gfx11Die,
    bases: [u64; 2],
    /// The GC hub's and the MM hub's full programming tables, in
    /// `bases` order. Navi32's GFX table is `GFX_11_0_3`.
    hubs: [HubRegs; 2],
    /// The same hubs' context/invalidate tables for the shared
    /// `amdgpu_vmhub_regs` helpers (client VMID setup).
    vmhub: [VmHubRegs; 2],
    nbio: u64,
    /// OSSSYS 6.0.0 bank: the PASID LUTs (`IH_VMID_0_LUT` at +0,
    /// `IH_VMID_0_LUT_MM` at +0x10, `osssys_6_0_0_offset.h`).
    osssys: u64,
}
/// Resolve the NBIF bank without gating on an NBIO version (see the
/// module docs): BASE_IDX 2, dword 0x12d, bounded by the BAR.
fn nbio_bank(gpu: &AmdGpu) -> Result<u64, Error> {
    let ip = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
    if ip.num_bases < 3 {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[2] as u64 * 4;
    if base
        .checked_add((0x12d_u64 + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    Ok(base)
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        let die = Gfx11Die::of(gpu).ok_or(Error::Unsupported)?;
        let reg = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        // Highest dword the owner touches through each base: the GFX
        // hub's PT_END (0x1733 on 11.0.0/11.0.1/11.0.2, 0x1743 on 11.0.3),
        // the MM hub's L1 TLB control (0x08f3).
        let gfx_last = match die {
            Gfx11Die::Navi32 => 0x1743,
            _ => 0x1733,
        };
        let (gfx, gfx_vmhub) = match die {
            Gfx11Die::Navi32 => (GFX_11_0_3, GFXHUB_V3_0_3),
            _ => (GFX, GFXHUB_V3_0),
        };
        // Phoenix's MMHUB is 3.0.1 on BASE_IDX 1; the discrete dies are
        // 3.0.0 on BASE_IDX 0. Same offsets either way (see module docs).
        let mmhub = match die {
            Gfx11Die::Phoenix => reg(ip::HW_ID_MMHUB, &[(3, 0, 1)], 1, 0x08f3)?,
            _ => reg(ip::HW_ID_MMHUB, &[(3, 0, 0)], 0, 0x08f3)?,
        };
        Ok(Self {
            die,
            bases: [reg(ip::HW_ID_GC, &[die.gc_version()], 0, gfx_last)?, mmhub],
            hubs: [gfx, MM],
            vmhub: [gfx_vmhub, MMHUB_V3_0],
            nbio: nbio_bank(gpu)?,
            osssys: reg(ip::HW_ID_OSSSYS, &[(6, 0, 0)], 0, 0x1f)?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// One 64-bit BAR store (Linux `amdgpu_gmc_set_pte_pde` uses writeq), so
    /// the GPU never observes a torn PTE/PDE.
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds both complete hub banks and the HDP remap;
        // the exclusive owner calls this only inside live Cap::invoke.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded exclusive register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: initialize bounds every write to its owned BYTES allocation,
        // before publication and inside live authority.
        unsafe { map.write32(offset, value) };
    }
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64) {
        // SAFETY: callers bound each 8-byte entry inside an owned, published
        // or still-private page-table reservation, inside live authority.
        unsafe { map.write64(offset, value) };
    }
}
/// `Gmc::hdp_flusher`: `amdgpu_device_flush_hdp(adev, NULL)` for CPU
/// page-table updates (`amdgpu_vm_cpu_commit`), usable without the owner.
#[derive(Clone, Copy, Debug)]
pub struct HdpFlusher {
    regs: MmioRegion,
    nbio: u64,
    authority: Cap<BusDeviceCap, Write>,
}
impl crate::amdgpu_vm::HdpFlush for HdpFlusher {
    fn flush(&self) -> Result<(), narf_filesystem::FsError> {
        // The remapped flush write and NBIO read-back are idempotent and
        // safe beside the owner's own MMIO.
        let mut io = Mmio(self.regs);
        let nbio = self.nbio;
        self.authority
            .invoke(Op(|| flush(&mut io, nbio)))
            .map_err(|_| narf_filesystem::FsError::NoDevice)?
            .map_err(|_| narf_filesystem::FsError::NoDevice)
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Clone, Copy, Debug)]
struct Geometry {
    fb: u64,
    end: u64,
    offset: u64,
    aperture: Aperture,
}
impl Geometry {
    fn new(fields: [u32; 3], bytes: u64, allocation: u64) -> Result<Self, Error> {
        if fields.contains(&u32::MAX) {
            return Err(Error::DeviceGone);
        }
        // linux-lit: 0xffffff=FB_LOCATION_BASE__FB_BASE_MASK
        // (gc_11_0_0_sh_mask.h / mmhub_3_0_0_sh_mask.h agree).
        let [base, top, offset] = fields.map(|v| u64::from(v & 0xff_ffff) << 24);
        let end = top.checked_add(1 << 24).ok_or(Error::Invalid)?;
        if end.checked_sub(base) != Some(bytes)
            || allocation < base
            || allocation.checked_add(BYTES).is_none_or(|v| v > end)
            || allocation % 4096 != 0
        {
            return Err(Error::Invalid);
        }
        let start =
            end.checked_add(APERTURE_SIZE - 1).ok_or(Error::Invalid)? & !(APERTURE_SIZE - 1);
        if start.checked_add(APERTURE_SIZE).is_none_or(|v| v > LIMIT)
            || offset.checked_add(bytes).is_none_or(|v| v > LIMIT)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            fb: base,
            end,
            offset,
            aperture: Aperture {
                start,
                size: APERTURE_SIZE,
                source: start,
                destination: start + 4096,
            },
        })
    }
    fn physical(self, address: u64) -> u64 {
        address - self.fb + self.offset
    }
}
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn flush<I: Io>(io: &mut I, nbio: u64) -> Result<(), Error> {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    io.write(0x7f000, 0);
    checked(io.read(nbio + 0xc3 * 4))?;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}
fn pair<I: Io>(io: &mut I, base: u64, reg: u32, value: u64) {
    io.write(base + u64::from(reg) * 4, value as u32);
    io.write(base + u64::from(reg + 1) * 4, (value >> 32) as u32);
}
fn update<I: Io>(io: &mut I, base: u64, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
    let address = base + u64::from(reg) * 4;
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | value);
    Ok(())
}
/// `gfxhub_v3_0_gart_enable` + `mmhub_v3_0_gart_enable` for one hub:
/// aperture registers, TLB control, L2 cache, fault defaults, identity
/// aperture off, invalidation ranges, VMID0 context.
///
/// The L1/L2/fault literals are computed from `gc_11_0_0_sh_mask.h` /
/// `mmhub_3_0_0_sh_mask.h` — the two headers agree on every field this
/// programs, so one value serves both hubs (as on Navi22):
///
/// - L1 (`init_tlb_regs`): ENABLE_L1_TLB=1, SYSTEM_ACCESS_MODE=3,
///   ENABLE_ADVANCED_DRIVER_MODEL=1, SYSTEM_APERTURE_UNMAPPED_ACCESS=0,
///   ECO_BITS=0, MTYPE=UC(3) → mask 0x3ff9, value 0x1859.
/// - L2 (`init_cache_regs`): ENABLE_L2_CACHE=1, FRAGMENT_PROCESSING=0,
///   PDE0_TAG_MODE=0, PDE_FAULT_CLASSIFICATION=0,
///   CONTEXT1_IDENTITY_ACCESS_MODE=1, IDENTITY_FRAGMENT_SIZE=0, and
///   DEFAULT_PAGE_OUT_TO_SYSTEM_MEMORY left **clear**: Linux sets it,
///   but this owner's default page is owned VRAM, not system memory, so
///   the Navi22 precedent (clear) is kept → mask 0x03fc0903, value
///   0x80001.
/// - L2_CNTL3: default 0x80100007 (`mmhub_v3_0.c:33`,
///   `gfxhub_v3_0_3.c:32`; `gc_11_0_0_default.h` says 0x80120007 — the
///   difference is a BIGK bit the mask erases, so the result is the
///   same), BANK_SELECT 9, BIGK_FRAGMENT_SIZE 6 (no `translate_further`).
/// - L2_CNTL4 default 0xc1 with the VMC_TAP bits cleared; L2_CNTL5
///   default 0x3fe0 with SMALLK_FRAGMENT_SIZE 0.
/// - Fault control (`set_fault_enable_default(true)`): all eleven
///   `*_PROTECTION_FAULT_ENABLE_DEFAULT` bits, status-address bits
///   cleared → mask 0xfffffffc, value 0x1ffc. Fault CNTL2 keeps only
///   ACTIVE_PAGE_MIGRATION_PTE_READ_RETRY (Linux sets it on the MMHUB
///   in `init_system_aperture_regs`; the GFX hub inherits the same bit
///   here by the Navi22 precedent).
/// - VMID0 context: ENABLE_CONTEXT + the seven fault-enable defaults
///   (`setup_vmid_config`'s set, `CTX_CNTL_FAULT_ENABLE_DEFAULTS`),
///   PAGE_TABLE_DEPTH 0 (flat PT — `enable_system_domain`).
fn program<I: Io>(
    io: &mut I,
    base: u64,
    r: HubRegs,
    g: Geometry,
    address: u64,
) -> Result<(), Error> {
    let write = |io: &mut I, reg, value| io.write(base + u64::from(reg) * 4, value);
    // linux-lit: 1=AMDGPU_PTE_VALID
    pair(io, base, r.pt_base, g.physical(address) | 1); // valid VRAM PDE, byte address
    pair(io, base, r.pt_start, g.aperture.start >> 12);
    pair(
        io,
        base,
        r.pt_end,
        (g.aperture.start + g.aperture.size - 1) >> 12,
    );
    write(io, r.agp_base, 0);
    // linux: n/a (0xffffff = amdgpu_gmc_set_agp_default agp_start 0xffffffffffff >> 24)
    write(io, r.agp_bot, 0xffffff);
    write(io, r.agp_top, 0);
    write(io, r.sys_low, (g.fb >> 18) as u32);
    write(io, r.sys_high, ((g.end - 1) >> 18) as u32);
    let scratch = g.physical(address + 4096);
    write(io, r.sys_default_lo, (scratch >> 12) as u32);
    write(io, r.sys_default_hi, (scratch >> 44) as u32);
    write(io, r.fault_lo, (scratch >> 12) as u32);
    write(io, r.fault_hi, (scratch >> 44) as u32);
    // linux-lit: 0x40000=GCVM_L2_PROTECTION_FAULT_CNTL2__ACTIVE_PAGE_MIGRATION_PTE_READ_RETRY_MASK
    update(io, base, r.fault_cntl2, 0x40000, 0x40000)?;
    // UC=3. System access mode 3, ADM on, unmapped aperture access off,
    // ECO bits 0.
    // linux-lit: 0x3ff9=GCMC_VM_MX_L1_TLB_CNTL__ENABLE_L1_TLB_MASK | GCMC_VM_MX_L1_TLB_CNTL__SYSTEM_ACCESS_MODE_MASK | GCMC_VM_MX_L1_TLB_CNTL__SYSTEM_APERTURE_UNMAPPED_ACCESS_MASK | GCMC_VM_MX_L1_TLB_CNTL__ENABLE_ADVANCED_DRIVER_MODEL_MASK | GCMC_VM_MX_L1_TLB_CNTL__ECO_BITS_MASK | GCMC_VM_MX_L1_TLB_CNTL__MTYPE_MASK
    // linux-lit: 0x1859=GCMC_VM_MX_L1_TLB_CNTL__ENABLE_L1_TLB_MASK | GCMC_VM_MX_L1_TLB_CNTL__SYSTEM_ACCESS_MODE_MASK | GCMC_VM_MX_L1_TLB_CNTL__ENABLE_ADVANCED_DRIVER_MODEL_MASK | (3 << GCMC_VM_MX_L1_TLB_CNTL__MTYPE__SHIFT)
    update(io, base, r.l1, 0x3ff9, 0x1859)?;
    // Default fault page is owned VRAM, so OUT_TO_SYSTEM_MEMORY stays clear.
    // linux-lit: 0x03fc0903=GCVM_L2_CNTL__ENABLE_L2_CACHE_MASK | GCVM_L2_CNTL__ENABLE_L2_FRAGMENT_PROCESSING_MASK | GCVM_L2_CNTL__L2_PDE0_CACHE_TAG_GENERATION_MODE_MASK | GCVM_L2_CNTL__ENABLE_DEFAULT_PAGE_OUT_TO_SYSTEM_MEMORY_MASK | GCVM_L2_CNTL__PDE_FAULT_CLASSIFICATION_MASK | GCVM_L2_CNTL__CONTEXT1_IDENTITY_ACCESS_MODE_MASK | GCVM_L2_CNTL__IDENTITY_MODE_FRAGMENT_SIZE_MASK
    // linux-lit: 0x80001=GCVM_L2_CNTL__ENABLE_L2_CACHE_MASK | (1 << GCVM_L2_CNTL__CONTEXT1_IDENTITY_ACCESS_MODE__SHIFT)
    update(io, base, r.l2, 0x03fc0903, 0x80001)?;
    // linux-lit: 3=GCVM_L2_CNTL2__INVALIDATE_ALL_L1_TLBS_MASK | GCVM_L2_CNTL2__INVALIDATE_L2_CACHE_MASK
    update(io, base, r.l2_2, 3, 3)?;
    // linux-lit: 0xf803f=GCVM_L2_CNTL3__BANK_SELECT_MASK | GCVM_L2_CNTL3__L2_CACHE_BIGK_FRAGMENT_SIZE_MASK; 15=GCVM_L2_CNTL3__L2_CACHE_BIGK_FRAGMENT_SIZE__SHIFT
    // linux: n/a (0x80100007 = mmGCVM_L2_CNTL3_DEFAULT, *_default.h not in checker for mmhub; 9/6 literal in gfxhub_v3_0_init_cache_regs, !translate_further)
    write(io, r.l2_3, (0x80100007 & !0xf803f) | 9 | (6 << 15));
    // linux-lit: 0xc0=GCVM_L2_CNTL4__VMC_TAP_PDE_REQUEST_PHYSICAL_MASK | GCVM_L2_CNTL4__VMC_TAP_PTE_REQUEST_PHYSICAL_MASK
    // linux: n/a (0xc1 = mmGCVM_L2_CNTL4_DEFAULT, gc_11_0_0_default.h / mmhub_v3_0.c:34)
    write(io, r.l2_4, 0xc1 & !0xc0);
    // linux-lit: 0x1f=GCVM_L2_CNTL5__L2_CACHE_SMALLK_FRAGMENT_SIZE_MASK
    // linux: n/a (0x3fe0 = mmGCVM_L2_CNTL5_DEFAULT, gc_11_0_0_default.h / mmhub_v3_0.c:35)
    write(io, r.l2_5, 0x3fe0 & !0x1f);
    // linux: n/a (literal in gfxhub_v3_0_disable_identity_aperture)
    pair(io, base, r.identity_low, 0xf_ffffffff);
    pair(io, base, r.identity_high, 0);
    pair(io, base, r.identity_offset, 0);
    // Invalid translations return the VRAM default page. Leave fault IRQs off
    // until IH has an owner; no retry storm or host-memory fallback.
    // linux-lit: 0xfffffffc=0xffffffff & ~(GCVM_L2_PROTECTION_FAULT_CNTL__CLEAR_PROTECTION_FAULT_STATUS_ADDR_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__ALLOW_SUBSEQUENT_PROTECTION_FAULT_STATUS_ADDR_UPDATES_MASK)
    // linux-lit: 0x1ffc=GCVM_L2_PROTECTION_FAULT_CNTL__RANGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__PDE0_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__PDE1_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__PDE2_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__TRANSLATE_FURTHER_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__NACK_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__DUMMY_PAGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__VALID_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__READ_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__WRITE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_L2_PROTECTION_FAULT_CNTL__EXECUTE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK
    update(io, base, r.fault_cntl, 0xffff_fffc, 0x1ffc)?;
    for index in 0..18 {
        // linux: n/a (literal 18 engines in gfxhub_v3_0_program_invalidation)
        // Engine n's range is the hub's `eng_addr_distance` past engine 0's.
        // linux: n/a (0x1f_ffffffff = LO32 0xffffffff / HI32 0x1f literals in program_invalidation)
        pair(
            io,
            base,
            r.inv_range + index * r.eng_addr_distance,
            0x1f_ffffffff,
        );
    }
    // Only privileged VMID0: flat PT, no retry, default-page fault responses.
    // linux-lit: 1=GCVM_CONTEXT0_CNTL__ENABLE_CONTEXT_MASK
    // linux-lit: 0x555400=amdgpu_vmhub_regs::CTX_CNTL_FAULT_ENABLE_DEFAULTS
    write(io, r.ctx, 1 | 0x555400);
    Ok(())
}
/// `gmc_v11_0_get_invalidate_req` for the kernel's engine: the same
/// request word on every GFX10..12 hub — see
/// `amdgpu_vmhub_regs::invalidate_req`.
fn invalidate_request(vmid: u8) -> u32 {
    hub::invalidate_req(vmid, 0)
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    vram_size: u64,
    state: State,
    aperture: Option<Aperture>,
    geometry: Option<Geometry>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn wait(&mut self, address: u64, mask: u32) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(100); // linux: n/a (adev->usec_timeout 100 ms)
        loop {
            if self.access(|io| checked(io.read(address)))? & mask == mask {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            // linux: n/a (NARF 1 ms poll interval)
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    /// `gmc_v11_0_flush_gpu_tlb(vmid, hub, 0)` on engine 17 for one hub:
    /// HDP flush, MMHUB-only semaphore acquire (a read returning 1),
    /// request, ACK bit `1 << vmid`, semaphore release, then the MMHUB's
    /// additional private-cache invalidation (`vm_l2_bank_select_reserved_cid2`
    /// bit 25, `RESERVED_CACHE_PRIVATE_INVALIDATION`). Linux logs and goes
    /// on after a timeout; here a timeout fails closed (no release/replay)
    /// because the invalidation may still be outstanding.
    async fn flush_tlb_on(&mut self, vmid: u8, hub: Hub, boot: bool) -> Result<(), Error> {
        let layout = self.layout;
        let (index, r) = match hub {
            Hub::Gfx => (0, layout.hubs[0]),
            Hub::Mm => (1, layout.hubs[1]),
        };
        let base = layout.bases[index];
        if boot {
            self.state = State::Invalidating(hub);
        }
        if hub == Hub::Mm {
            // linux: n/a (semaphore-acquired bit 0x1, literal in gmc_v11_0_flush_gpu_tlb)
            self.wait(base + u64::from(r.inv_sem) * 4, 1).await?;
        }
        self.access(|io| {
            flush(io, layout.nbio)?;
            io.write(base + u64::from(r.inv_req) * 4, invalidate_request(vmid));
            Ok(())
        })?;
        self.wait(base + u64::from(r.inv_ack) * 4, 1 << vmid)
            .await?;
        if hub == Hub::Mm {
            self.access(|io| {
                io.write(base + u64::from(r.inv_sem) * 4, 0);
                // GMC11 additionally invalidates the MMHUB private cache.
                update(io, base, r.l2_bank_select, 1 << 25, 1 << 25)?;
                checked(io.read(base + u64::from(r.l2_bank_select) * 4))?;
                Ok(())
            })?;
        }
        Ok(())
    }
    /// `gmc_v11_0_flush_gpu_tlb` on both hubs, GFX then MM.
    async fn flush_tlb(&mut self, vmid: u8) -> Result<(), Error> {
        self.flush_tlb_on(vmid, Hub::Gfx, false).await?;
        self.flush_tlb_on(vmid, Hub::Mm, false).await?;
        Ok(())
    }
    /// `gmc_v11_0_get_vmid_pasid_mapping_info`: the PASID the GFX LUT
    /// holds for `vmid`, or `None` when unmapped (LUT entry 0).
    fn pasid_for_vmid(&mut self, vmid: u8) -> Result<Option<u16>, Error> {
        if vmid >= 16 {
            return Err(Error::Invalid);
        }
        let lut = self.layout.osssys + u64::from(vmid) * 4;
        let pasid = self.access(|io| checked(io.read(lut)))? & 0xffff;
        Ok(if pasid == 0 { None } else { Some(pasid as u16) })
    }
    /// `gmc_v11_0_emit_pasid_mapping`: write `pasid` into the VMID's
    /// slot of both LUTs (GFX at `IH_VMID_0_LUT + vmid`, MM at
    /// `IH_VMID_0_LUT_MM + vmid`). Linux's ring emit writes the one for
    /// its hub; the owner programs both so either hub's lookup agrees.
    /// PASID 0 unmaps (the LUT entry Linux reads as "no mapping").
    fn map_pasid(&mut self, vmid: u8, pasid: u16) -> Result<(), Error> {
        if vmid >= 16 {
            return Err(Error::Invalid);
        }
        let osssys = self.layout.osssys;
        self.access(|io| {
            io.write(osssys + u64::from(vmid) * 4, u32::from(pasid));
            io.write(osssys + 0x10 * 4 + u64::from(vmid) * 4, u32::from(pasid));
            Ok(())
        })
    }
    /// `gmc_v11_0_flush_gpu_tlb_pasid`: flush every VMID whose LUT entry
    /// is `pasid`, on both hubs. A PASID no VMID holds is a no-op.
    async fn flush_tlb_pasid(&mut self, pasid: u16) -> Result<(), Error> {
        if pasid == 0 {
            return Ok(());
        }
        for vmid in 1..16u8 {
            if self.pasid_for_vmid(vmid)? == Some(pasid) {
                self.flush_tlb(vmid).await?;
            }
        }
        Ok(())
    }
    async fn initialize(&mut self) -> Result<Aperture, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner().await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
    async fn initialize_inner(&mut self) -> Result<Aperture, Error> {
        let layout = self.layout;
        let address = self.memory.address();
        let size = self.vram_size;
        let geometry = self.access(|io| {
            // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
            // linux: n/a (0x7f000 = MMIO_REG_HOLE_OFFSET + KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL)
            if checked(io.read(layout.nbio + 0x12d * 4))? != 0x7f000 {
                return Err(Error::Invalid);
            }
            let g = Geometry::new(
                [
                    io.read(layout.bases[0] + u64::from(layout.hubs[0].fb_base) * 4),
                    io.read(layout.bases[0] + u64::from(layout.hubs[0].fb_top) * 4),
                    io.read(layout.bases[0] + u64::from(layout.hubs[0].fb_offset) * 4),
                ],
                size,
                address,
            )?;
            // Both hubs must agree on the inherited FB base and offset.
            // TOP is read on the GFX hub only (gmc_v11_0_vram_gtt_location
            // uses MEMSIZE for the end; the fixture's TOP must agree).
            if u64::from(checked(io.read(layout.bases[1] + u64::from(MM.fb_base) * 4))? & 0xffffff)
                << 24
                != g.fb
                || u64::from(
                    checked(io.read(layout.bases[1] + u64::from(MM.fb_offset) * 4))? & 0xffffff,
                ) << 24
                    != g.offset
            {
                return Err(Error::Invalid);
            }
            for (base, r) in layout.bases.into_iter().zip(layout.hubs) {
                // VMID0 is the kernel context firmware/GOP may leave enabled;
                // gfxhub/mmhub gart_enable reprograms it, as Linux does. A
                // live user context (1..15) would have unknown tables.
                for context in 1..16 {
                    // linux: n/a (VMIDs 1..15, AMDGPU_NUM_VMID 16)
                    // linux-lit: 1=GCVM_CONTEXT1_CNTL__ENABLE_CONTEXT_MASK
                    if checked(io.read(base + u64::from(r.ctx + context) * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
            Ok(g)
        })?;
        let map = self.memory.mapping();
        self.access(|io| {
            for offset in (0..BYTES).step_by(4) {
                io.memory(map, offset, 0);
            }
            // linux: n/a (NARF test-page layout)
            for (index, offset) in [8192, 12288].into_iter().enumerate() {
                // linux-lit: 0x61=AMDGPU_PTE_VALID | AMDGPU_PTE_READABLE | AMDGPU_PTE_WRITEABLE
                let pte = geometry.physical(address + offset) | 0x61; // V/R/W, NC VRAM
                io.memory(map, index as u64 * 8, pte as u32);
                io.memory(map, index as u64 * 8 + 4, (pte >> 32) as u32);
            }
            flush(io, layout.nbio)?;
            Ok(())
        })?;
        self.memory.publish(); // before either hub can retain a PT/default address
        self.aperture = Some(geometry.aperture);
        self.geometry = Some(geometry);
        self.access(|io| {
            for (base, r) in layout.bases.into_iter().zip(layout.hubs) {
                program(io, base, r, geometry, address)?;
            }
            Ok(())
        })?;
        self.flush_tlb(0).await?;
        Ok(geometry.aperture)
    }
}
/// One hub's register bank as the shared VM hub programming sees it.
struct Bank<'a, I: Io> {
    io: &'a mut I,
    base: u64,
}
impl<I: Io> crate::amdgpu_vmhub_regs::VmHubMmio for Bank<'_, I> {
    fn read(&mut self, byte_off: u32) -> u32 {
        self.io.read(self.base + u64::from(byte_off))
    }
    fn write(&mut self, byte_off: u32, value: u32) {
        self.io.write(self.base + u64::from(byte_off), value);
    }
}
impl<I: Io> Engine<I> {
    /// `gfxhub_v3_0_setup_vmid_config` / `mmhub_v3_0_setup_vmid_config` for
    /// VMIDs 1..15: each enabled with GMC 11's depth (3) and block size
    /// (9), every protection-fault default and no retry
    /// (`amdgpu_noretry`, `noretry_flags = AMDGPU_VM_NORETRY_FLAGS_TF`),
    /// bounded to 0..max_pfn-1, and — where Linux leaves the base at
    /// whatever the last flush wrote — pointed at an owned root directory
    /// whose every entry is GMC 11's invalid pattern, so a context no
    /// submission has flushed faults instead of translating. Then one
    /// invalidation of all fifteen on each hub's kernel engine (17), the
    /// MMHUB semaphore held around it. The 1–7 / 8–15 split is policy,
    /// not programming: every context gets the same registers.
    async fn prepare_clients(&mut self) -> Result<(), Error> {
        use crate::amdgpu_vmhub_regs::{self as hub, KERNEL_INVALIDATE_ENGINE};
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let geometry = self.geometry.ok_or(Error::Invalid)?;
        let layout = self.layout;
        let vm = VmGeometry::GMC11;
        let root = self.memory.address() + EMPTY_ROOT;
        let base = geometry.physical(root) | 1; // valid VRAM PDE, byte address
        let entries = vm.entries_at(vm.root_level);
        if entries * 8 > 4096 {
            return Err(Error::Invalid);
        }
        let empty = vm.format.pde_pte();
        let map = self.memory.mapping();
        self.state = State::PreparingClients;
        let result = async {
            self.access(|io| {
                for index in 0..entries {
                    io.memory64(map, EMPTY_ROOT + index * 8, empty);
                }
                flush(io, layout.nbio)?;
                for (bank, regs) in layout.bases.into_iter().zip(layout.vmhub) {
                    let mut b = Bank { io, base: bank };
                    for vmid in 1..16 {
                        hub::write_vmid_pt_base(&mut b, &regs, vmid, base);
                        hub::write_vmid_aperture(&mut b, &regs, vmid, 0, vm.max_pfn - 1);
                        hub::write_vmid_cntl(
                            &mut b,
                            &regs,
                            vmid,
                            vm.num_level(),
                            vm.block_size as u8,
                            true,
                        );
                    }
                }
                Ok(())
            })?;
            for (index, h, regs) in [
                (0, Hub::Gfx, layout.vmhub[0]),
                (1, Hub::Mm, layout.vmhub[1]),
            ] {
                let bank = layout.bases[index];
                let eng = regs.eng_distance * KERNEL_INVALIDATE_ENGINE;
                let at = |reg: u32| bank + u64::from(reg + eng) * 4;
                self.state = State::Invalidating(h);
                if regs.semaphore {
                    self.wait(at(regs.inv_eng0_sem), 1).await?;
                }
                // Every client VMID in one legacy request.
                let request = hub::invalidate_req(0, 0) & !1 | u32::from(CLIENT_VMIDS);
                self.access(|io| {
                    io.write(at(regs.inv_eng0_req), request);
                    Ok(())
                })?;
                let acked = self
                    .wait(at(regs.inv_eng0_ack), u32::from(CLIENT_VMIDS))
                    .await;
                if regs.semaphore {
                    self.access(|io| {
                        io.write(at(regs.inv_eng0_sem), 0);
                        Ok(())
                    })?;
                }
                acked?;
                self.state = State::PreparingClients;
            }
            // Read every context back.
            self.access(|io| {
                for (bank, regs) in layout.bases.into_iter().zip(layout.vmhub) {
                    let cntl =
                        hub::vmid_cntl_value(&regs, vm.num_level(), vm.block_size as u8, true);
                    for vmid in 1..16u32 {
                        let reg = |r: u32, d: u32| bank + u64::from(r + d * vmid) * 4;
                        let lo =
                            checked(io.read(reg(regs.ctx0_pt_base_lo, regs.ctx_addr_distance)))?;
                        let hi =
                            checked(io.read(reg(regs.ctx0_pt_base_hi, regs.ctx_addr_distance)))?;
                        // max_pfn - 1 has an all-ones low word; the high
                        // word (0xf) is what proves the device answered.
                        let end_lo = io.read(reg(regs.ctx0_pt_end_lo, regs.ctx_addr_distance));
                        let end_hi =
                            checked(io.read(reg(regs.ctx0_pt_end_hi, regs.ctx_addr_distance)))?;
                        if u64::from(hi) << 32 | u64::from(lo) != base
                            || u64::from(end_hi) << 32 | u64::from(end_lo) != vm.max_pfn - 1
                            || checked(io.read(reg(regs.ctx0_cntl, regs.ctx_distance)))? != cntl
                        {
                            return Err(Error::Invalid);
                        }
                    }
                }
                Ok(())
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::ClientsReady
        } else {
            State::Failed
        };
        result
    }
}
#[derive(Debug)]
pub struct Gmc {
    engine: Engine<Mmio>,
}
impl Gmc {
    /// Reserve backing pages without I/O. Only a physical Navi31/32/33 PF
    /// or a Phoenix APU is supported: AMD vendor, a GFX11 GC version
    /// (11.0.0 / 11.0.2 / 11.0.3 discrete, 11.0.1 Phoenix), MMHUB 3.0.0
    /// (3.0.1 on BASE_IDX 1 for Phoenix), OSSSYS 6.0.0.
    /// # Safety
    /// Caller owns both hubs, HDP, VRAM and the matching permanent pool,
    /// with no active GPU queues/VMs, GFXOFF, hub gating, reset or PM transition.
    /// Keep this owner alive while any consumer can use its VMID0 translations.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        // Holding the cap proves a prior grant; only invoke proves it is
        // still current, so construction itself proves validity — a
        // revoked authority fails here, before any allocation.
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        Ok(Self {
            engine: Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                vram_size: gpu.vram.size,
                state: State::Prepared,
                aperture: None,
                geometry: None,
            },
        })
    }
    /// The die this owner was built for.
    pub fn die(&self) -> Gfx11Die {
        self.engine.layout.die
    }
    /// # Safety
    /// Requires trained VRAM, completed PSP/RLC startup and the same exclusive
    /// ownership as new, with automatic power gating still disabled.
    /// Cancellation/failure prevents replay and quarantines published backing pages.
    pub async unsafe fn initialize(&mut self) -> Result<Aperture, Error> {
        self.engine.initialize().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// (MC_VM_FB_LOCATION_BASE, MC_VM_FB_OFFSET) as byte addresses: a pool
    /// address becomes the physical VRAM address entries carry as
    /// `address - fb + offset` (`gmc_v11_0_get_vm_pde`).
    pub fn framebuffer(&self) -> Option<(u64, u64)> {
        self.engine.geometry.map(|g| (g.fb, g.offset))
    }
    pub fn aperture(&self) -> Option<Aperture> {
        self.engine.aperture
    }
    /// Enable the client VMIDs 1..15 on both hubs at an empty root, as
    /// Linux's GART enable does, so a submission's in-ring VM flush can
    /// point one at a client's page tables. No client runs yet. VMIDs
    /// 1–7 are the graphics/compute range, 8–15 the KFD range
    /// (`FIRST_KFD_VMID`).
    /// # Safety
    /// As for `initialize`, after it succeeded; no queue may use a client
    /// VMID until this returns.
    pub async unsafe fn prepare_client_contexts(&mut self) -> Result<(), Error> {
        self.engine.prepare_clients().await
    }
    /// `gmc_v11_0_emit_pasid_mapping`: bind `pasid` to `vmid` in both
    /// IH LUTs. PASID 0 unmaps.
    /// # Safety
    /// As for `initialize`; the VMID must not be in use by a running
    /// queue while its mapping changes.
    pub unsafe fn map_pasid(&mut self, vmid: u8, pasid: u16) -> Result<(), Error> {
        self.engine.map_pasid(vmid, pasid)
    }
    /// `gmc_v11_0_get_vmid_pasid_mapping_info`: the PASID bound to
    /// `vmid`, or `None` when unmapped.
    pub fn pasid_for_vmid(&mut self, vmid: u8) -> Result<Option<u16>, Error> {
        self.engine.pasid_for_vmid(vmid)
    }
    /// `gmc_v11_0_flush_gpu_tlb_pasid`: flush every VMID bound to
    /// `pasid`, on both hubs.
    pub async fn flush_tlb_pasid(&mut self, pasid: u16) -> Result<(), Error> {
        self.engine.flush_tlb_pasid(pasid).await
    }
    /// `gmc_v11_0_flush_gpu_tlb(vmid, hub, 0)` on both hubs, GFX then MM.
    pub async fn flush_tlb(&mut self, vmid: u8) -> Result<(), Error> {
        self.engine.flush_tlb(vmid).await
    }
    /// The HDP flush (the remapped HDP_MEM_FLUSH_CNTL write and NBIO
    /// read-back `flush` does) under this owner's live PCI authority.
    pub fn hdp_flusher(&self) -> HdpFlusher {
        HdpFlusher {
            regs: self.engine.io.0,
            nbio: self.engine.layout.nbio,
            authority: self.engine.authority,
        }
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gmc_navi31_tests.rs"]
pub(crate) mod tests;

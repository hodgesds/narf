//! Strix Point (GC 11.5.0) cold boot: the sixteen-stage graphics bring-up in
//! Linux order, mirroring [`crate::amdgpu_phoenix_boot`] but with the
//! Strix owners (`gfx_v11_0.c::gfx_v11_0_hw_init` +
//! `mes_v11_0.c::mes_v11_0_hw_init`).
//!
//! Stages: Smu → MemoryHubs → Gart → Interrupts → GoldenSettings → SdmaTest
//! → InterruptTest → Doorbells → GfxSetup → Kiq → ComputeQueues → GfxRing →
//! SdmaQueues → IbTests → FenceInterrupts → ReadTopology. Media (VCN 4.0.5)
//! is NOT one of the sixteen: there is no VCN 4.0 owner yet, so the media
//! stage is a flagged remainder and `media` is always `None`.
//!
//! The owners this coordinator wires together:
//!
//!   * SMU 14.0.0 MMIO mailbox — [`crate::amdgpu_smu_strix`] (C2PMSG_66 /
//!     82 / 90 on MP1 window 1; driver-IF exactly 0x7; the
//!     `FIRMWARE_FLAGS` check runs first in `start`). Merged #2486 gated
//!     on MP1 14.0.1 / 0x6 — Strix Halo, not Strix Point — and is corrected
//!     here; see that module's docs.
//!   * GMC — [`crate::amdgpu_gmc_navi31`]'s `Gfx11Die::Strix` arm (GC
//!     11.5.0 bank 0, MMHUB 3.0.1 bank 1 or 3.0.2 bank 0, OSSSYS 6.0.0).
//!   * IH6 — [`crate::amdgpu_ih_phoenix`] (drain-based; no subscribe API),
//!     with the Strix FB aperture registers (0x167c/0x167d).
//!   * SDMA 6.1.0 queue 0 — [`crate::amdgpu_sdma::build_sdma6_ring_init`]
//!     directly. Linux's `sdma_v6_0.c` has no version arms in the ring
//!     init/test path (only user-queue arms for 6.1.0–6.1.3), and every
//!     SDMA0 register the builder uses is identical between
//!     `gc_11_0_0_offset.h` and `gc_11_5_0_offset.h`, so the builder
//!     carries over with the 6.1.0 bank.
//!   * MES-KIQ — [`crate::amdgpu_mes::MesQueue`] (sched pipe 0, KIQ pipe 1)
//!     with `map_legacy_queue` for the kernel GFX and compute rings, and
//!     [`crate::amdgpu_mes_hw::STRIX_TOPOLOGY`] (the `gfx_v11_0_sw_init`
//!     11.5.0 arm is the same arm as Phoenix's).
//!   * GFXOFF — [`crate::amdgpu_raphael_gfxoff::GfxOff`] with a Strix
//!     `GcPower` (SMU `set_gfxoff` + RLC `gfx_v11_cntl_pg`), and the
//!     `STRIX_CG` / `STRIX_PG` flags (`soc21.c` 11.5.0 arm).
//!   * Topology — [`crate::amdgpu_gfx11_topology::read_strix`] (GC 11.5.0
//!     banks, NBIO 7.11 strap dword).
//!
//! Clock gating has NO owner yet (the GC11 `Gating` tables from
//! `gfx_v11_0_update_gfx_clock_gating` are not transcribed): `gating` is
//! `None`, the clocks stay ungated, and `gate_gfx` still gates power. The
//! GC11 `Gating` owner is a flagged remainder.
//!
//! Inferred, not known: OSSSYS 6.0.0 (`ih_v6_0.c` is version-agnostic and
//! Linux gives every soc21 part the 6.0.0 bank) and one SDMA instance
//! (Phoenix hardcodes 1 the same way; no Strix discovery table has been
//! read). The discovery line names the inferred versions on first boot.
//!
//! Register access in this module follows the owners: Cap-invoked direct
//! byte-offset MMIO (`Mmio(gpu.regs)` + `access`), never
//! [`crate::amdgpu::AmdGpu::apply_gfx11_sequence`] (indexed MM_INDEX port,
//! returns `()` and silently no-ops unless the generation is Gfx11). The one
//! exception is [`crate::amdgpu::AmdGpu::read_mes_fw_versions`], which
//! brackets its own GRBM selection and restores it.
//!
//! Fixture-validated end to end; silicon untested. The platform wiring
//! (`graphics_boot_strix` in `amdgpu_platform`) is unreachable until a
//! Strix firmware-set opener (`Firmware::open_strix` +
//! `Loader::set_graphics` Strix arm) lands — there is none in tree, and
//! Phoenix itself has no firmware-set opener either.

use crate::amdgpu::AmdGpu;
use crate::amdgpu_cp_navi22::{self as cp22, Doorbells};
use crate::amdgpu_gfx::{
    self as gfx, ComputeContext, Gfx11Sequence, GfxContext, GfxStep, SubmitError,
};
use crate::amdgpu_gfx11_topology::{self as topo11, Topology};
use crate::amdgpu_gmc_navi31::{self as gmc31, Gmc};
use crate::amdgpu_ih_phoenix::{self as ih, Rings};
use crate::amdgpu_mes::{self as mes, MesQueue};
use crate::amdgpu_mes_hw::{self as meshw, STRIX_TOPOLOGY};
use crate::amdgpu_navi22_gating as gating;
use crate::amdgpu_raphael_gfxoff::{self as gfxoff, PowerGating};
use crate::amdgpu_rdna2::options::BootOptions;
use crate::amdgpu_smu_strix::{self as smu, Smu};
use crate::amdgpu_vram::Pool;
use crate::{amdgpu_discovery as ip, amdgpu_psp_ring::bank};
use alloc::boxed::Box;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId};

/// SDMA engine 0's doorbell assignment index
/// (`AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE0`, via `soc21_init_doorbell_index`,
/// which is not version-gated — the same index for all soc21 including
/// Strix); the dword-space index is twice it (`sdma_v6_0.c`:
/// `ring->doorbell_index = sdma_engine[i] << 1`). The header itself is not
/// in this ref checkout, so the numeric value rests on the APU audit's
/// earlier read of it.
const SDMA0_DOORBELL_INDEX: u16 = 0x100;
/// MES doorbell dword indices (`AMDGPU_NAVI10_DOORBELL_MES_RING0/1` 0x00B /
/// 0x00C, `amdgpu_doorbell.h`, shifted to dword space).
const MES_SCHED_DOORBELL_DW: u32 = 0x16;
const MES_KIQ_DOORBELL_DW: u32 = 0x18;
/// MES command rings: 16 frames of 64 dwords = 1024 dwords, like
/// `MES_RING_DWORDS`.
const MES_FRAMES: usize = 16;
/// `CP_INT_CNTL_RING0` / `CP_ME1_PIPE0_INT_CNTL` (GC BASE_IDX 0,
/// `gc_11_5_0_offset.h`), and their EOP/fault fields. Both are identical
/// to the 11.0.0 values.
const CP_INT_CNTL_RING0: u32 = 0x1e0a;
const CP_ME1_PIPE0_INT_CNTL: u32 = 0x1e25;
const CP_INT_PRIV_INSTR: u32 = 1 << 22;
const CP_INT_PRIV_REG: u32 = 1 << 23;
const CP_INT_OPCODE_ERROR: u32 = 1 << 24;
const CP_INT_TIME_STAMP: u32 = 1 << 26;
const CP_INT_GENERIC0: u32 = 1 << 31;
/// `regSDMA0_CNTL` (SDMA0 BASE_IDX 0) `TRAP_ENABLE`, bit 0
/// (`sdma_v6_0.c:1588`). Identical on 11.5.0.
const SDMA0_CNTL_REL: u32 = 0x1c * 4;
const SDMA_TRAP_ENABLE: u32 = 1;
/// `regRCC_DOORBELL_APER_EN` (NBIF BASE_IDX 2, `nbio_7_11_0_offset.h`:
/// `regRCC_DEV0_EPF0_0_RCC_DOORBELL_APER_EN` 0x00c0).
const NBIO_DOORBELL_APER_EN_REL: u32 = 0x00c0 * 4;
/// NBIO self-ring registers are NOT written: Linux's
/// `nbio_v7_0_enable_doorbell_selfring_aperture` is an empty no-op, and
/// `nbio_v7_11_enable_doorbell_selfring_aperture` is one too — the
/// self-ring is a flagged remainder.
/// `regRLC_SAFE_MODE` (GC BASE_IDX 1, `gc_11_5_0_offset.h`) and
/// `regRLC_PG_DELAY_3` (GC BASE_IDX 1): both identical to the 11.0.0 values.
const RLC_SAFE_MODE: u32 = 0x0980;
const RLC_PG_DELAY_3: u32 = 0x4c78;
/// `RLC_PG_DELAY_3_DEFAULT_GC_11_0_1` (`gfx_v11_0.c:5812`): the same
/// 0x1388 is written for 11.5.0–11.5.4, 11.0.1 and 11.0.4.
const RLC_PG_DELAY_3_DEFAULT_11_5_0: u32 = 0x1388;
const IB_DEADLINE_MS: u64 = 100;
const INTERRUPT_TEST_DEADLINE_MS: u64 = 100;
/// `MES_SCH_API_SET_HW_RSRC_1` opcode 19, gated on sched version ≥ 0x52
/// (`mes_v11_0.c:2145`). NARF has the opcode but no builder, so the stage
/// records `hw_rsrc_1_skipped` instead of failing the boot.
const SET_HW_RSRC_1_MIN_VERSION: u32 = 0x52;

/// One golden-register entry: (GC window, dword register, mask, value),
/// applied as `(live & !mask) | (value & mask)`.
struct Golden {
    window: u32,
    reg: u32,
    mask: u32,
    value: u32,
}
/// `golden_settings_gc_11_0[]` (`gfx_v11_0.c:319`): applied to ALL GC 11.x
/// including 11.5.0. The 11.0.1 table (`golden_settings_gc_11_0_1`, 9
/// entries) applies only to 11.0.1/11.0.4, so Strix gets the base table
/// only — one entry, GC 0, regTCP_CNTL 0x19a2 (the same dword in
/// `gc_11_5_0_offset.h`).
const GOLDEN_11_0_0: [Golden; 1] = [Golden {
    window: 1,
    reg: 0x19a2,
    mask: 0x20000000,
    value: 0x20000000,
}];

/// The four GC/MMHub/OSSSYS/NBIF byte bases this coordinator writes through
/// directly, resolved in [`StrixColdBoot::new`] via `bank()`.
#[derive(Clone, Copy, Debug)]
struct Banks {
    gc0: u32,
    gc1: u32,
    sdma0: u32,
    nbio: u32,
}

/// SDMA queue 0: the production queue and the test ring are the same ring
/// (Strix has one SDMA instance, as Phoenix does), so the SdmaTest stage
/// re-verifies the live RB_CNTL and records the queue rather than testing
/// a spare.
struct SdmaRing {
    ring: crate::amdgpu_ring::Ring,
    /// One 4 KiB writeback page: rptr +0, wptr poll +8, fence +16 (u32 each).
    wb: DmaBuffer,
    fence_seq: u32,
}
impl SdmaRing {
    fn new() -> Result<Self, crate::amdgpu_ring::RingError> {
        let ring = crate::amdgpu_ring::Ring::new(
            SDMA0_DOORBELL_INDEX,
            crate::amdgpu_ring::DoorbellKind::Sdma,
        )?;
        let wb = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| crate::amdgpu_ring::RingError::NoMemory)?;
        // SAFETY: identity-mapped, exclusive owner, bounded by the page.
        unsafe {
            for offset in (0..4096u64).step_by(8) {
                core::ptr::write_volatile(wb.cpu_mut_ptr_at::<u64>(offset), 0);
            }
        }
        Ok(Self {
            ring,
            wb,
            fence_seq: 0,
        })
    }
    fn rptr_phys(&self) -> u64 {
        self.wb.dma_addr().raw()
    }
    fn wptr_poll_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + 8
    }
    fn fence_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + 16
    }
    fn fence_observed(&self) -> u32 {
        // SAFETY: identity-mapped DMA backing, exclusive owner.
        unsafe { core::ptr::read_volatile(self.wb.cpu_ptr_at::<u32>(16)) }
    }
    fn rptr_observed(&self) -> u64 {
        // SAFETY: identity-mapped DMA backing, exclusive owner.
        u64::from(unsafe { core::ptr::read_volatile(self.wb.cpu_ptr_at::<u32>(0)) })
    }
}

/// PMFW's GFXOFF messages and RLC's power gating, for `gfxoff`.
struct GcPower<'a> {
    smu: &'a mut Smu,
    banks: Banks,
    authority: Cap<BusDeviceCap, Write>,
    regs: MmioRegion,
}
impl crate::amdgpu_navi22_gfxoff::Control for GcPower<'_> {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        self.smu.set_gfxoff(allow).await.map_err(|_| ())
    }
}
impl GcPower<'_> {
    /// One Cap-invoked register read; `u32::MAX` is a vanished device.
    fn read(&mut self, at: u64) -> Result<u32, ()> {
        let mut io = Mmio(self.regs);
        self.authority
            .invoke(Op(|| read(&mut io, at)))
            .map_err(|_| ())?
            .map_err(|_| ())
    }
    /// One Cap-invoked register write with readback.
    fn write(&mut self, at: u64, value: u32) -> Result<(), ()> {
        let mut io = Mmio(self.regs);
        self.authority
            .invoke(Op(|| write(&mut io, at, value)))
            .map_err(|_| ())?
            .map_err(|_| ())
    }
    /// Poll `RLC_SAFE_MODE` until its CMD bit clears, yielding between
    /// reads; the RLC's safe-mode transition is not instantaneous.
    async fn poll_safe_mode_clear(&mut self, safe_mode: u64) -> Result<(), ()> {
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.read(safe_mode)? & 0x1 == 0 {
                return Ok(());
            }
            if deadline.expired() {
                return Err(());
            }
            narf_scheduler::yield_now().await;
        }
    }
}
impl PowerGating for GcPower<'_> {
    async fn set_power_gating(&mut self, enable: bool) -> Result<(), ()> {
        // `gfx_v11_cntl_pg`: enter safe mode, `gfx_v11_cntl_power_gating`,
        // exit safe mode. Safe mode only applies when RLC is enabled
        // (`RLC_CNTL` bit 0) and the CG flags carry CGCG | MGCG | 3D_CGCG.
        // GFXOFF is disallowed for the call (the count is 1 before GATE,
        // and UNGATE ran first), so no other task is touching GC.
        let gc1 = self.banks.gc1;
        let rlc_cntl = gc1 + crate::amdgpu_cp_rdna3::RLC_CNTL * 4;
        let rlc_pg_cntl = gc1 + crate::amdgpu_cp_rdna3::RLC_PG_CNTL * 4;
        let safe_mode = gc1 + RLC_SAFE_MODE * 4;
        let pg_delay_3 = gc1 + RLC_PG_DELAY_3 * 4;
        let live_cntl = self.read(u64::from(rlc_cntl))?;
        let live_pg = self.read(u64::from(rlc_pg_cntl))?;
        let rlc_on = live_cntl & crate::amdgpu_cp_rdna3::RLC_ENABLE_F32 != 0;
        let cg = gating::cg::GFX_CGCG | gating::cg::GFX_MGCG | gating::cg::GFX_3D_CGCG;
        let safe = rlc_on && (gating::STRIX_CG & cg) != 0;
        if safe {
            // `gfx_v11_0_set_safe_mode` (enter): CMD | (1 << MESSAGE).
            self.write(u64::from(safe_mode), 0x1 | (1 << 1))?;
            self.poll_safe_mode_clear(u64::from(safe_mode)).await?;
        }
        // `gfx_v11_cntl_power_gating`: RLC_PG_CNTL bit 0, only when enabling
        // and the PG flags carry GFX_PG.
        let pg_enable = enable && (gating::STRIX_PG & gating::pg::GFX_PG) != 0;
        let want = if pg_enable {
            live_pg | 0x1
        } else {
            live_pg & !0x1
        };
        self.write(u64::from(rlc_pg_cntl), want)?;
        if pg_enable {
            // 11.5.0: RLC_PG_DELAY_3 = 0x1388, as for 11.0.1/11.0.4.
            self.write(u64::from(pg_delay_3), RLC_PG_DELAY_3_DEFAULT_11_5_0)?;
        }
        if safe {
            self.write(u64::from(safe_mode), 0x1)?;
            self.poll_safe_mode_clear(u64::from(safe_mode)).await?;
        }
        Ok(())
    }
}

/// Direct byte-offset MMIO over the permanent BAR5 mapping, Cap-invoked per
/// call — the owners' pattern.
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: bounded exact discovery banks, exclusive owner, live invocation.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same permanent register mapping, ownership and authority.
        unsafe { self.0.write32(at, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn read(io: &mut Mmio, at: u64) -> Result<u32, Error> {
    match io.read(at) {
        u32::MAX => Err(Error::DeviceGone),
        value => Ok(value),
    }
}
fn write(io: &mut Mmio, at: u64, value: u32) -> Result<(), Error> {
    io.write(at, value);
    if read(io, at)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn update(io: &mut Mmio, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, at)?;
    io.write(at, (old & !mask) | (value & mask));
    if read(io, at)? & mask != value & mask {
        return Err(Error::Readback);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Smu(smu::Error),
    MemoryHubs(gmc31::Error),
    Interrupts(ih::Error),
    Sdma(crate::amdgpu_sdma::SdmaError),
    SdmaPkt(crate::amdgpu_sdma::SdmaPktError),
    Queues(SubmitError),
    Compute(gfx::ComputeCtxError),
    Gfx(gfx::GfxError),
    Mqd(gfx::MqdError),
    Doorbells(cp22::Error),
    Mes(mes::MesError),
    Topology(topo11::Error),
    GfxOff(gfxoff::Error),
}

/// The sixteen stages, in Linux bring-up order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Smu,
    MemoryHubs,
    Gart,
    Interrupts,
    GoldenSettings,
    SdmaTest,
    InterruptTest,
    Doorbells,
    GfxSetup,
    Kiq,
    ComputeQueues,
    GfxRing,
    SdmaQueues,
    IbTests,
    FenceInterrupts,
    ReadTopology,
}
const STAGES: [Stage; 16] = [
    Stage::Smu,
    Stage::MemoryHubs,
    Stage::Gart,
    Stage::Interrupts,
    Stage::GoldenSettings,
    Stage::SdmaTest,
    Stage::InterruptTest,
    Stage::Doorbells,
    Stage::GfxSetup,
    Stage::Kiq,
    Stage::ComputeQueues,
    Stage::GfxRing,
    Stage::SdmaQueues,
    Stage::IbTests,
    Stage::FenceInterrupts,
    Stage::ReadTopology,
];

/// What the SDMA stage proved: queue 0's ring is enabled. The fence proof
/// for the queue lives in [`QueueProof::sdma_fence`] (the IB test); the
/// packet round-trip proof is the SDMA-owner lane's remainder. This stage
/// proves the ring, not the packet builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdmaProof {
    pub rb_enabled: bool,
}
/// What the queue stages proved: one fence per kernel queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueProof {
    pub gfx_fence: u64,
    pub compute_fence: u64,
    pub sdma_fence: u32,
}
/// What the MES-KIQ stage proved: both pipes running, the legacy queue map
/// decision, and whether SET_HW_RSRC_1 was skipped (no NARF builder).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MesProof {
    pub sched_version: u32,
    pub kiq_version: u32,
    pub legacy_queue_map: bool,
    pub hw_rsrc_1_skipped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    pub aperture: gmc31::Aperture,
    /// The Navi31 GMC has no separate `enable_gart` / `gart()`: GART is
    /// ready once client contexts are prepared (`ClientsReady`).
    pub gart_ready: bool,
    pub sdma: SdmaProof,
    pub queues: QueueProof,
    pub mes: MesProof,
    pub topology: Topology,
    /// How many of the sixteen stages completed.
    pub stages_completed: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "boot state snapshots remain Copy and allocation-free, as Phoenix's"
)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    Failed { stage: Stage, error: Error },
}

/// One lent GFXHUB client VMID range: the driver range 1..`first_kfd_vmid`
/// (8), lent once to the submitter lane. The Navi31 GMC enables VMIDs 1..15
/// at empty root in `prepare_client_contexts` but tracks no lending; the
/// coordinator does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientVmids {
    pub first: u8,
    pub count: u8,
}

/// Every Strix Point graphics owner, retained through success and failure
/// so no published memory is released while an engine may still reach it.
pub struct StrixColdBoot {
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    smu: Smu,
    // Boxed: the owners are large, and a coordinator holding them inline
    // would put all of them in every frame and future that holds it.
    gmc: Box<Gmc>,
    ih: Box<Rings>,
    sdma: SdmaRing,
    doorbells: Doorbells,
    gfx: GfxContext,
    compute: ComputeContext,
    mes_sched: MesQueue,
    mes_kiq: MesQueue,
    /// Per-pipe MES program-counter entry points (`uc_start_addr`), from the
    /// firmware-load lane; see [`crate::amdgpu_phoenix_boot::parse_mes_start_addrs`].
    mes_start: [u64; 2],
    /// The four byte bases this coordinator writes through directly.
    banks: Banks,
    /// The ring-test IB buffer, shared by the GFX and compute IB tests
    /// (sequential use).
    ib_buf: DmaBuffer,
    versions: Option<smu::Versions>,
    aperture: Option<gmc31::Aperture>,
    gart_ready: bool,
    sdma_proof: Option<SdmaProof>,
    queue_proof: Option<QueueProof>,
    mes_proof: Option<MesProof>,
    topology: Option<Topology>,
    client_vmids_lent: bool,
    stages_completed: u8,
    state: State,
    /// GFX power gating and GFXOFF for this lifetime. There is no
    /// clock-gating owner yet (the GC11 `Gating` tables are a flagged
    /// remainder), so the clocks stay ungated; `pg_flags` / `cg_flags`
    /// ([`gating::STRIX_PG`] / [`gating::STRIX_CG`] under
    /// `amdgpu.pg_mask` / `amdgpu.cg_mask`) are consumed at construction
    /// and not retained — the media owner that reads them does not exist
    /// yet either.
    gfxoff: gfxoff::GfxOff,
    /// `amdgpu.gfxoff`: whether the SMU stage disallows GFXOFF at boot
    /// and the RLC start sequence keeps the SMU handshake enabled.
    gfxoff_enabled: bool,
}

/// `AmdGpu` has no `Debug` impl, so the derived form is unavailable; the
/// coordinator still formats its boot state for the failure path.
impl core::fmt::Debug for StrixColdBoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StrixColdBoot")
            .field("state", &self.state)
            .field("gart_ready", &self.gart_ready)
            .field("client_vmids_lent", &self.client_vmids_lent)
            .field("gfxoff_enabled", &self.gfxoff_enabled)
            .finish_non_exhaustive()
    }
}

fn is_strix_did(vid: u16, did: u16) -> bool {
    // Strix Point is its own family (Family::Strix, RDNA3.5) with its own
    // bring-up; every Strix owner DID-gates on this one DID.
    matches!(
        (vid, did),
        (crate::amdgpu::AMD_VENDOR, crate::amdgpu::STRIX_POINT)
    )
}

/// Resolve the NBIF bank without gating on an NBIO version (see the GMC
/// owner): BASE_IDX 2, dword 0x00c0, bounded by the BAR. Only the doorbell
/// aperture enable goes through it; the self-ring is a remainder.
fn nbio_bank(gpu: &AmdGpu) -> Result<u32, Error> {
    let ip = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
    if ip.num_bases < 3 {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[2] as u64 * 4;
    if base
        .checked_add((0x00c0_u64 + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    u32::try_from(base).map_err(|_| Error::Invalid)
}

/// The blocks whose Strix versions this port infers rather than knows:
/// no Strix discovery table has been read. Each is accepted at every
/// version Linux drives with the same functions.
const INFERRED: [(&str, u16); 6] = [
    ("NBIF", ip::HW_ID_NBIF),
    ("MMHUB", ip::HW_ID_MMHUB),
    ("ATHUB", ip::HW_ID_ATHUB),
    ("OSSSYS", ip::HW_ID_OSSSYS),
    ("HDP", ip::HW_ID_HDP),
    ("SMUIO", ip::HW_ID_SMUIO),
];
/// One boot line with the discovered versions of [`INFERRED`]'s blocks
/// (instance 0; `-` where discovery lists none), so the first boot on the
/// hardware confirms or refutes them.
fn discovery_line(blocks: &[ip::IpBlock]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut line = alloc::string::String::from("amdgpu: strix discovery:");
    for (name, id) in INFERRED {
        let _ = match ip::find_ip(blocks, id, 0) {
            Some(b) => write!(line, " {name} {}.{}.{}", b.major, b.minor, b.revision),
            None => write!(line, " {name} -"),
        };
    }
    line
}

fn snapshot(gpu: &AmdGpu) -> Result<AmdGpu, Error> {
    let mut blocks = alloc::vec::Vec::new();
    blocks
        .try_reserve_exact(gpu.ip_blocks.len())
        .map_err(|_| Error::Allocation)?;
    blocks.extend_from_slice(&gpu.ip_blocks);
    Ok(AmdGpu {
        fb_bar: gpu.fb_bar,
        regs: gpu.regs,
        chip: gpu.chip,
        vram: gpu.vram,
        ip_blocks: blocks,
        gc_info: gpu.gc_info,
        vbios: None,
        mode: None,
        backlight_percent: None,
        fw_loaded: false,
    })
}

impl StrixColdBoot {
    /// # Safety
    /// Own this physical GPU, permanent mappings, the inventory-derived free
    /// VRAM pool, all GFX/SDMA/MES/IP sources/indexing/reset/PM, and its PCI
    /// interrupt route. The retained coordinator must outlive any published
    /// address, including errors. Preparation validates layouts, reserves
    /// memory and maps BAR2, but never writes a register.
    ///
    /// `mes_start` is `[sched, kiq]`: the two MES program-counter entry
    /// points from the MES firmware header (see
    /// [`crate::amdgpu_phoenix_boot::parse_mes_start_addrs`]); the
    /// firmware-load lane supplies them.
    pub(crate) unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: &BusDevice,
        mes_start: [u64; 2],
    ) -> Result<Self, Error> {
        if !is_strix_did(gpu.chip.vid, gpu.chip.did) {
            return Err(Error::Unsupported);
        }
        {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "{}", discovery_line(&gpu.ip_blocks));
        }
        let gpu = snapshot(gpu)?;
        // SAFETY: forwarded exclusive ownership; every constructor below only
        // validates layouts, reserves memory or maps BAR2.
        unsafe {
            let smu = Smu::new(&gpu, authority).map_err(Error::Smu)?;
            let gmc = Gmc::new(&gpu, authority, pool).map_err(Error::MemoryHubs)?;
            let ih = Rings::new(&gpu, authority, pool).map_err(Error::Interrupts)?;
            let sdma = SdmaRing::new().map_err(|e| Error::Queues(e.into()))?;
            let doorbells = Doorbells::map_strix(device).map_err(Error::Doorbells)?;
            let gfx = GfxContext::new(crate::amdgpu_ring::doorbell_assignment::GFX_RING0)
                .map_err(|e| Error::Queues(e.into()))?;
            let compute = ComputeContext::new(0, 0, 0, 0).map_err(Error::Compute)?;
            let mes_sched = MesQueue::new(MES_FRAMES, MES_SCHED_DOORBELL_DW).map_err(Error::Mes)?;
            let mes_kiq = MesQueue::new(MES_FRAMES, MES_KIQ_DOORBELL_DW).map_err(Error::Mes)?;
            let ib_buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?;
            // The four byte bases this coordinator writes through directly.
            // GC idx 0's highest dword touched is CP_HQD_PQ_DOORBELL_CONTROL
            // (0x1fb8, queue-init); GC idx 1's is the topology's
            // CGTS_USER_TCC_DISABLE (0x5b96); SDMA0's is its doorbell
            // (0x92); NBIF idx 2 is version-ungated, bounded by the doorbell
            // aperture enable (0x00c0).
            let banks = Banks {
                gc0: u32::try_from(
                    bank(&gpu, ip::HW_ID_GC, &[(11, 5, 0)], 0, 0x1fb8)
                        .map_err(|_| Error::Unsupported)?,
                )
                .map_err(|_| Error::Unsupported)?,
                gc1: u32::try_from(
                    bank(&gpu, ip::HW_ID_GC, &[(11, 5, 0)], 1, 0x5b96)
                        .map_err(|_| Error::Unsupported)?,
                )
                .map_err(|_| Error::Unsupported)?,
                sdma0: u32::try_from(
                    bank(&gpu, ip::HW_ID_SDMA0, &[(6, 1, 0)], 0, 0x92)
                        .map_err(|_| Error::Unsupported)?,
                )
                .map_err(|_| Error::Unsupported)?,
                nbio: nbio_bank(&gpu)?,
            };
            let options = BootOptions::parse(narf_boot::args().raw());
            let pg_flags = gating::STRIX_PG & options.pg_mask;
            // Reserved: no clock-gating owner consumes the CG mask yet.
            let _cg_flags = gating::STRIX_CG & u64::from(options.cg_mask);
            Ok(Self {
                gpu,
                authority,
                pool: pool.clone(),
                smu,
                gmc: Box::new(gmc),
                ih: Box::new(ih),
                sdma,
                doorbells,
                gfx,
                compute,
                mes_sched,
                mes_kiq,
                mes_start,
                banks,
                ib_buf,
                versions: None,
                aperture: None,
                gart_ready: false,
                sdma_proof: None,
                queue_proof: None,
                mes_proof: None,
                topology: None,
                client_vmids_lent: false,
                stages_completed: 0,
                state: State::Prepared,
                gfxoff: gfxoff::GfxOff::new(options.gfxoff, pg_flags & gating::pg::GFX_PG != 0),
                gfxoff_enabled: options.gfxoff,
            })
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// A completed run: every kernel queue passed its ring and IB tests.
    pub fn queues_verified(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }
    /// GART is ready once the GMC's client contexts are prepared.
    pub fn memory(&mut self) -> Option<&mut Gmc> {
        matches!(self.state, State::Ready(_)).then_some(&mut *self.gmc)
    }
    /// Lend the GFXHUB driver VMIDs (1..8) once, to the submitter lane.
    pub fn reserve_client_vmids(&mut self) -> Result<ClientVmids, Error> {
        if !self.queues_verified() || self.client_vmids_lent {
            return Err(Error::Busy);
        }
        self.client_vmids_lent = true;
        Ok(ClientVmids { first: 1, count: 7 })
    }
    /// Half of the carve-out the display left, as a client heap: Navi22's
    /// policy. Everything an APU's pool holds is CPU-mapped.
    pub fn reserve_client_vram(
        &mut self,
    ) -> Result<(crate::amdgpu_vram::Reservation, crate::amdgpu_gem::VramHeap), Error> {
        const ALIGN: u64 = 2 << 20; // linux: n/a (NARF policy, client heap alignment)
        if !self.queues_verified() {
            return Err(Error::Busy);
        }
        let (fb_base, fb_offset) = self.gmc.framebuffer().ok_or(Error::Invalid)?;
        let size = (self.pool.available() / 2) & !(ALIGN - 1);
        if size < 64 << 20 {
            return Err(Error::Allocation);
        }
        let mut chunk = self
            .pool
            .reserve_aligned(size, ALIGN)
            .map_err(|_| Error::Allocation)?;
        // SAFETY: the reservation is this heap's alone, inside the owned,
        // CPU-mapped carve-out the display path's pool covers.
        let pool = unsafe { Pool::from_owned_range(chunk.mapping(), chunk.address()) }
            .map_err(|_| Error::Allocation)?;
        chunk.publish();
        Ok((
            chunk,
            crate::amdgpu_gem::VramHeap {
                pool,
                fb_base,
                fb_offset,
                unmapped: None,
            },
        ))
    }
}

/// Boot-only checkpoints, never a poll-loop trace.
fn progress(stage: Stage, result: Option<Result<(), Error>>) {
    use core::fmt::Write as _;
    let _ = match result {
        None => writeln!(narf_console::Writer, "amdgpu: strix {stage:?}: start"),
        Some(Ok(())) => writeln!(narf_console::Writer, "amdgpu: strix {stage:?}: complete"),
        Some(Err(error)) => writeln!(
            narf_console::Writer,
            "amdgpu: strix {stage:?}: failed {error:?}"
        ),
    };
}

/// The five HWIP segment bases `mes_v11_0_set_hw_resources` reads
/// (`reg_offset[hw_ip][inst][i]`, i in 0..5): a missing segment contributes 0,
/// exactly what Linux passes, not a failure.
fn hw_segments(gpu: &AmdGpu, id: u16, versions: &[(u8, u8, u8)]) -> [u32; 5] {
    let mut out = [0u32; 5];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = bank(gpu, id, versions, i, 0)
            .ok()
            .and_then(|b| u32::try_from(b).ok())
            .unwrap_or(0);
    }
    out
}

impl StrixColdBoot {
    /// One Cap-invoked direct-MMIO call.
    fn access<T>(&mut self, f: impl FnOnce(&mut Mmio) -> Result<T, Error>) -> Result<T, Error> {
        let mut io = Mmio(self.gpu.regs);
        self.authority
            .invoke(Op(|| f(&mut io)))
            .map_err(|_| Error::Revoked)?
    }
    /// Apply a `Gfx11Sequence` through direct MMIO: writes go through the
    /// checked `write` helper, delays through `amdgpu::delay_us`. The
    /// sequence's addresses are already byte addresses
    /// (`gc_base + (dword_reg << 2)`).
    fn apply_sequence(&mut self, seq: &Gfx11Sequence) -> Result<(), Error> {
        self.access(|io| {
            for step in &seq.steps {
                match step {
                    GfxStep::Write { addr, value } => write(io, u64::from(*addr), *value)?,
                    GfxStep::Delay { us } => crate::amdgpu::delay_us(*us),
                }
            }
            Ok(())
        })
    }
    fn gc_power(
        smu: &mut Smu,
        banks: Banks,
        authority: Cap<BusDeviceCap, Write>,
        regs: MmioRegion,
    ) -> GcPower<'_> {
        GcPower {
            smu,
            banks,
            authority,
            regs,
        }
    }

    /// # Safety
    /// The owner is new, this display owner holds the whole GPU, and the
    /// RLC autoload has completed — the same contract as Raphael's `run`.
    pub(crate) async unsafe fn run(&mut self) -> Result<&Report, Error> {
        if !matches!(self.state, State::Prepared) {
            return Err(Error::Busy);
        }
        for stage in STAGES {
            self.state = State::Running(stage);
            progress(stage, None);
            let result = self.step(stage).await;
            progress(stage, Some(result));
            if let Err(error) = result {
                self.state = State::Failed { stage, error };
                return Err(error);
            }
            self.stages_completed += 1;
        }
        let report = Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            aperture: self.aperture.ok_or(Error::Invalid)?,
            gart_ready: self.gart_ready,
            sdma: self.sdma_proof.ok_or(Error::Invalid)?,
            queues: self.queue_proof.ok_or(Error::Invalid)?,
            mes: self.mes_proof.ok_or(Error::Invalid)?,
            topology: self.topology.ok_or(Error::Invalid)?,
            stages_completed: self.stages_completed,
        };
        self.state = State::Ready(report);
        Ok(match &self.state {
            State::Ready(report) => report,
            _ => unreachable!(),
        })
    }

    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::Smu => self.step_smu().await,
            Stage::MemoryHubs => self.step_memory_hubs().await,
            Stage::Gart => self.step_gart().await,
            Stage::Interrupts => self.step_interrupts().await,
            Stage::GoldenSettings => self.step_golden(),
            Stage::SdmaTest => self.step_sdma_test(),
            Stage::InterruptTest => self.step_interrupt_test().await,
            Stage::Doorbells => self.step_doorbells(),
            Stage::GfxSetup => self.step_gfx_setup().await,
            Stage::Kiq => self.step_kiq().await,
            Stage::ComputeQueues => self.step_compute_queues().await,
            Stage::GfxRing => self.step_gfx_ring().await,
            Stage::SdmaQueues => self.step_sdma_queues(),
            Stage::IbTests => self.step_ib_tests().await,
            Stage::FenceInterrupts => self.step_fence_interrupts(),
            Stage::ReadTopology => self.step_read_topology(),
        }
    }

    async fn step_smu(&mut self) -> Result<(), Error> {
        // Unlike Phoenix there is no known newer driver-IF to accept: the
        // engine refuses anything but exactly 0x7, so no mismatch-continue
        // logic applies here.
        let versions = self.smu.start().await.map_err(Error::Smu)?;
        self.smu.set_gfxoff(false).await.map_err(Error::Smu)?;
        self.versions = Some(versions);
        Ok(())
    }

    async fn step_memory_hubs(&mut self) -> Result<(), Error> {
        // SAFETY: trained VRAM, completed PSP/RLC startup, exclusive
        // ownership, automatic power gating still disabled (Smu stage ran).
        let aperture = unsafe { self.gmc.initialize().await }.map_err(Error::MemoryHubs)?;
        self.aperture = Some(aperture);
        Ok(())
    }

    async fn step_gart(&mut self) -> Result<(), Error> {
        // The Navi31 GMC has no separate `enable_gart`: GART is ready once
        // client contexts are prepared (VMIDs 1..15 at empty root).
        // SAFETY: same ownership as `initialize`.
        unsafe { self.gmc.prepare_client_contexts().await }.map_err(Error::MemoryHubs)?;
        if !self.gmc.state().vmid0_ready() {
            return Err(Error::Invalid);
        }
        self.gart_ready = true;
        Ok(())
    }

    async fn step_interrupts(&mut self) -> Result<(), Error> {
        // SAFETY: authenticated firmware, trained VRAM, ready GMC/MMHUB0.
        unsafe { self.ih.initialize(&self.gmc) }.map_err(Error::Interrupts)?;
        Ok(())
    }

    fn step_golden(&mut self) -> Result<(), Error> {
        // `gfx_v11_0_init_golden_registers`: the base 11.0.0 table only —
        // the 11.0.1 table does not apply to 11.5.0. `Gfx11Sequence` has
        // Write/Delay only (no RMW), so the read-modify-write is inline
        // against live reads.
        for entry in GOLDEN_11_0_0.iter() {
            let base = if entry.window == 0 {
                self.banks.gc0
            } else {
                self.banks.gc1
            };
            let addr = u64::from(base + entry.reg * 4);
            let (mask, value) = (entry.mask, entry.value);
            self.access(|io| {
                let live = read(io, addr)?;
                write(io, addr, (live & !mask) | (value & mask))
            })?;
        }
        Ok(())
    }

    fn step_sdma_test(&mut self) -> Result<(), Error> {
        let seq = crate::amdgpu_sdma::build_sdma6_ring_init(
            self.banks.sdma0,
            self.banks.gc1,
            self.sdma.ring.phys_addr(),
            crate::amdgpu_ring::RING_SIZE_DW as u32,
            self.sdma.ring.doorbell_index_dw(),
            self.sdma.rptr_phys(),
            self.sdma.wptr_poll_phys(),
        )
        .map_err(Error::Sdma)?;
        self.access(|io| {
            for w in seq.iter() {
                write(io, u64::from(w.addr), w.value)?;
            }
            Ok(())
        })?;
        let sdma0 = self.banks.sdma0;
        let rb_cntl = self.access(|io| {
            read(
                io,
                u64::from(sdma0 + crate::amdgpu_sdma::SDMA6_QUEUE0_RB_CNTL_REL),
            )
        })?;
        let rb_enabled = rb_cntl & crate::amdgpu_sdma::SDMA_RB_ENABLE != 0;
        if !rb_enabled {
            return Err(Error::Invalid);
        }
        self.sdma_proof = Some(SdmaProof { rb_enabled });
        Ok(())
    }

    async fn step_interrupt_test(&mut self) -> Result<(), Error> {
        // Arm the self-interrupt mechanism per `ih_v6_0_irq_init`
        // (IH_CNTL2 SELF_IV_FORCE_WPTR_UPDATE_TIMEOUT=8 + ENABLE, ring1
        // RB_USED_INT_THRESHOLD=0), drain, and verify a self-interrupt
        // entry arrives within a bounded budget. The exact self-IV vector
        // payload is NOT established — the stage checks for a ring1 entry
        // arriving, not a specific payload. No SDMA trap round-trip: that
        // needs an SDMA packet submitter.
        self.ih
            .set_self_interrupt(true)
            .map_err(Error::Interrupts)?;
        let deadline = narf_time::Deadline::after_ms(INTERRUPT_TEST_DEADLINE_MS);
        let mut seen = false;
        let mut result = Ok(());
        loop {
            match self.ih.drain() {
                Ok(batch) => {
                    if batch.events().any(|e| e.ih_ring == 1) {
                        seen = true;
                        break;
                    }
                }
                Err(e) => {
                    result = Err(Error::Interrupts(e));
                    break;
                }
            }
            if deadline.expired() {
                break;
            }
            narf_scheduler::yield_now().await;
        }
        // Always disarm, even on failure.
        let disarm = self.ih.set_self_interrupt(false);
        result?;
        disarm.map_err(Error::Interrupts)?;
        if !seen {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn step_doorbells(&mut self) -> Result<(), Error> {
        // NBIO doorbell aperture enable. The self-ring registers are NOT
        // written (NBIO 7.11 remainder — see the const doc above).
        let nbio = self.banks.nbio;
        self.access(|io| update(io, u64::from(nbio + NBIO_DOORBELL_APER_EN_REL), 0x1, 0x1))?;
        // CP doorbell range (`gfx_v11_0_cp_set_doorbell_range`).
        let seq = gfx::build_cp_set_doorbell_range(self.banks.gc0);
        self.apply_sequence(&seq)
    }

    async fn step_gfx_setup(&mut self) -> Result<(), Error> {
        let gc0 = self.banks.gc0;
        let gc1 = self.banks.gc1;
        // RLC start: `build_rlc_start` needs the live RLC_PG_CNTL and
        // RLC_CNTL (RLC_PG_CNTL SMU-handshake-disable bit 23 if !gfxoff;
        // RLC_CNTL | RLC_ENABLE_F32; 50 µs delay). RLC autoload already
        // completed before `run()` (per `new`'s contract).
        let (live_pg, live_cntl) = self.access(|io| {
            let pg = read(io, u64::from(gc1 + crate::amdgpu_cp_rdna3::RLC_PG_CNTL * 4))?;
            let cntl = read(io, u64::from(gc1 + crate::amdgpu_cp_rdna3::RLC_CNTL * 4))?;
            Ok((pg, cntl))
        })?;
        let rlc_seq =
            crate::amdgpu_cp_rdna3::build_rlc_start(gc1, live_pg, live_cntl, self.gfxoff_enabled);
        self.apply_sequence(&rlc_seq)?;
        // GFX ring 0: `build_gfx11_ring_init` (selects pipe 0 via live
        // GRBM_GFX_CNTL; `mdelay(1)` before the second CP_RB0_CNTL write).
        let grbm = self.access(|io| read(io, u64::from(gc1 + meshw::GRBM_GFX_CNTL * 4)))?;
        let doorbell_dw = u32::from(crate::amdgpu_ring::doorbell_assignment::GFX_RING0) << 1;
        let ring_seq = gfx::build_gfx11_ring_init(
            gc0,
            gc1,
            grbm,
            self.gfx.ring_phys(),
            (crate::amdgpu_ring::RING_SIZE_DW as u64) * 4,
            doorbell_dw,
            true,
            self.gfx.rptr_phys(),
            self.gfx.wptr_phys(),
        )
        .map_err(Error::Gfx)?;
        self.apply_sequence(&ring_seq)?;
        self.gfx.write_mqd().map_err(Error::Mqd)?;
        Ok(())
    }

    async fn step_kiq(&mut self) -> Result<(), Error> {
        let gc0 = self.banks.gc0;
        let gc1 = self.banks.gc1;
        // MES enable (both pipes, `kiq_pipe=true`): select me 3 / pipe 0,
        // read live CP_MES_CNTL, then the enable sequence (first CNTL write
        // is RMW asserting resets; second composed from zero setting
        // ACTIVE; 500 µs delay). `build_mes_enable` does not select before
        // its first CNTL write, so the coordinator selects first.
        let live_cntl = self.access(|io| {
            write(
                io,
                u64::from(gc1 + meshw::GRBM_GFX_CNTL * 4),
                meshw::grbm_select(meshw::MES_ME_ID, 0, 0, 0),
            )?;
            read(io, u64::from(gc1 + meshw::CP_MES_CNTL * 4))
        })?;
        let enable = meshw::build_mes_enable(gc1, live_cntl, self.mes_start, true, None)
            .ok_or(Error::Invalid)?;
        self.apply_sequence(&enable)?;
        // Firmware versions, per pipe (0 = not running). The reader handles
        // its own GRBM selection and restores it.
        // SAFETY: ColdBoot holds the GPU exclusively (&mut self) during
        // bring-up; the reader selects GRBM itself and restores it.
        let (sched, kiq) = unsafe { self.gpu.read_mes_fw_versions() }.ok_or(Error::Invalid)?;
        if !sched.is_running() || !kiq.is_running() {
            return Err(Error::Invalid);
        }
        // `gfx_v11_0_kiq_setting`: RLC_CP_SCHEDULERS low byte = (me<<5) |
        // (pipe<<3) | queue, | 0x80.
        let live_sched =
            self.access(|io| read(io, u64::from(gc1 + meshw::RLC_CP_SCHEDULERS * 4)))?;
        let want = crate::amdgpu_cp_rdna3::kiq_rlc_schedulers_value(live_sched);
        self.access(|io| write(io, u64::from(gc1 + meshw::RLC_CP_SCHEDULERS * 4), want))?;
        // Descriptors first, then the HQD registers for each pipe
        // (`mes_v11_0_queue_init_register`: live CP_HQD_VMID /
        // CP_HQD_PQ_DOORBELL_CONTROL read after the pipe's selection).
        self.mes_kiq.write_mqd().map_err(Error::Mes)?;
        self.mes_sched.write_mqd().map_err(Error::Mes)?;
        for pipe in [meshw::MES_KIQ_PIPE, meshw::MES_SCHED_PIPE] {
            let (live_vmid, live_doorbell) = self.access(|io| {
                write(
                    io,
                    u64::from(gc1 + meshw::GRBM_GFX_CNTL * 4),
                    meshw::grbm_select(meshw::MES_ME_ID, pipe, 0, 0),
                )?;
                let vmid = read(io, u64::from(gc0 + meshw::CP_HQD_VMID * 4))?;
                let doorbell = read(io, u64::from(gc0 + meshw::CP_HQD_PQ_DOORBELL_CONTROL * 4))?;
                Ok((vmid, doorbell))
            })?;
            let seq = if pipe == meshw::MES_KIQ_PIPE {
                self.mes_kiq
                    .queue_init_sequence(gc0, gc1, pipe, live_vmid, live_doorbell)
            } else {
                self.mes_sched
                    .queue_init_sequence(gc0, gc1, pipe, live_vmid, live_doorbell)
            };
            self.apply_sequence(&seq)?;
        }
        // SET_HW_RSRC via the sched pipe. `MesQueue::submit` pairs the
        // packet with a status query automatically; the API-status dword is
        // at frame offset 50 (`amdgpu_mes::set_hw_rsrc::API_STATUS`, private
        // module — the literal is pinned by the MES tests). The MMHUB
        // segment accepts both 3.0.1 and 3.0.2: whichever the part
        // reports is the one discovery lists.
        let mut res = self.mes_sched.hw_resources(&STRIX_TOPOLOGY);
        res.gc_base = hw_segments(&self.gpu, ip::HW_ID_GC, &[(11, 5, 0)]);
        res.mmhub_base = hw_segments(&self.gpu, ip::HW_ID_MMHUB, &[(3, 0, 1), (3, 0, 2)]);
        res.osssys_base = hw_segments(&self.gpu, ip::HW_ID_OSSSYS, &[(6, 0, 0)]);
        let mut packet = mes::build_set_hw_resources(&res);
        let bar2 = self.doorbells.region();
        // SAFETY: the doorbell region is this GPU's BAR2; the sched queue
        // is the coordinator's own.
        unsafe { self.mes_sched.submit(&mut packet, 50, &bar2) }.map_err(Error::Mes)?;
        // SET_HW_RSRC_1 (opcode 19) has no NARF builder: record the skip
        // rather than failing the boot for any firmware ≥ 0x52.
        let hw_rsrc_1_skipped = sched.version >= SET_HW_RSRC_1_MIN_VERSION;
        if hw_rsrc_1_skipped {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: strix MES sched version {:#x} ≥ {:#x}; SET_HW_RSRC_1 skipped (no builder)",
                sched.version,
                SET_HW_RSRC_1_MIN_VERSION
            );
        }
        self.mes_proof = Some(MesProof {
            sched_version: sched.version,
            kiq_version: kiq.version,
            legacy_queue_map: sched.enable_legacy_queue_map(),
            hw_rsrc_1_skipped,
        });
        Ok(())
    }

    async fn step_compute_queues(&mut self) -> Result<(), Error> {
        // One kernel compute ring (MEC 1, pipe 0, queue 0) through MES
        // `map_legacy_queue` (ADD_QUEUE + `map_legacy_kq = 1`). NOT the
        // legacy `KiqScheduler` MAP_QUEUES packet, and NOT MES `add_queue`
        // (needs KFD process/gang contexts).
        let args = self.compute.map_legacy_args();
        let bar2 = self.doorbells.region();
        // SAFETY: the doorbell region is this GPU's BAR2; the sched queue
        // is the coordinator's own.
        unsafe { self.mes_sched.map_legacy_queue(&args, &bar2) }.map_err(Error::Mes)?;
        Ok(())
    }

    async fn step_gfx_ring(&mut self) -> Result<(), Error> {
        // The GFX ring, same path as the compute ring.
        let args = self.gfx.map_legacy_args(0, 0);
        let bar2 = self.doorbells.region();
        // SAFETY: the doorbell region is this GPU's BAR2; the sched queue
        // is the coordinator's own.
        unsafe { self.mes_sched.map_legacy_queue(&args, &bar2) }.map_err(Error::Mes)?;
        Ok(())
    }

    fn step_sdma_queues(&mut self) -> Result<(), Error> {
        // Queue 0 IS the production queue (one SDMA instance), programmed
        // by SdmaTest; this stage re-verifies RB_CNTL still enabled after
        // the intervening stages and records the queue.
        let sdma0 = self.banks.sdma0;
        let rb_cntl = self.access(|io| {
            read(
                io,
                u64::from(sdma0 + crate::amdgpu_sdma::SDMA6_QUEUE0_RB_CNTL_REL),
            )
        })?;
        if rb_cntl & crate::amdgpu_sdma::SDMA_RB_ENABLE == 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    async fn step_ib_tests(&mut self) -> Result<(), Error> {
        let gc1 = self.banks.gc1;
        let scratch_dword = gfx::ring_test_scratch_dword(gc1).ok_or(Error::Invalid)?;
        let scratch_byte = u64::from(scratch_dword) * 4;
        let packet = gfx::build_ring_test_packet(gc1).ok_or(Error::Invalid)?;
        // SAFETY: the IB buffer is this coordinator's, 4 KiB,
        // identity-mapped; the packet is 3 dwords.
        unsafe {
            for (i, dw) in packet.iter().enumerate() {
                core::ptr::write_volatile(self.ib_buf.cpu_mut_ptr_at::<u32>((i * 4) as u64), *dw);
            }
        }
        // GFX ring test via IB.
        self.access(|io| write(io, scratch_byte, gfx::RING_TEST_SEED))?;
        // SAFETY: the GFX ring is the coordinator's own, bound in
        // step_gfx_setup and mapped in step_gfx_ring; this is its first
        // submission, so none overlaps.
        let fence = unsafe {
            self.gfx
                .submit_ib(self.ib_buf.dma_addr().raw(), packet.len() as u32)
        }
        .map_err(Error::Queues)?;
        let bar2 = self.doorbells.region();
        // SAFETY: the doorbell region is this GPU's BAR2; the GFX ring is
        // the coordinator's own.
        unsafe { self.gfx.commit(&bar2) };
        // The fence must complete AND the scratch register must hold
        // `RING_TEST_EXPECT`.
        let deadline = narf_time::Deadline::after_ms(IB_DEADLINE_MS);
        loop {
            if self.gfx.fence_completed(&fence) {
                let v = self.access(|io| read(io, scratch_byte))?;
                if v == gfx::RING_TEST_EXPECT {
                    break;
                }
            }
            if deadline.expired() {
                return Err(Error::Invalid);
            }
            narf_scheduler::yield_now().await;
        }
        let gfx_fence = fence.seq;
        // Compute ring test via IB (re-seed first — both rings write the
        // same scratch register).
        self.access(|io| write(io, scratch_byte, gfx::RING_TEST_SEED))?;
        // SAFETY: the compute ring is the coordinator's own, mapped
        // through MES in step_compute_queues; the GFX fence completed
        // above, so no submission overlaps.
        let cfence = unsafe {
            self.compute
                .submit_ib(self.ib_buf.dma_addr().raw(), packet.len() as u32)
        }
        .map_err(Error::Queues)?;
        // SAFETY: the doorbell region is this GPU's BAR2; the compute ring
        // is the coordinator's own.
        unsafe { self.compute.commit(&bar2) };
        let deadline = narf_time::Deadline::after_ms(IB_DEADLINE_MS);
        loop {
            if self.compute.fence_completed(&cfence) {
                let v = self.access(|io| read(io, scratch_byte))?;
                if v == gfx::RING_TEST_EXPECT {
                    break;
                }
            }
            if deadline.expired() {
                return Err(Error::Invalid);
            }
            narf_scheduler::yield_now().await;
        }
        let compute_fence = cfence.seq;
        // SDMA fence packet via queue 0.
        let dst = self.sdma.fence_phys();
        self.sdma.fence_seq += 1;
        let seq = self.sdma.fence_seq;
        let mut staging = [0u32; 8];
        let nwords = {
            let mut b = crate::amdgpu_sdma::SdmaBuilder::new(
                &mut staging,
                crate::amdgpu_sdma::SdmaGeneration::V6,
            );
            b.fence(dst, seq).map_err(Error::SdmaPkt)?;
            b.bytes_written() / 4
        };
        let rptr = self.sdma.rptr_observed();
        // SAFETY: the ring is the coordinator's own queue 0; `rptr` is the
        // live writeback value.
        unsafe { self.sdma.ring.submit(&staging[..nwords], rptr) }
            .map_err(|e| Error::Queues(e.into()))?;
        // SAFETY: the doorbell region is this GPU's BAR2.
        unsafe { self.sdma.ring.ring_doorbell(&bar2) };
        let deadline = narf_time::Deadline::after_ms(IB_DEADLINE_MS);
        loop {
            if self.sdma.fence_observed() >= seq {
                break;
            }
            if deadline.expired() {
                return Err(Error::Invalid);
            }
            narf_scheduler::yield_now().await;
        }
        self.queue_proof = Some(QueueProof {
            gfx_fence,
            compute_fence,
            sdma_fence: seq,
        });
        Ok(())
    }

    fn step_fence_interrupts(&mut self) -> Result<(), Error> {
        let gc0 = self.banks.gc0;
        let sdma0 = self.banks.sdma0;
        // EOP + fault interrupts on the GFX ring and the compute pipe.
        // Strix's IH is drain-based (no subscribe API), so fence waits
        // keep polling; these enables only shorten the waits.
        let ring0 = CP_INT_TIME_STAMP
            | CP_INT_GENERIC0
            | CP_INT_PRIV_REG
            | CP_INT_OPCODE_ERROR
            | CP_INT_PRIV_INSTR;
        let pipe0 = CP_INT_TIME_STAMP | CP_INT_GENERIC0 | CP_INT_PRIV_REG | CP_INT_OPCODE_ERROR;
        self.access(|io| {
            update(io, u64::from(gc0 + CP_INT_CNTL_RING0 * 4), ring0, ring0)?;
            update(io, u64::from(gc0 + CP_ME1_PIPE0_INT_CNTL * 4), pipe0, pipe0)?;
            update(
                io,
                u64::from(sdma0 + SDMA0_CNTL_REL),
                SDMA_TRAP_ENABLE,
                SDMA_TRAP_ENABLE,
            )
        })
    }

    fn step_read_topology(&mut self) -> Result<(), Error> {
        // SAFETY: same exclusive ownership as `new`; reads GC registers and
        // the NBIO strap.
        let topology =
            unsafe { topo11::read_strix(&self.gpu, &self.authority) }.map_err(Error::Topology)?;
        self.topology = Some(topology);
        Ok(())
    }

    /// `amdgpu_device_ip_late_init` once graphics serves clients: RLC power
    /// gating on, then GFXOFF allowed [`gfxoff::DELAY_MS`] later. There is no
    /// clock-gating owner yet, so the clocks stay ungated. A second GATE
    /// does nothing.
    pub(crate) async fn gate_gfx(&mut self) -> Result<(), Error> {
        if !self.queues_verified() {
            return Err(Error::Busy);
        }
        // GFX is powered: the count is still 1 until the GATE below.
        let mut hw = Self::gc_power(&mut self.smu, self.banks, self.authority, self.gpu.regs);
        let allow = self.gfxoff.gate(&mut hw).await.map_err(Error::GfxOff)?;
        schedule(allow);
        Ok(())
    }
    /// `amdgpu_device_ip_suspend_phase1`, before S3 and before a mode 2
    /// reset: `set_pg_state(UNGATE)` (GFXOFF disallowed, then RLC power
    /// gating off). GFX is powered on `Ok`. There is no clock-gating owner
    /// to ungate.
    #[allow(
        dead_code,
        reason = "no Strix S3/s0ix path calls the ungate yet; prepare_graphics_s0ix ungates Raphael's coordinator"
    )]
    pub(crate) async fn ungate_gfx(&mut self) -> Result<(), Error> {
        let mut hw = Self::gc_power(&mut self.smu, self.banks, self.authority, self.gpu.regs);
        self.gfxoff.ungate(&mut hw).await.map_err(Error::GfxOff)
    }
    /// `amdgpu_device_delay_enable_gfx_off` for an allow this coordinator
    /// scheduled; `Ok(false)` when it was cancelled or is from a lifetime
    /// before a re-arm.
    pub(crate) async fn delayed_gfx_off(&mut self, allow: gfxoff::Allow) -> Result<bool, Error> {
        let mut hw = Self::gc_power(&mut self.smu, self.banks, self.authority, self.gpu.regs);
        self.gfxoff
            .delayed(allow, &mut hw)
            .await
            .map_err(Error::GfxOff)
    }
    /// `amdgpu_device_prepare`'s flush of the delayed GFXOFF allow.
    #[allow(
        dead_code,
        reason = "no Strix s0ix path calls the flush yet; prepare_graphics_s0ix flushes Raphael's coordinator"
    )]
    pub(crate) async fn flush_gfx_off(&mut self) -> Result<bool, Error> {
        let mut hw = Self::gc_power(&mut self.smu, self.banks, self.authority, self.gpu.regs);
        self.gfxoff.flush(&mut hw).await.map_err(Error::GfxOff)
    }
    /// Quiesce for a mode 2 reset: disable the IH rings. No client queues
    /// exist yet (no submitter), so there is nothing else to park. The
    /// coordinator is spent after [`Self::mode2_reset`]; the platform must
    /// retire it (rebuild-only recovery — there is no `rearm`, because the
    /// rings' host write pointers live in contexts with no reset API).
    #[allow(
        dead_code,
        reason = "no Strix recovery lane calls the quiesce yet; recover() has no Strix arm"
    )]
    pub(crate) async fn quiesce_for_reset(&mut self) -> Result<(), Error> {
        self.ih.disable().map_err(Error::Interrupts)
    }
    /// PMFW mode-2 reset via the SMU (`GfxDeviceDriverReset`, MODE2). The
    /// scratch3 save/restore + memsize wrapper Raphael's `mode2` performs is
    /// a flagged remainder: it needs the Strix NBIO 7.11 banks, and NARF
    /// has no NBIO 7.11 owner.
    #[allow(
        dead_code,
        reason = "no Strix recovery lane calls the reset yet; recover() has no Strix arm"
    )]
    pub(crate) async fn mode2_reset(&mut self) -> Result<(), Error> {
        // SAFETY: exclusive ownership; the GPU is quiesced.
        unsafe { self.smu.mode2_reset().await }.map_err(Error::Smu)
    }
}

/// Deliver a delayed GFXOFF allow to the platform's Strix scheduler.
fn schedule(allow: Option<gfxoff::Allow>) {
    if let Some(allow) = allow {
        crate::amdgpu_platform::schedule_gfx_off_strix(allow);
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_strix_boot_tests.rs"]
mod tests;

//! Raphael (GC 10.3.6) graphics cold boot.
//!
//! It runs after the display path's PSP session has loaded the graphics set
//! and the RLC autoload has completed (`amdgpu_platform` hands the set to
//! `amdgpu_dmub_boot::Loader`, which loads it in Linux's `psp_load_non_psp_fw`
//! order). Raphael's PSP secure OS and PMFW are BIOS-resident, and its memory
//! is the carve-out, so none of the discrete cold boot's reset, training, SOS,
//! SMC or power-table stages exist here. What remains follows Linux's
//! `amdgpu_device_ip_init` order on GC 10.3:
//! - SMU (`smu_hw_init`);
//! - GMC with its GART (`gmc_v10_0_hw_init`);
//! - IH (phase 1);
//! - the GFX golden settings and SDMA (phase 2);
//! - the CP's KIQ, compute and GFX rings and the SDMA queues;
//! - `amdgpu_ib_ring_tests`;
//! - the GFX constants' topology read.
//!
//! Each engine is the discrete RDNA2 owner through its Raphael resolution:
//! `Gmc::new_raphael`, `Ih::new_raphael`, `Sdma::new_raphael`,
//! `Gfx::new_raphael`, `Compute::new_raphael` and the SDMA queues'.
//!
//! GFXOFF is disallowed before any GC register is touched. Linux starts with
//! its GFXOFF request count at one, so PMFW never powers GFX down during
//! `hw_init`; sending `DisallowGfxOff` makes that independent of how the BIOS
//! left PMFW. Once clients are served the display owner gates GFX
//! (`gate_gfx`: power gating, then GFXOFF after its delay, see
//! `amdgpu_raphael_gfxoff`), and ungates it before S3 or a mode 2 reset.
//!
//! Construction reserves memory and maps the doorbell page but performs no
//! register I/O. A failure stops the sequence at its stage; the display path
//! that preceded it is unaffected. After a completed run the display owner
//! hands the verified queues to clients (`amdgpu_navi22_cs::register_raphael`,
//! through `amdgpu_rdna2_client`).
use crate::amdgpu_navi22_gating as gating;
use crate::amdgpu_raphael_gfxoff as gfxoff;
use crate::{
    amdgpu::AmdGpu, amdgpu_cp_navi22 as cp, amdgpu_gmc_navi22 as gmc, amdgpu_ih_navi22 as ih,
    amdgpu_kiq_navi22 as kiq, amdgpu_sdma_navi22 as sdma, amdgpu_sdma_navi22_queues as sdma_queues,
    amdgpu_smu_raphael as smu, amdgpu_vcn_navi22 as vcn, amdgpu_vram::Pool,
};
use alloc::boxed::Box;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

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
/// The order is the substance, as in the discrete cold boot:
/// - the SMU first, so GFXOFF is disallowed before GC is touched;
/// - VMID0 and the GART before anything the engines fetch;
/// - IH before any engine that interrupts;
/// - golden settings before SDMA (`gfx_v10_0_hw_init` precedes
///   `sdma_v5_2_start` in phase 2);
/// - the SDMA0 proof and its trap round trip before the production queues
///   take SDMA over;
/// - the rings before the IB tests, and fences armed only after the proofs.
pub const STAGES: [Stage; 16] = [
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
/// INT_CONTEXT of the boot SDMA0 TRAP round trip.
const TRAP_CONTEXT: u32 = 0x0675_0022; // linux: n/a (NARF-chosen TRAP INT_CONTEXT tag)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Invalid,
    Allocation,
    /// The display path did not load the graphics set and boot the RLC.
    NoFirmware,
    Smu(smu::Error),
    MemoryHubs(gmc::Error),
    Interrupts(ih::Error),
    Sdma(sdma::Error),
    Queues(cp::Error),
    Topology(crate::amdgpu_gfx10_topology::Error),
    Media(vcn::Error),
    /// A GFXOFF transition failed; GFX power is unknown.
    GfxOff(gfxoff::Error),
    /// A clock-gating transition failed or the gating owner is missing.
    ClockGating(gating::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    pub aperture: gmc::Aperture,
    pub gart: Option<gmc::GartInfo>,
    pub sdma: sdma::Proof,
    pub queues: cp::QueueProof,
    pub topology: crate::amdgpu_gfx10_topology::Topology,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "boot state snapshots remain Copy and allocation-free, as Navi22's"
)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    Failed { stage: Stage, error: Error },
}

/// Every Raphael graphics owner, retained through success and failure so no
/// published memory is released while an engine may still reach it.
#[derive(Debug)]
pub struct ColdBoot {
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    /// VCN and JPEG, once `run_media` has reserved them.
    media: Option<Box<vcn::Media>>,
    smu: smu::Smu,
    // Boxed: the owners are large, and a coordinator holding them inline
    // would put all of them in every frame and future that holds it.
    gmc: Box<gmc::Gmc>,
    ih: Box<ih::Ih>,
    sdma: Box<sdma::Sdma>,
    doorbells: cp::Doorbells,
    gfx: Box<cp::Gfx>,
    compute: Box<kiq::Compute>,
    queues: Box<sdma_queues::Sdma>,
    versions: Option<smu::Versions>,
    aperture: Option<gmc::Aperture>,
    proof: Option<sdma::Proof>,
    topology: Option<crate::amdgpu_gfx10_topology::Topology>,
    state: State,
    /// GFX power gating and GFXOFF for this lifetime (`amdgpu_raphael_gfxoff`).
    gfxoff: gfxoff::GfxOff,
    /// Clock gating (`amdgpu_device_set_cg_state`); `None` if its banks did
    /// not resolve, and the clocks then stay ungated.
    gating: Option<gating::Gating>,
    /// `adev->pg_flags` and `cg_flags`: [`gating::RAPHAEL_PG`] and
    /// [`gating::RAPHAEL_CG`] under `amdgpu.pg_mask` and `amdgpu.cg_mask`
    /// (`amdgpu_device_ip_early_init`). The media owner reads both.
    pg_flags: u32,
    cg_flags: u64,
}
/// PMFW's GFXOFF messages and RLC's power gating, for `gfxoff`.
struct GcPower<'a> {
    smu: &'a mut smu::Smu,
    gfx: &'a mut cp::Gfx,
}
impl crate::amdgpu_navi22_gfxoff::Control for GcPower<'_> {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        self.smu.set_gfxoff(allow).await.map_err(drop)
    }
}
impl gfxoff::PowerGating for GcPower<'_> {
    async fn set_power_gating(&mut self, enable: bool) -> Result<(), ()> {
        self.gfx.set_power_gating(enable).await.map_err(drop)
    }
}
impl ColdBoot {
    /// Reserve every owner: no register I/O. Refused unless every engine
    /// resolves Raphael's layout.
    ///
    /// # Safety
    /// The caller exclusively owns this Raphael GPU's graphics engines (GC,
    /// SDMA, the memory hubs, IH, the SMU graphics mailbox, NBIO's doorbell
    /// apertures), its PCI interrupt capabilities and BAR2, the permanent
    /// register mapping, and `pool`'s free carve-out memory, which the display
    /// path shares. The PSP has loaded the graphics set and the RLC autoload
    /// completed; no other graphics owner, client, reset or PM transition runs.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: BusDevice,
    ) -> Result<Self, Error> {
        if crate::amdgpu_rdna2::apu_for_pci_id(gpu.chip.vid, gpu.chip.did)
            != Some(&crate::amdgpu_rdna2::RAPHAEL)
        {
            return Err(Error::Invalid);
        }
        let gpu = snapshot(gpu)?;
        // SAFETY: forwarded exclusive ownership; every constructor below only
        // validates layouts, reserves memory or maps BAR2.
        unsafe {
            let smu = smu::Smu::new(&gpu, authority).map_err(Error::Smu)?;
            let mut gmc =
                gmc::Gmc::new_raphael(&gpu, authority, pool).map_err(Error::MemoryHubs)?;
            gmc.prepare_gart().map_err(Error::MemoryHubs)?;
            let ih =
                ih::Ih::new_raphael(&gpu, authority, pool, device).map_err(Error::Interrupts)?;
            let sdma = sdma::Sdma::new_raphael(&gpu, authority, pool).map_err(Error::Sdma)?;
            let doorbells = cp::Doorbells::map_raphael(&device).map_err(Error::Queues)?;
            let gfx =
                cp::Gfx::new_raphael(&gpu, authority, pool, doorbells).map_err(Error::Queues)?;
            let compute = kiq::Compute::new_raphael(&gpu, authority, pool, doorbells)
                .map_err(Error::Queues)?;
            let queues = sdma_queues::Sdma::new_raphael(&gpu, authority, pool, doorbells)
                .map_err(Error::Queues)?;
            let options = crate::amdgpu_rdna2::options::BootOptions::parse(narf_boot::args().raw());
            let pg_flags = gating::RAPHAEL_PG & options.pg_mask;
            let cg_flags = gating::RAPHAEL_CG & u64::from(options.cg_mask);
            // This coordinator alone writes the gating registers; no access.
            let gating = match gating::Gating::new_raphael(&gpu, authority, options.cg_mask) {
                Ok(gating) => Some(gating),
                Err(error) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: raphael clock gating unavailable: {error:?}"
                    );
                    None
                }
            };
            Ok(Self {
                gpu,
                authority,
                pool: pool.clone(),
                media: None,
                smu,
                gmc: Box::new(gmc),
                ih: Box::new(ih),
                sdma: Box::new(sdma),
                doorbells,
                gfx: Box::new(gfx),
                compute: Box::new(compute),
                queues: Box::new(queues),
                versions: None,
                aperture: None,
                proof: None,
                topology: None,
                state: State::Prepared,
                gfxoff: gfxoff::GfxOff::new(options.gfxoff, pg_flags & gating::pg::GFX_PG != 0),
                gating,
                pg_flags,
                cg_flags,
            })
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// The live memory-hub owner after a completed boot.
    pub fn memory(&mut self) -> Option<&mut gmc::Gmc> {
        matches!(self.state, State::Ready(_)).then_some(&mut *self.gmc)
    }

    // ── Client work (amdgpu_navi22_cs through amdgpu_rdna2_client) ──────
    /// A completed run: every kernel queue passed its ring and IB tests.
    pub fn queues_verified(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }
    /// Queue a client job on a verified kernel queue, as Navi22's owner does.
    pub(crate) fn submit(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
        state: &mut crate::amdgpu_navi22_submit::RingState,
        vm: crate::amdgpu_navi22_submit::VmRef,
        context: u64,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
    ) -> Result<u32, cp::Error> {
        use crate::amdgpu_navi22_submit::Ring;
        if !self.queues_verified() {
            return Err(cp::Error::DeviceGone);
        }
        if ring == Ring::Compute {
            state.configure_gds(self.gpu.gc_info);
        }
        match ring {
            Ring::Gfx => self.gfx.submit(state, vm, context, ibs),
            Ring::Compute => self.compute.submit(state, vm, context, ibs),
            Ring::Sdma(i) => self.queues.submit(i, state, vm, context, ibs),
        }
    }
    pub(crate) fn fences(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
    ) -> Result<(u32, u32), cp::Error> {
        use crate::amdgpu_navi22_submit::Ring;
        if !self.queues_verified() {
            return Err(cp::Error::DeviceGone);
        }
        match ring {
            Ring::Gfx => self.gfx.fences(),
            Ring::Compute => self.compute.fences(),
            Ring::Sdma(i) => self.queues.fences(i),
        }
    }
    /// Lock-free fence reader over the verified kernel queues. Raphael's one
    /// SDMA leaves the other SDMA slots absent, so no client reaches them.
    pub fn client_fence_reader(&self) -> Option<cp::FenceReader> {
        if !self.queues_verified() {
            return None;
        }
        Some(self.gfx.fence_reader([
            Some(self.gfx.fence_map()),
            Some(self.compute.fence_map()),
            self.queues.fence_map(0),
            self.queues.fence_map(1),
            self.queues.fence_map(2),
            self.queues.fence_map(3),
        ]))
    }
    /// Lend the GFXHUB client VMIDs (1..`first_kfd_vmid`), as Navi22 does.
    pub fn reserve_client_vmids(&mut self) -> Result<gmc::ClientVmids, Error> {
        self.memory()
            .ok_or(Error::Busy)?
            .reserve_client_vmids()
            .map_err(Error::MemoryHubs)
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
    /// The hang watchdog's sample (`amdgpu_navi22_tdr`): each verified
    /// queue's emitted and signalled sequences, from fence writeback memory.
    pub(crate) fn queue_progress(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_tdr::Progress>, cp::Error> {
        if !self.queues_verified() {
            return Err(cp::Error::Busy);
        }
        let mut samples = alloc::vec::Vec::new();
        samples
            .try_reserve_exact(4)
            .map_err(|_| cp::Error::Allocation)?;
        samples.push(self.gfx.progress()?);
        samples.extend(self.compute.progress()?);
        samples.extend(self.queues.progress()?);
        Ok(samples)
    }
    /// `amdgpu_ring_soft_recovery` on `ring` (GFX or compute): kill VMID
    /// `vmid`'s waves until the job with sequence `seq` signals, for 10 ms at
    /// most. True once it has.
    pub(crate) async fn soft_recovery(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
        vmid: u8,
        seq: u32,
    ) -> Result<bool, cp::Error> {
        use crate::amdgpu_navi22_submit::Ring;
        const DEADLINE_NS: u64 = 10_000_000; // linux: n/a (ktime_add_us(ktime_get(), 10000))
        if !matches!(ring, Ring::Gfx | Ring::Compute) {
            return Err(cp::Error::Invalid);
        }
        let deadline = narf_time::monotonic_ns().saturating_add(DEADLINE_NS);
        loop {
            let (completed, _) = self.fences(ring)?;
            if crate::amdgpu_fence_navi22::signaled(completed, seq) {
                return Ok(true);
            }
            if narf_time::monotonic_ns() >= deadline {
                return Ok(false);
            }
            self.gfx.kill_waves(vmid).await?;
            narf_scheduler::yield_now().await;
        }
    }
    /// `amdgpu_ring_reset`: `gfx_v10_0_reset_kcq` for the compute ring,
    /// `gfx_v10_0_reset_kgq` for GFX ring 0 (its timed-out job's VMID `vmid`;
    /// a kernel job's VMID 0 is refused). SDMA 5.2's queue reset needs a PMFW
    /// message 13.0.5 lacks, so it is refused. Every job the ring held is
    /// dropped; [`Self::force_complete`] then shows its fences done.
    pub(crate) async fn reset_queue(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
        vmid: u8,
    ) -> Result<(), cp::Error> {
        use crate::amdgpu_navi22_submit::Ring;
        if !self.queues_verified() {
            return Err(cp::Error::Busy);
        }
        match ring {
            Ring::Compute => self.compute.reset_compute().await,
            Ring::Gfx if vmid != 0 => {
                let map = self.gfx.begin_reset()?;
                if let Err(error) = self.compute.reset_gfx_vmid(vmid, map).await {
                    self.gfx.fail_reset();
                    return Err(error);
                }
                self.gfx.restore_queue()?;
                if let Err(error) = self.compute.remap_gfx(map).await {
                    self.gfx.fail_reset();
                    return Err(error);
                }
                self.gfx.end_reset().await
            }
            Ring::Gfx | Ring::Sdma(_) => Err(cp::Error::Unsupported),
        }
    }
    /// `amdgpu_fence_driver_force_completion` for a reset `ring`.
    pub(crate) fn force_complete(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
    ) -> Result<(), cp::Error> {
        use crate::amdgpu_navi22_submit::Ring;
        match ring {
            Ring::Compute => self.compute.force_complete_compute(),
            Ring::Gfx => self.gfx.force_complete(),
            Ring::Sdma(_) => Err(cp::Error::Unsupported),
        }
    }
    /// GC registers after a graphics timeout (`gfx_v10_ip_dump`), with
    /// GFXOFF disallowed for the reads.
    pub(crate) async fn gfx_hang_snapshot(&mut self) -> Result<cp::GfxHangSnapshot, cp::Error> {
        if !self.queues_verified() {
            return Err(cp::Error::Busy);
        }
        self.hold_gc().await.map_err(|_| cp::Error::Busy)?;
        let snapshot = self.gfx.hang_snapshot();
        self.release_gc();
        snapshot
    }
    /// `amdgpu_device_ip_late_init` once graphics serves clients:
    /// `set_cg_state(GATE)` over every block, then
    /// `gfx_v10_0_set_powergating_state(GATE)` (RLC power gating on, then
    /// GFXOFF allowed [`gfxoff::DELAY_MS`] later). A clock-gating failure is
    /// returned after power gating ran; a second GATE does nothing.
    pub(crate) async fn gate_gfx(&mut self) -> Result<(), Error> {
        if !self.queues_verified() {
            return Err(Error::Busy);
        }
        // GFX is powered: the count is still 1 until the GATE below.
        let clocks = self.set_clock_gating(true).await;
        let mut hw = GcPower {
            smu: &mut self.smu,
            gfx: &mut self.gfx,
        };
        let allow = self.gfxoff.gate(&mut hw).await.map_err(Error::GfxOff)?;
        schedule(allow);
        clocks
    }
    /// `amdgpu_device_ip_suspend_phase1`, before S3 and before a mode 2
    /// reset: `set_pg_state(UNGATE)` (GFXOFF disallowed, then RLC power
    /// gating off), then `set_cg_state(UNGATE)` in reverse block order. GFX
    /// is powered on `Ok`.
    pub(crate) async fn ungate_gfx(&mut self) -> Result<(), Error> {
        let mut hw = GcPower {
            smu: &mut self.smu,
            gfx: &mut self.gfx,
        };
        self.gfxoff.ungate(&mut hw).await.map_err(Error::GfxOff)?;
        self.set_clock_gating(false).await
    }
    /// `amdgpu_device_set_cg_state` over every block. GFX must be powered.
    async fn set_clock_gating(&mut self, gate: bool) -> Result<(), Error> {
        let Some(gating) = self.gating.as_mut() else {
            return Ok(());
        };
        let all = gating::Blocks::SOC.union(gating::Blocks::GFX);
        let ungated = gating.state() == gating::State::Idle
            || gating.state() == gating::State::Gated(gating::Blocks::NONE);
        if (!gate && ungated) || (gate && gating.state() == gating::State::Gated(all)) {
            return Ok(());
        }
        // SAFETY: the coordinator owns every gated block; GFXOFF is
        // disallowed for the call (the count is 1 before GATE, and UNGATE
        // ran first), RLC runs once the rings are verified, and
        // `amdgpu.cg_mask` admitted the flags.
        unsafe { gating.set_clockgating(gate, all) }
            .await
            .map_err(Error::ClockGating)
    }
    /// `amdgpu_device_delay_enable_gfx_off` for an allow this coordinator
    /// scheduled; `Ok(false)` when it was cancelled or is from a lifetime
    /// before a re-arm.
    pub(crate) async fn delayed_gfx_off(&mut self, allow: gfxoff::Allow) -> Result<bool, Error> {
        let mut hw = GcPower {
            smu: &mut self.smu,
            gfx: &mut self.gfx,
        };
        self.gfxoff
            .delayed(allow, &mut hw)
            .await
            .map_err(Error::GfxOff)
    }
    /// `amdgpu_gfx_off_ctrl(false)` around a driver read of GC registers.
    async fn hold_gc(&mut self) -> Result<(), Error> {
        let mut hw = GcPower {
            smu: &mut self.smu,
            gfx: &mut self.gfx,
        };
        self.gfxoff.hold(&mut hw).await.map_err(Error::GfxOff)
    }
    /// The read's `amdgpu_gfx_off_ctrl(true)`.
    fn release_gc(&mut self) {
        match self.gfxoff.release() {
            Ok(allow) => schedule(allow),
            Err(error) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael GFXOFF release {error:?}"
                );
            }
        }
    }
    /// Every engine owner back to Prepared on its own reservations after a
    /// reset, so `run` (and `run_media`) bring the same buffers up again:
    /// Linux's hw_init over its existing BOs, where building a new
    /// coordinator would quarantine these and leak them each cycle. A fresh
    /// SMU mailbox; the IH ring keeps its MSI vector.
    ///
    /// # Safety
    /// The GPU was reset (mode 2, or S3's power-off) since these owners last
    /// ran, `quiesce_for_reset` completed, no future of theirs is alive, and
    /// the PSP session has loaded the graphics set again.
    pub(crate) async unsafe fn rearm(&mut self) -> Result<(), Error> {
        // SAFETY: the coordinator owns the graphics mailbox, as `new`'s
        // contract gave it; the old handle is dropped here.
        self.smu = unsafe { smu::Smu::new(&self.gpu, self.authority) }.map_err(Error::Smu)?;
        // SAFETY: forwarded; every owner was reset with the device.
        unsafe {
            self.gmc.rearm().map_err(Error::MemoryHubs)?;
            self.ih.rearm().await.map_err(Error::Interrupts)?;
            self.sdma.rearm();
            self.gfx.rearm();
            self.compute.rearm();
            self.queues.rearm();
            if let Some(media) = self.media.as_mut() {
                media.rearm();
            }
        }
        self.versions = None;
        self.aperture = None;
        self.proof = None;
        self.topology = None;
        self.state = State::Prepared;
        // A new lifetime: the count back at 1 (the SMU stage disallows), and
        // a delayed allow from before lands nowhere.
        self.gfxoff = self.gfxoff.renewed();
        if let Some(gating) = self.gating.as_mut() {
            // SAFETY: forwarded; the reset left every gating register at its
            // default and no transition is in flight.
            unsafe { gating.rearm() };
        }
        Ok(())
    }
    /// Recovery's quiesce before a mode 2 reset (Navi22's `quiesce_for_reset`):
    /// the IH ring disabled, so every subscriber ends, and quarantined with
    /// its vector. The engines are left to the reset.
    ///
    /// # Safety
    /// Recovery's contract: no client work is admitted, and the owner is
    /// rebuilt rather than reused after the reset.
    pub(crate) async unsafe fn quiesce_for_reset(&mut self) -> Result<(), Error> {
        // SAFETY: forwarded; nothing depends on IH delivery any more.
        unsafe { self.ih.disable() }
            .await
            .map_err(Error::Interrupts)
    }
    /// `nv_asic_mode2_reset` through this owner's SMU mailbox and `device`,
    /// its PCI function. The owner is spent afterwards until `rearm`
    /// returns it to Prepared (or, if that fails, keep it, its memory
    /// quarantined, and build a new one).
    ///
    /// # Safety
    /// `quiesce_for_reset` completed, the PSP released its TMR, and the
    /// caller rebuilds every engine before use (`amdgpu_raphael_reset::mode2`).
    pub(crate) async unsafe fn mode2_reset(
        &mut self,
        device: &BusDevice,
    ) -> Result<(), crate::amdgpu_raphael_reset::Error> {
        self.state = State::Failed {
            stage: Stage::Smu,
            error: Error::Busy,
        };
        // SAFETY: forwarded.
        unsafe {
            crate::amdgpu_raphael_reset::mode2(&self.gpu, &self.authority, device, &mut self.smu)
        }
        .await
    }
    /// Client media rings (bit `MediaRing::index()`) and their fence reader,
    /// once `run_media` started VCN and JPEG.
    pub fn client_media(&self) -> Option<(u8, vcn::MediaFenceReader)> {
        let media = self.media.as_ref()?;
        let rings = media.client_rings();
        (rings != 0).then(|| (rings, media.fence_reader()))
    }
    /// `amdgpu_vcn_ring_begin_use` (power VCN up and restart it after an idle
    /// gate), then the client job. `psp` is the session that loaded VCN.
    pub(crate) async fn submit_media(
        &mut self,
        psp: &mut crate::amdgpu_psp_ring::Psp,
        ring: crate::amdgpu_navi22_submit::MediaRing,
        vm: crate::amdgpu_navi22_submit::VmRef,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
        copies: &[alloc::vec::Vec<u32>],
    ) -> Result<u32, vcn::Error> {
        let media = self.media.as_mut().ok_or(vcn::Error::Invalid)?;
        let mut power = MediaPower {
            smu: &mut self.smu,
            psp,
        };
        media
            .begin_use(&mut power, ring, narf_time::monotonic_ns())
            .await?;
        media.submit(ring, vm, ibs, copies)
    }
    pub(crate) fn media_fences(
        &mut self,
        ring: crate::amdgpu_navi22_submit::MediaRing,
    ) -> Result<(u32, u32), vcn::Error> {
        self.media
            .as_mut()
            .ok_or(vcn::Error::Invalid)?
            .client_fences(ring)
    }
    /// The VCN idle work: stop VCN and send `PowerDownVcn` once its rings are
    /// idle (`amdgpu_vcn_idle_work_handler`). JPEG stays up, as on Navi22.
    pub(crate) async fn idle_media(
        &mut self,
        psp: &mut crate::amdgpu_psp_ring::Psp,
        now: u64,
    ) -> Result<bool, vcn::Error> {
        let Some(media) = self.media.as_mut() else {
            return Ok(false);
        };
        let mut power = MediaPower {
            smu: &mut self.smu,
            psp,
        };
        media.idle(&mut power, now).await
    }
    pub(crate) fn media_idle_recheck(&self, now: u64) -> Option<u64> {
        self.media.as_ref()?.idle_recheck(now)
    }
    /// Whether every media ring signalled its last job (no media: true).
    pub(crate) fn media_signalled(&mut self) -> Result<bool, vcn::Error> {
        self.media
            .as_mut()
            .map_or(Ok(true), |media| media.fences_signalled())
    }
    /// S3's `vcn_v3_0_suspend`: VCN and JPEG stopped and each VCPU BO saved,
    /// so the resume's media start puts the firmware's sessions back.
    /// `Ok(false)`: no media owner.
    pub(crate) async fn suspend_media(&mut self) -> Result<bool, vcn::Error> {
        let Some(media) = self.media.as_mut() else {
            return Ok(false);
        };
        media.suspend().await.map(|()| true)
    }
    /// Whether the last media start carried the firmware's sessions over.
    pub(crate) fn media_sessions_restored(&self) -> bool {
        self.media
            .as_ref()
            .is_some_and(|media| media.sessions_restored())
    }
    /// Drop a saved VCPU BO, so the next media start begins with no
    /// sessions (a recovery's).
    pub(crate) fn forget_media_sessions(&mut self) {
        if let Some(media) = self.media.as_mut() {
            media.forget_saved();
        }
    }
    /// `AMDGPU_INFO_READ_MMR_REG` from nv.c's allow-list, with GFXOFF
    /// disallowed for the reads, as `amdgpu_info_ioctl` does.
    pub(crate) async fn read_mmr(
        &mut self,
        payload: [u32; 4],
        cached_gb: Option<u32>,
    ) -> Result<alloc::vec::Vec<u8>, narf_filesystem::FsError> {
        if !self.queues_verified() {
            return Err(narf_filesystem::FsError::NoDevice);
        }
        self.hold_gc()
            .await
            .map_err(|_| narf_filesystem::FsError::NoDevice)?;
        let reply = crate::amdgpu_rdna2_mmr::read(&self.gpu, &self.authority, payload, cached_gb);
        self.release_gc();
        reply
    }
    /// Run every stage once. A failed or cancelled run cannot be replayed:
    /// the state records the stage before it starts.
    ///
    /// # Safety
    /// The contract of `new` still holds, and the RLC autoload has completed.
    pub async unsafe fn run(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        for stage in STAGES {
            self.state = State::Running(stage);
            progress(stage, None);
            // SAFETY: forwarded; stages run strictly in STAGES order.
            let result = unsafe { self.step(stage) }.await;
            progress(stage, Some(result));
            if let Err(error) = result {
                self.state = State::Failed { stage, error };
                return Err(error);
            }
        }
        let report = self.report()?;
        self.state = State::Ready(report);
        Ok(report)
    }
    /// Bring VCN and JPEG up after a completed `run`: `smu_hw_init`'s APU
    /// power-up (`PowerUpVcn`, `PowerUpJpeg`; VCN is power gated by default,
    /// and Linux sends both whatever `pg_flags` hold), then `vcn_v3_0_hw_init`
    /// in DPG mode with `psp`, the session that loaded the VCN image, writing
    /// its register lists (the static path without `AMD_PG_SUPPORT_VCN_DPG`),
    /// then JPEG, then the
    /// interrupt routes and the decode/encode/JPEG IB tests. Failing here
    /// leaves the graphics engines and the display as they are.
    ///
    /// # Safety
    /// The contract of `new`, a completed `run`, and `psp` the session that
    /// loaded `firmware`'s VCN image, still holding its TMR.
    pub async unsafe fn run_media(
        &mut self,
        psp: &mut crate::amdgpu_psp_ring::Psp,
        firmware: crate::amdgpu_psp_ring::MediaFirmware,
        vcn_bytes: usize,
    ) -> Result<vcn::Status, Error> {
        use core::fmt::Write as _;
        if !matches!(self.state, State::Ready(_)) {
            return Err(Error::Busy);
        }
        self.smu.set_vcn_power(true).await.map_err(Error::Smu)?;
        self.smu.set_jpeg_power(true).await.map_err(Error::Smu)?;
        let media = match self.media.as_mut() {
            // Re-armed after a reset: the same buffers, started again.
            Some(media) if media.status().state == vcn::State::Prepared => media,
            Some(_) => return Err(Error::Busy),
            None => {
                // SAFETY: forwarded; the VCN image is in the TMR `psp` still
                // holds, both hubs' VMID0 and the doorbell apertures are up.
                let media = unsafe {
                    vcn::Media::new_raphael(
                        &self.gpu,
                        self.authority,
                        &self.pool,
                        self.doorbells,
                        vcn_bytes,
                        self.pg_flags,
                        self.cg_flags,
                    )
                }
                .map_err(Error::Media)?;
                self.media.insert(Box::new(media))
            }
        };
        // SAFETY: as above; PMFW has powered VCN up.
        unsafe { media.start(firmware, None, psp) }
            .await
            .map_err(Error::Media)?;
        if media.status().jpeg == vcn::JpegState::Prepared {
            // SAFETY: as above; PMFW has powered JPEG up.
            unsafe { media.start_jpeg() }.await.map_err(Error::Media)?;
        }
        if let Err(error) = vcn::route_interrupts(&self.ih.handle(), media.status()) {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael media: polling only {error:?}"
            );
        }
        media.test_ib().await.map_err(Error::Media)?;
        Ok(media.status())
    }
    fn report(&self) -> Result<Report, Error> {
        let queues = (self.gfx.state() == cp::GfxState::Verified
            && self.compute.state() == kiq::State::Verified
            && self.queues.state() == sdma_queues::State::Verified)
            .then(|| cp::QueueProof {
                gfx: self.gfx.proof(),
                compute: self.compute.proof(),
                sdma: self.queues.proof(),
            })
            .ok_or(Error::Invalid)?;
        Ok(Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            aperture: self.aperture.ok_or(Error::Invalid)?,
            gart: self.gmc.gart(),
            sdma: self.proof.ok_or(Error::Invalid)?,
            queues,
            topology: self.topology.ok_or(Error::Invalid)?,
        })
    }
    async unsafe fn step(&mut self, stage: Stage) -> Result<(), Error> {
        let (gpu, authority) = (&self.gpu, self.authority);
        // SAFETY: for every call, the contract of `new`, the completed RLC
        // autoload, and strict STAGES order without replay.
        unsafe {
            match stage {
                Stage::Smu => {
                    let versions = self.smu.start().await.map_err(Error::Smu)?;
                    if !versions.driver_if_matches() {
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: raphael smu driver if version {:#x}, expected {:#x}",
                            versions.driver_if,
                            smu::DRIVER_IF_VERSION
                        );
                    }
                    self.versions = Some(versions);
                    self.smu.set_gfxoff(false).await.map_err(Error::Smu)?;
                }
                Stage::MemoryHubs => {
                    self.aperture = Some(self.gmc.initialize().await.map_err(Error::MemoryHubs)?);
                }
                Stage::Gart => {
                    self.gmc.enable_gart().await.map_err(Error::MemoryHubs)?;
                }
                Stage::Interrupts => {
                    self.ih.initialize().await.map_err(Error::Interrupts)?;
                }
                Stage::GoldenSettings => self.gfx.golden().map_err(Error::Queues)?,
                Stage::SdmaTest => {
                    self.proof = Some(
                        self.sdma
                            .initialize(&mut self.gmc)
                            .await
                            .map_err(Error::Sdma)?,
                    );
                }
                Stage::InterruptTest => trap_round_trip(&mut self.ih, &mut self.sdma).await?,
                Stage::Doorbells => {
                    cp::enable_doorbell_apertures_raphael(gpu, authority, self.doorbells)
                        .map_err(Error::Queues)?
                }
                Stage::GfxSetup => self.gfx.configure().await.map_err(Error::Queues)?,
                Stage::Kiq => self.compute.init_kiq().await.map_err(Error::Queues)?,
                Stage::ComputeQueues => self.compute.map_compute().await.map_err(Error::Queues)?,
                Stage::GfxRing => {
                    let maps = self.gfx.prepare_queues().map_err(Error::Queues)?;
                    if let Err(error) = self.compute.map_gfx(&maps).await {
                        self.gfx.abandon_mapping();
                        return Err(Error::Queues(error));
                    }
                    self.gfx.start_mapped().await.map_err(Error::Queues)?;
                }
                Stage::SdmaQueues => self.queues.start().await.map_err(Error::Queues)?,
                Stage::IbTests => {
                    self.gfx.test_ib().await.map_err(Error::Queues)?;
                    self.compute.test_ib().await.map_err(Error::Queues)?;
                    self.queues.test_ib().await.map_err(Error::Queues)?;
                }
                Stage::FenceInterrupts => {
                    // Subscribe before unmasking, as Navi22 does. Without the
                    // routes the queues still work, polled at each deadline.
                    if let Err(error) = crate::amdgpu_navi22_boot::route_fences(&self.ih.handle()) {
                        use core::fmt::Write;
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: raphael FenceInterrupts: polling only {error:?}"
                        );
                        return Ok(());
                    }
                    cp::enable_fence_interrupts_raphael(gpu, authority, self.doorbells)
                        .map_err(Error::Queues)?
                }
                Stage::ReadTopology => {
                    let topology = crate::amdgpu_gfx10_topology::read_raphael(gpu, &authority)
                        .map_err(Error::Topology)?;
                    // AMDGPU_INFO's CU/RB fields and cached GB_ADDR_CONFIG.
                    crate::amdgpu_info::publish_navi22_topology(topology);
                    self.topology = Some(topology);
                }
            }
        }
        Ok(())
    }
}

/// VCN power for the idle work and `begin_use`: PMFW 13.0.5's
/// `PowerUpVcn`/`PowerDownVcn` (`smu_v13_0_5_dpm_set_vcn_enable`; always
/// sent, there is no MM_DPM_PG feature to consult), and the DPG register
/// lists through the PSP session that loaded VCN.
struct MediaPower<'a> {
    smu: &'a mut smu::Smu,
    psp: &'a mut crate::amdgpu_psp_ring::Psp,
}
impl vcn::SramLoader for MediaPower<'_> {
    async fn load_sram(&mut self, instance: usize, words: &[u32]) -> Result<(), vcn::Error> {
        vcn::SramLoader::load_sram(&mut *self.psp, instance, words).await
    }
}
impl vcn::idle::Control for MediaPower<'_> {
    async fn power(&mut self, instances: [bool; 2], on: bool) -> Result<bool, vcn::Error> {
        // Raphael has one VCN instance; nothing else to power.
        if !instances[0] {
            return Ok(false);
        }
        self.smu.set_vcn_power(on).await.map_err(vcn::Error::Pmfw)?;
        Ok(true)
    }
}

/// The SDMA0 proof's TRAP reaches the CPU through the IH ring.
async fn trap_round_trip(ih: &mut ih::Ih, sdma: &mut sdma::Sdma) -> Result<(), Error> {
    let mut waiter = ih
        .handle()
        .subscribe(ih::source::SDMA0_TRAP)
        .map_err(Error::Interrupts)?;
    let interrupts = ih.interrupts();
    if let Err(error) = sdma.trap(TRAP_CONTEXT).await {
        ih.record_proof(ih::Error::Source);
        return Err(Error::Sdma(error));
    }
    ih.prove(&mut waiter, TRAP_CONTEXT, interrupts)
        .await
        .map_err(Error::Interrupts)?;
    Ok(())
}

/// Boot-only checkpoints, never a poll-loop trace.
fn progress(stage: Stage, result: Option<Result<(), Error>>) {
    use core::fmt::Write;
    let _ = match result {
        None => writeln!(narf_console::Writer, "amdgpu: raphael {stage:?}: start"),
        Some(Ok(())) => writeln!(narf_console::Writer, "amdgpu: raphael {stage:?}: complete"),
        Some(Err(error)) => writeln!(
            narf_console::Writer,
            "amdgpu: raphael {stage:?}: failed {error:?}"
        ),
    };
}

/// A private immutable copy of the registers and identity; physical authority
/// still belongs to the caller of `ColdBoot::new`.
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

/// Hand a delayed `AllowGfxOff` to the display owner's task.
fn schedule(allow: Option<gfxoff::Allow>) {
    if let Some(allow) = allow {
        crate::amdgpu_platform::schedule_gfx_off(allow);
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_raphael_boot_tests.rs"]
mod tests;

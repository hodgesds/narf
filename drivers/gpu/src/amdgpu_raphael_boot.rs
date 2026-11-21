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
//! left PMFW. Nothing here allows it again: no GFXOFF or power-gating policy is
//! ported, so GFX stays powered.
//!
//! Construction reserves memory and maps the doorbell page but performs no
//! register I/O. A failure stops the sequence at its stage; the display path
//! that preceded it is unaffected. Nothing here publishes acceleration to
//! userspace.
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
    /// power-up (`PowerUpVcn`, `PowerUpJpeg`; VCN is power gated by default),
    /// then `vcn_v3_0_hw_init` in DPG mode with `psp`, the session that loaded
    /// the VCN image, writing its register lists, then JPEG, then the
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
        if !matches!(self.state, State::Ready(_)) || self.media.is_some() {
            return Err(Error::Busy);
        }
        self.smu.set_vcn_power(true).await.map_err(Error::Smu)?;
        self.smu.set_jpeg_power(true).await.map_err(Error::Smu)?;
        // SAFETY: forwarded; the VCN image is in the TMR `psp` still holds,
        // both hubs' VMID0 and the doorbell apertures are up.
        let media = unsafe {
            vcn::Media::new_raphael(
                &self.gpu,
                self.authority,
                &self.pool,
                self.doorbells,
                vcn_bytes,
            )
        }
        .map_err(Error::Media)?;
        let media = self.media.insert(Box::new(media));
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
                    self.topology = Some(
                        crate::amdgpu_gfx10_topology::read_raphael(gpu, &authority)
                            .map_err(Error::Topology)?,
                    );
                }
            }
        }
        Ok(())
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

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_raphael_boot_tests.rs"]
mod tests;

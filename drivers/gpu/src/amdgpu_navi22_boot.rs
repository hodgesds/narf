//! Ordered cold-boot firmware bring-up for Navi22. The caller supplies an
//! exclusive pool and trained VRAM or an explicit training inventory. The
//! only reset is the explicitly prepared reset-on-init of a posted card (Linux
//! `nv_need_reset_on_init`). No pool carving, platform initcall, modeset or
//! acceleration publication happens here.
use crate::{
    amdgpu::AmdGpu, amdgpu_gddr6 as gddr6, amdgpu_gfx_navi22 as gfx, amdgpu_power_navi22 as power,
    amdgpu_psp_boot as sos, amdgpu_psp_ring as psp, amdgpu_smu_navi22 as smu, amdgpu_vram::Pool,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Invalid,
    Allocation,
    Sos(sos::Error),
    Psp(psp::Error),
    Smu(smu::Error),
    Graphics(gfx::Error),
    Training(gddr6::Error),
    Power(power::Error),
    MemoryHubs(crate::amdgpu_gmc_navi22::Error),
    Sdma(crate::amdgpu_sdma_navi22::Error),
    Dmub(crate::amdgpu_dmub_navi22::Error),
    Display(crate::amdgpu_navi22_display::Error),
    Modeset(crate::amdgpu_navi22_modeset::Error),
    Queues(crate::amdgpu_cp_navi22::Error),
    Reset(crate::amdgpu_reset_navi22::Error),
    Interrupts(crate::amdgpu_ih_navi22::Error),
    Media(crate::amdgpu_vcn_navi22::Error),
    Topology(crate::amdgpu_gfx10_topology::Error),
    PowerSaving(crate::amdgpu_navi22_power_saving::Error),
}
/// All files are validated and copied before the first device operation.
#[derive(Debug)]
pub struct Firmware {
    sos: sos::Firmware,
    smc: smu::Firmware,
    graphics: gfx::Firmware,
    power: Option<power::Prepared>,
    dmub: Option<crate::amdgpu_dmub_navi22::Prepared>,
    display: Option<DisplayPrep>,
}
impl Firmware {
    /// The versions `AMDGPU_INFO_FW_VERSION` reports for this validated set
    /// (Linux takes them from the requested files' headers, not the device).
    pub fn uapi_versions(&self) -> Option<crate::amdgpu_info_navi22::Firmware> {
        use crate::amdgpu_gfx_firmware::Source;
        let g = |source| self.graphics.source_bytes(source);
        crate::amdgpu_info_navi22::Firmware::parse(&crate::amdgpu_info_navi22::Files {
            me: g(Source::Me)?,
            pfp: g(Source::Pfp)?,
            ce: g(Source::Ce)?,
            mec: g(Source::Mec)?,
            mec2: g(Source::Mec2),
            rlc: g(Source::Rlc)?,
            sdma: g(Source::Sdma)?,
            sos: self.sos.bytes(),
            vcn: g(Source::Vcn)?,
            dmcub: g(Source::Dmcub)?,
        })
        .ok()
    }
    pub fn open(
        gpu: &AmdGpu,
        registry: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        Ok(Self {
            sos: sos::Firmware::open(gpu, registry).map_err(Error::Sos)?,
            smc: smu::Firmware::open(gpu, registry).map_err(Error::Smu)?,
            graphics: gfx::Firmware::open(gpu, registry).map_err(Error::Graphics)?,
            power: None,
            dmub: None,
            display: None,
        })
    }
    /// Remove harvested VCN instances (`adev->vcn.harvest_config`) before PSP
    /// receives the graphics set; the media owner follows the same mask.
    pub fn harvest_vcn(&mut self, harvested: u8) {
        self.graphics.harvest_vcn(harvested);
    }
    /// Decode the board's connector routes (DDC line, HPD, transmitter) from
    /// the VBIOS before any device write. Optional: firmware bring-up does not
    /// depend on display routing.
    pub fn prepare_display(&mut self, gpu: &AmdGpu) -> Result<(), Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        let vbios = gpu.vbios.as_ref().ok_or(Error::Invalid)?;
        let inventory =
            |error| Error::Display(crate::amdgpu_navi22_display::Error::Inventory(error));
        let paths =
            crate::amdgpu_dcn_inventory::display_paths(gpu, vbios.bytes()).map_err(inventory)?;
        // bios_parser2 takes the crystal from dce_refclk_10khz (27 MHz if zero).
        let crystal =
            crate::amdgpu_dcn_inventory::dchub_refclk_khz(vbios.bytes()).map_err(inventory)?;
        // The VBIOS command tables and vram_info are needed after the
        // controller's own copy becomes inaccessible.
        let mut bytes = alloc::vec::Vec::new();
        bytes
            .try_reserve_exact(vbios.bytes().len())
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(vbios.bytes());
        self.display = Some(DisplayPrep {
            paths,
            crystal,
            vbios: bytes,
        });
        Ok(())
    }
    /// Prepare DCN3.0's nonsecure DMUB storage before starting any hardware.
    pub fn prepare_dmub(&mut self, gpu: &AmdGpu) -> Result<(), Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        let vbios = gpu.vbios.as_ref().ok_or(Error::Invalid)?;
        self.dmub = Some(
            crate::amdgpu_dmub_navi22::Prepared::new(
                self.graphics.dmcub_bytes().map_err(Error::Graphics)?,
                vbios.bytes(),
                self.sos.image().map_err(Error::Sos)?.version(),
            )
            .map_err(Error::Dmub)?,
        );
        Ok(())
    }
    /// Prepare this board's power table before any device writes. Production
    /// platform boot always calls this; explicit firmware-only callers may
    /// omit it, in which case Report::power is None and no table is sent.
    pub fn prepare_power(&mut self, gpu: &AmdGpu, identity: power::Identity) -> Result<(), Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        let vbios = gpu
            .vbios
            .as_ref()
            .ok_or(Error::Power(power::Error::MissingVbios))?;
        let prepared = power::Prepared::new(vbios, &self.smc, identity).map_err(Error::Power)?;
        prepared.boot_policy().map_err(Error::Power)?;
        self.power = Some(prepared);
        Ok(())
    }
}
impl Firmware {
    /// Prepare the display inputs and DMUB storage again for a recovered
    /// owner, from the VBIOS copy and routes the first boot retained (the
    /// controller's own VBIOS is no longer reachable).
    fn restore_display(
        &mut self,
        vbios: alloc::vec::Vec<u8>,
        crystal: u32,
        paths: alloc::vec::Vec<crate::amdgpu_dcn_inventory::Path>,
    ) -> Result<(), Error> {
        self.dmub = Some(
            crate::amdgpu_dmub_navi22::Prepared::new(
                self.graphics.dmcub_bytes().map_err(Error::Graphics)?,
                &vbios,
                self.sos.image().map_err(Error::Sos)?.version(),
            )
            .map_err(Error::Dmub)?,
        );
        self.display = Some(DisplayPrep {
            paths,
            crystal,
            vbios,
        });
        Ok(())
    }
}
/// VBIOS-derived display inputs, copied before any device write.
#[derive(Debug)]
struct DisplayPrep {
    paths: alloc::vec::Vec<crate::amdgpu_dcn_inventory::Path>,
    crystal: u32,
    vbios: alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    ResetOnInit,
    MemoryTraining,
    Sos,
    Ring,
    TrustedMemory,
    Smc,
    SmuVersions,
    PowerTable,
    DmubQuiesce,
    Graphics,
    RlcBoot,
    PowerSetup,
    MemoryHubs,
    Gart,
    Interrupts,
    GoldenSettings,
    SdmaTest,
    InterruptTest,
    DmubStart,
    Doorbells,
    GfxSetup,
    Kiq,
    ComputeQueues,
    GfxRing,
    SdmaQueues,
    IbTests,
    FenceInterrupts,
    Media,
    Jpeg,
    MediaIbTests,
    ReadTopology,
}
const STAGES: [Stage; 31] = [
    Stage::ResetOnInit,
    Stage::MemoryTraining,
    Stage::Sos,
    Stage::Ring,
    Stage::TrustedMemory,
    Stage::Smc,
    Stage::SmuVersions,
    Stage::PowerTable,
    Stage::DmubQuiesce,
    Stage::Graphics,
    Stage::RlcBoot,
    Stage::PowerSetup,
    Stage::MemoryHubs,
    // gmc_v10_0_hw_init's gart_enable completes GMC before any engine.
    Stage::Gart,
    // Linux enables IH (hw_init phase 1) after COMMON/GMC and before every
    // phase-2 engine. Its VRAM ring needs VMID0, so IH follows MemoryHubs.
    Stage::Interrupts,
    // gfx_v10_0_hw_init's init_golden_registers: GFX precedes SDMA in the
    // phase-2 pass, so GC golden settings land before SDMA starts.
    Stage::GoldenSettings,
    Stage::SdmaTest,
    Stage::InterruptTest,
    // gfx_v10_0_hw_init / cp_resume, sdma_v5_2_start, amdgpu_ib_ring_tests.
    Stage::Doorbells,
    Stage::GfxSetup,
    Stage::Kiq,
    Stage::ComputeQueues,
    Stage::GfxRing,
    Stage::SdmaQueues,
    Stage::IbTests,
    // Arms EOP/trap interrupts and routes them to fence waiters.
    Stage::FenceInterrupts,
    // dm_dmub_hw_init. Linux runs it before GFX in the phase-2 pass, but no
    // queue stage depends on DMUB; here it follows every queue/fence proof
    // and is non-fatal, so a DMUB failure cannot cost GFX/SDMA/media.
    Stage::DmubStart,
    // vcn_v3_0_hw_init, jpeg_v3_0_hw_init, then the multimedia part of
    // amdgpu_ib_ring_tests. Linux runs VCN/JPEG hw_init after GFX/SDMA in
    // the same phase-2 pass; here they follow every display, queue and fence
    // proof so a media fault cannot delay or alter them, and the IB tests
    // already have IH-routed fences. Each media stage is non-fatal.
    Stage::Media,
    Stage::Jpeg,
    Stage::MediaIbTests,
    // gfx_v10_0_constants_init's setup_rb/get_cu_info/get_tcc_info reads, for
    // AMDGPU_INFO. Appended: RLC is booted, GFX powered and the idle kernel
    // queues never touch GRBM indexing after GfxSetup.
    Stage::ReadTopology,
];
/// INT_CONTEXT of the boot SDMA0 TRAP round trip.
const TRAP_CONTEXT: u32 = 0x0675_0022;
/// Firmware/power observations, optional VMID0 and SDMA execution proof.
/// This does not publish acceleration or initialize native display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Present when SOS was running and the ASIC was reset before bring-up.
    pub reset: Option<crate::amdgpu_reset_navi22::Report>,
    pub smu: smu::Versions,
    pub gfx: psp::GfxBootStatus,
    pub power: Option<power::Info>,
    pub power_status: Option<smu::PowerStatus>,
    pub media_firmware: psp::MediaFirmware,
    pub memory_aperture: Option<crate::amdgpu_gmc_navi22::Aperture>,
    pub sdma: Option<crate::amdgpu_sdma_navi22::Proof>,
    pub dmub: Option<crate::amdgpu_dmub_navi22::Status>,
    /// Kernel GFX/compute/SDMA ring and IB tests passed.
    pub queues: Option<crate::amdgpu_cp_navi22::QueueProof>,
    pub interrupts: Option<crate::amdgpu_ih_navi22::Status>,
    /// VCN/JPEG owner state; failures there leave the boot degraded only.
    pub media: Option<crate::amdgpu_vcn_navi22::Status>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "boot state snapshots remain Copy and allocation-free"
)]
pub enum State {
    Prepared,
    Running(Stage),
    FirmwareReady(Report),
    Failed { stage: Stage, error: Error },
    Released,
}
trait Backend {
    /// None marks entry; Some records the terminal result, once per stage.
    fn progress(&mut self, stage: Stage, result: Option<Result<(), Error>>);
    async fn step(&mut self, stage: Stage) -> Result<(), Error>;
    fn report(&self) -> Result<Report, Error>;
}
#[derive(Debug)]
struct Sequence<B: Backend> {
    backend: B,
    state: State,
}
impl<B: Backend> Sequence<B> {
    async fn run(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        for stage in STAGES {
            // Stored outside the future, so dropping the future cannot permit
            // replay or discard the backend's outstanding hardware owners.
            self.state = State::Running(stage);
            self.backend.progress(stage, None);
            let result = self.backend.step(stage).await;
            self.backend.progress(stage, Some(result));
            if let Err(error) = result {
                self.state = State::Failed { stage, error };
                return Err(error);
            }
        }
        match self.backend.report() {
            Ok(report) => {
                self.state = State::FirmwareReady(report);
                Ok(report)
            }
            Err(error) => {
                self.state = State::Failed {
                    stage: STAGES[STAGES.len() - 1],
                    error,
                };
                Err(error)
            }
        }
    }
}
#[derive(Debug)]
struct Hardware {
    // Private immutable register/identity snapshot; physical authority still
    // belongs exclusively to ColdBoot. No controller guard spans an await.
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    firmware: Firmware,
    reset: Option<crate::amdgpu_reset_navi22::Reset>,
    reset_report: Option<crate::amdgpu_reset_navi22::Report>,
    training: Option<gddr6::Trainer>,
    bootstrap: Option<sos::Bootloader>,
    psp: Option<psp::Psp>,
    smu: Option<smu::Smu>,
    versions: Option<smu::Versions>,
    gfx_status: Option<psp::GfxBootStatus>,
    power_status: Option<smu::PowerStatus>,
    gmc: Option<crate::amdgpu_gmc_navi22::Gmc>,
    sdma: Option<crate::amdgpu_sdma_navi22::Sdma>,
    dmub: Option<crate::amdgpu_dmub_navi22::Dmub>,
    display: Option<crate::amdgpu_navi22_display::Display>,
    /// DCN3.0 Linux never routes AUX/HPD through DMUB; only an explicit
    /// opt-in plus a firmware capability reply re-enables that transport.
    dmub_aux: bool,
    /// VBIOS copy and crystal for the native modeset, and its retained owner.
    display_bios: Option<(alloc::vec::Vec<u8>, u32)>,
    modeset: Option<crate::amdgpu_navi22_modeset::Pipeline>,
    /// Presentation of the lit pipe (amdgpu_navi22_scanout), built after it
    /// lights and stopped before the pipeline tears it down.
    scanout: Option<crate::amdgpu_navi22_scanout::Scanout>,
    /// A multi-stream context (KMS CRTCs 1..), lit instead of `modeset`.
    group: Option<crate::amdgpu_navi22_modeset::Group>,
    queues: Option<Queues>,
    ih: Option<crate::amdgpu_ih_navi22::Ih>,
    media: Option<crate::amdgpu_vcn_navi22::Media>,
    /// The `amdgpu.navi22_pg` opt-in's owners; None on a default boot.
    power_saving: Option<crate::amdgpu_navi22_power_saving::Retained>,
}
/// Kernel queue owners, retained through success, failure and cancellation.
#[derive(Debug)]
struct Queues {
    doorbells: crate::amdgpu_cp_navi22::Doorbells,
    gfx: crate::amdgpu_cp_navi22::Gfx,
    compute: crate::amdgpu_kiq_navi22::Compute,
    sdma: crate::amdgpu_sdma_navi22_queues::Sdma,
}
impl Queues {
    // SAFETY contract for every call: ColdBoot exclusively owns the GPU,
    // firmware/RLC are up, VMID0 is ready, clock gating and GFXOFF stay off,
    // and stages run strictly in STAGES order without replay.
    async fn step(
        &mut self,
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        stage: Stage,
    ) -> Result<(), crate::amdgpu_cp_navi22::Error> {
        match stage {
            // SAFETY: see above; the doorbell page belongs to this GPU's BAR2.
            Stage::Doorbells => unsafe {
                crate::amdgpu_cp_navi22::enable_doorbell_apertures(gpu, authority, self.doorbells)
            },
            // SAFETY: see above.
            Stage::GfxSetup => unsafe { self.gfx.configure().await },
            // SAFETY: see above; GFX setup completed in the previous stage.
            Stage::Kiq => unsafe { self.compute.init_kiq().await },
            // SAFETY: see above; the KIQ is live.
            Stage::ComputeQueues => unsafe { self.compute.map_compute().await },
            // SAFETY: see above; KIQ/KCQ precede the gfx ring as in cp_resume.
            Stage::GfxRing => unsafe { self.gfx.start().await },
            // SAFETY: see above; the SDMA0 proof ring finished and is idle.
            Stage::SdmaQueues => unsafe { self.sdma.start().await },
            Stage::IbTests => {
                self.gfx.test_ib().await?;
                self.compute.test_ib().await?;
                self.sdma.test_ib().await
            }
            _ => Ok(()),
        }
    }
    fn proof(&self) -> Option<crate::amdgpu_cp_navi22::QueueProof> {
        (self.gfx.state() == crate::amdgpu_cp_navi22::GfxState::Verified
            && self.compute.state() == crate::amdgpu_kiq_navi22::State::Verified
            && self.sdma.state() == crate::amdgpu_sdma_navi22_queues::State::Verified)
            .then(|| crate::amdgpu_cp_navi22::QueueProof {
                gfx: self.gfx.proof(),
                compute: self.compute.proof(),
                sdma: self.sdma.proof(),
            })
    }
}
/// Kernel queue a CP EOP / SDMA trap entry completed (`gfx_v10_0_eop_irq`
/// me/pipe decode, `sdma_v5_2_process_trap_irq` client).
fn fence_engine(iv: &crate::amdgpu_ih_navi22::Iv) -> Option<crate::amdgpu_fence_navi22::Engine> {
    use crate::{amdgpu_fence_navi22::Engine, amdgpu_ih_navi22::source};
    let from = crate::amdgpu_ih_navi22::Source {
        client: iv.client,
        src: iv.src,
    };
    if from == source::GFX_EOP {
        return match iv.cp_queue().me {
            0 => Some(Engine::Gfx),
            1 => Some(Engine::Compute),
            2 => Some(Engine::Kiq),
            _ => None,
        };
    }
    if from == source::SDMA0_TRAP {
        return Some(Engine::Sdma0);
    }
    (from == source::SDMA1_TRAP).then_some(Engine::Sdma1)
}
/// One task per source forwards entries to fence waiters. A terminal IH
/// error wakes every waiter so each re-samples and observes device loss.
fn route_fences(
    ih: &crate::amdgpu_ih_navi22::Handle,
) -> Result<(), crate::amdgpu_ih_navi22::Error> {
    use crate::amdgpu_ih_navi22::source;
    let mut subscriptions = alloc::vec::Vec::new();
    for from in [source::GFX_EOP, source::SDMA0_TRAP, source::SDMA1_TRAP] {
        subscriptions.push(ih.subscribe(from)?);
    }
    for mut subscription in subscriptions {
        narf_scheduler::spawn(async move {
            loop {
                match subscription.wait().await {
                    Ok(iv) => {
                        if let Some(engine) = fence_engine(&iv) {
                            crate::amdgpu_fence_navi22::notify(engine);
                        }
                    }
                    Err(_) => {
                        crate::amdgpu_fence_navi22::notify_all();
                        return;
                    }
                }
            }
        });
    }
    Ok(())
}
/// Device loss and revoked authority stop the boot; any other failure of the
/// diagnostic round trip leaves IH enabled with watchdog/polling delivery.
fn fatal(error: Error) -> bool {
    use crate::{amdgpu_ih_navi22 as ih, amdgpu_sdma_navi22 as sdma};
    matches!(
        error,
        Error::Sdma(sdma::Error::DeviceGone | sdma::Error::Revoked)
            | Error::Interrupts(
                ih::Error::DeviceGone
                    | ih::Error::Revoked
                    | ih::Error::Closed(ih::Closed::DeviceLost | ih::Closed::AuthorityRevoked)
            )
    )
}
/// Device loss and revoked authority stop the boot; every other media
/// failure is logged and the owner retained (quarantined), like InterruptTest.
fn media_result(
    stage: Stage,
    result: Result<(), crate::amdgpu_vcn_navi22::Error>,
) -> Result<(), Error> {
    use crate::amdgpu_vcn_navi22::Error as Vcn;
    match result {
        Ok(()) => Ok(()),
        Err(error @ (Vcn::DeviceGone | Vcn::Revoked)) => Err(Error::Media(error)),
        Err(error) => {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 {stage:?}: degraded {error:?}"
            );
            Ok(())
        }
    }
}
/// Device loss and revoked authority stop the boot; any other DMUB failure
/// leaves the owner Failed (storage retained) and the boot degraded: the
/// display paths that need DMUB refuse a non-Running owner.
fn dmub_result(result: Result<(), crate::amdgpu_dmub_navi22::Error>) -> Result<(), Error> {
    use crate::amdgpu_dmub_navi22::Error as Dmub;
    match result {
        Ok(()) => Ok(()),
        Err(error @ (Dmub::DeviceGone | Dmub::Revoked)) => Err(Error::Dmub(error)),
        Err(error) => {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 DmubStart: degraded {error:?}"
            );
            Ok(())
        }
    }
}
async fn trap_round_trip(
    ih: &mut crate::amdgpu_ih_navi22::Ih,
    sdma: &mut crate::amdgpu_sdma_navi22::Sdma,
) -> Result<(), Error> {
    use crate::amdgpu_ih_navi22 as ih_mod;
    let mut waiter = ih
        .handle()
        .subscribe(ih_mod::source::SDMA0_TRAP)
        .map_err(Error::Interrupts)?;
    let interrupts = ih.interrupts();
    if let Err(error) = sdma.trap(TRAP_CONTEXT).await {
        ih.record_proof(ih_mod::Error::Source);
        return Err(Error::Sdma(error));
    }
    ih.prove(&mut waiter, TRAP_CONTEXT, interrupts)
        .await
        .map_err(Error::Interrupts)?;
    Ok(())
}
impl Backend for Hardware {
    fn progress(&mut self, stage: Stage, result: Option<Result<(), Error>>) {
        use core::fmt::Write;
        // Boot-only checkpoints, never a poll-loop trace. Do not write to
        // the framebuffer while training owns its VRAM preimage.
        let _ = match result {
            None => writeln!(narf_console::Writer, "amdgpu: navi22 {stage:?}: start"),
            Some(Ok(())) => writeln!(narf_console::Writer, "amdgpu: navi22 {stage:?}: complete"),
            Some(Err(error)) => writeln!(
                narf_console::Writer,
                "amdgpu: navi22 {stage:?}: failed {error:?}"
            ),
        };
    }
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::ResetOnInit => {
                if let Some(reset) = self.reset.as_mut() {
                    self.reset_report = reset.run().await.map_err(Error::Reset)?;
                }
            }
            Stage::MemoryTraining => {
                if let Some(training) = self.training.as_mut() {
                    training.run().await.map_err(Error::Training)?;
                }
            }
            Stage::Sos => {
                // The pool's GPU addresses came from the pre-reset/pre-training
                // FB location; re-validate before any reaches the bootloader.
                psp::validate_navi22_pool(&self.gpu, &self.authority, &self.pool).map_err(
                    |error| {
                        Error::Sos(match error {
                            psp::Error::Revoked => sos::Error::Revoked,
                            psp::Error::DeviceGone => sos::Error::DeviceGone,
                            psp::Error::Unsupported => sos::Error::Unsupported,
                            _ => sos::Error::Invalid,
                        })
                    },
                )?;
                if self.bootstrap.is_none() {
                    // SAFETY: explicit training finished before claiming PSP
                    // bootstrap ownership; its idle owner retains only data.
                    self.bootstrap = Some(
                        unsafe { sos::Bootloader::new(&self.gpu, self.authority, &self.pool) }
                            .map_err(Error::Sos)?,
                    );
                }
                self.bootstrap
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .load(&self.firmware.sos)
                    .await
                    .map_err(Error::Sos)?;
                // Successful SOS startup ended its read of staging. Relinquish
                // the bootstrap mailbox before the same PSP is claimed by GPCOM.
                self.bootstrap.take();
            }
            Stage::Ring => {
                // SAFETY: ColdBoot owns the physical GPU/pool and SOS completed;
                // the bootstrap owner was dropped. Mappings remain permanent.
                self.psp = Some(
                    unsafe { psp::Psp::new_navi22(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Psp)?,
                );
                self.psp
                    .as_mut()
                    .unwrap()
                    .start()
                    .await
                    .map_err(Error::Psp)?;
            }
            Stage::TrustedMemory => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .setup_tmr_navi22(&self.firmware.sos)
                .await
                .map_err(Error::Psp)?,
            Stage::Smc => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .load_smc_navi22(&self.firmware.smc)
                .await
                .map_err(Error::Psp)?,
            Stage::SmuVersions => {
                // SAFETY: SMC upload completed for this cold boot. ColdBoot owns
                // MP1/reset/PM and excludes all other SMU clients.
                self.smu = Some(
                    unsafe { smu::Smu::after_upload(&self.gpu, self.authority) }
                        .map_err(Error::Smu)?,
                );
                self.versions = Some(
                    self.smu
                        .as_mut()
                        .unwrap()
                        .verify()
                        .await
                        .map_err(Error::Smu)?,
                );
            }
            Stage::Graphics => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .load_gfx_navi22(&self.firmware.graphics)
                .await
                .map_err(Error::Psp)?,
            Stage::PowerTable => {
                if let Some(table) = self.firmware.power.as_ref() {
                    // SAFETY: this coordinator retains the same exclusive
                    // GPU/pool/HDP/index latch after PSP startup and training.
                    unsafe {
                        self.smu
                            .as_mut()
                            .ok_or(Error::Invalid)?
                            .upload_power_table(table, &self.pool)
                            .await
                    }
                    .map_err(Error::Smu)?;
                }
            }
            Stage::RlcBoot => {
                self.gfx_status = Some(
                    self.psp
                        .as_mut()
                        .ok_or(Error::Invalid)?
                        .wait_gfx_boot_navi22()
                        .await
                        .map_err(Error::Psp)?,
                );
            }
            Stage::PowerSetup => {
                if self.firmware.power.is_some() {
                    // SAFETY: retained exclusive SMU/VRAM owner, confirmed
                    // RLC boot, and no queues have been enabled yet.
                    self.power_status = Some(
                        unsafe {
                            self.smu
                                .as_mut()
                                .ok_or(Error::Invalid)?
                                .configure_power()
                                .await
                        }
                        .map_err(Error::Smu)?,
                    );
                }
            }
            Stage::DmubQuiesce => {
                if let Some(dmub) = self.dmub.as_mut() {
                    dmub.quiesce().await.map_err(Error::Dmub)?;
                }
            }
            Stage::DmubStart => {
                if let Some(dmub) = self.dmub.as_mut() {
                    // SAFETY: same exclusive GPU; trained VRAM, both hubs and
                    // protected power are ready. PSP/TMR remain retained here.
                    let result =
                        unsafe { dmub.start(self.psp.as_ref().ok_or(Error::Invalid)?).await };
                    dmub_result(result.map(|_| ()))?;
                }
            }
            Stage::GoldenSettings => {
                if let Some(queues) = self.queues.as_mut() {
                    // SAFETY: RLC autoload completed (RlcBoot), no GC client
                    // runs, and ColdBoot owns the whole GPU.
                    unsafe { queues.gfx.golden() }.map_err(Error::Queues)?;
                }
            }
            Stage::ReadTopology => {
                // SAFETY: firmware/RLC/power are up; this owner holds GRBM
                // indexing and GC exclusively and no queue has started.
                match unsafe { crate::amdgpu_gfx10_topology::read(&self.gpu, &self.authority) } {
                    Ok(topology) => crate::amdgpu_info::publish_navi22_topology(topology),
                    Err(
                        error @ (crate::amdgpu_gfx10_topology::Error::DeviceGone
                        | crate::amdgpu_gfx10_topology::Error::Revoked),
                    ) => return Err(Error::Topology(error)),
                    // Userspace identity only: the kernel queues do not
                    // depend on it, so an implausible sample is reported and
                    // DEV_INFO keeps its unknown-harvest zeros.
                    Err(error) => {
                        use core::fmt::Write;
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: navi22 topology unavailable: {error:?}"
                        );
                    }
                }
            }
            Stage::SdmaTest => {
                if let Some(sdma) = self.sdma.as_mut() {
                    // SAFETY: firmware, protected power and both hubs are ready.
                    // The same exclusive owner retains TMR and VRAM backing.
                    unsafe {
                        sdma.initialize(self.gmc.as_mut().ok_or(Error::Invalid)?)
                            .await
                    }
                    .map_err(Error::Sdma)?;
                }
            }
            Stage::Doorbells
            | Stage::GfxSetup
            | Stage::Kiq
            | Stage::ComputeQueues
            | Stage::GfxRing
            | Stage::SdmaQueues
            | Stage::IbTests => {
                if let Some(queues) = self.queues.as_mut() {
                    queues
                        .step(&self.gpu, self.authority, stage)
                        .await
                        .map_err(Error::Queues)?;
                }
            }
            Stage::FenceInterrupts => {
                if let (Some(queues), Some(ih)) = (self.queues.as_ref(), self.ih.as_ref()) {
                    if queues.proof().is_some() {
                        // SAFETY: every kernel queue is verified, IH is live and
                        // this owner holds the GPU exclusively.
                        unsafe {
                            crate::amdgpu_cp_navi22::enable_fence_interrupts(
                                &self.gpu,
                                self.authority,
                                queues.doorbells,
                            )
                        }
                        .map_err(Error::Queues)?;
                        if let Err(error) = route_fences(&ih.handle()) {
                            use core::fmt::Write;
                            let _ = writeln!(
                                narf_console::Writer,
                                "amdgpu: navi22 FenceInterrupts: polling only {error:?}"
                            );
                        }
                    }
                }
            }
            Stage::Media => {
                if let Some(media) = self.media.as_mut() {
                    let firmware = self.psp.as_ref().ok_or(Error::Invalid)?.media_firmware();
                    // SAFETY: PSP loaded these VCN images into the retained
                    // TMR, both hubs and NBIF doorbells are up, and ColdBoot
                    // owns the whole GPU. Power gating stays disabled.
                    let result = unsafe { media.start(firmware, self.power_status).await };
                    media_result(stage, result)?;
                }
            }
            Stage::Jpeg => {
                if let Some(media) = self.media.as_mut() {
                    if media.status().jpeg == crate::amdgpu_vcn_navi22::JpegState::Prepared {
                        // SAFETY: as for Media; JPEG uses VCN0's registers.
                        let result = unsafe { media.start_jpeg().await };
                        media_result(stage, result)?;
                    }
                }
            }
            Stage::MediaIbTests => {
                if let Some(media) = self.media.as_mut() {
                    if let Some(ih) = self.ih.as_ref() {
                        let status = media.status();
                        if let Err(error) =
                            crate::amdgpu_vcn_navi22::route_interrupts(&ih.handle(), status)
                        {
                            use core::fmt::Write;
                            let _ = writeln!(
                                narf_console::Writer,
                                "amdgpu: navi22 MediaIbTests: polling only {error:?}"
                            );
                        }
                    }
                    if media.status().state == crate::amdgpu_vcn_navi22::State::Running {
                        let result = media.test_ib().await;
                        media_result(stage, result)?;
                    }
                }
            }
            Stage::Interrupts => {
                if let Some(ih) = self.ih.as_mut() {
                    // SAFETY: VMID0 is ready, no engine raises interrupts yet,
                    // and this owner holds the PCI function exclusively.
                    unsafe { ih.initialize().await }.map_err(Error::Interrupts)?;
                }
            }
            Stage::InterruptTest => {
                if let (Some(ih), Some(sdma)) = (self.ih.as_mut(), self.sdma.as_mut()) {
                    if let Err(error) = trap_round_trip(ih, sdma).await {
                        if fatal(error) {
                            return Err(error);
                        }
                        use core::fmt::Write;
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: navi22 InterruptTest: degraded {error:?}"
                        );
                    }
                }
            }
            Stage::MemoryHubs => {
                if let Some(gmc) = self.gmc.as_mut() {
                    // SAFETY: firmware/RLC are ready, VRAM is trained, queues
                    // remain idle and the boot power policy excludes gating.
                    unsafe { gmc.initialize().await }.map_err(Error::MemoryHubs)?;
                }
            }
            Stage::Gart => {
                if let Some(gmc) = self.gmc.as_mut().filter(|gmc| gmc.gart_prepared()) {
                    // SAFETY: same exclusive owner; both hubs are Ready and no
                    // queue runs in any VMID before the SDMA test below.
                    unsafe { gmc.enable_gart().await }.map_err(Error::MemoryHubs)?;
                }
            }
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(Report {
            reset: self.reset_report,
            smu: self.versions.ok_or(Error::Invalid)?,
            gfx: self.gfx_status.ok_or(Error::Invalid)?,
            power: self.firmware.power.as_ref().map(power::Prepared::info),
            power_status: self.power_status,
            media_firmware: self.psp.as_ref().ok_or(Error::Invalid)?.media_firmware(),
            dmub: self
                .dmub
                .as_ref()
                .and_then(crate::amdgpu_dmub_navi22::Dmub::status),
            sdma: self
                .sdma
                .as_ref()
                .and_then(crate::amdgpu_sdma_navi22::Sdma::proof),
            memory_aperture: self
                .gmc
                .as_ref()
                .and_then(crate::amdgpu_gmc_navi22::Gmc::aperture),
            queues: self.queues.as_ref().and_then(Queues::proof),
            interrupts: self.ih.as_ref().map(crate::amdgpu_ih_navi22::Ih::status),
            media: self
                .media
                .as_ref()
                .map(crate::amdgpu_vcn_navi22::Media::status),
        })
    }
}
#[derive(Debug)]
pub struct ColdBoot {
    sequence: Sequence<Hardware>,
}
/// Copy only the immutable layout consumed by firmware owners. VBIOS,
/// userspace topology and live driver state remain with the controller.
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
        // Immutable discovery maxima, needed to bound the topology sample.
        gc_info: gpu.gc_info,
        vbios: None,
        mode: None,
        fw_loaded: false,
    })
}
impl ColdBoot {
    /// # Safety
    /// Caller exclusively owns this physical Navi22 GPU (not an SR-IOV VF), its
    /// PSP/MP1/GC/HDP mailboxes and reset/power controls. Mappings are permanent,
    /// VRAM already trained, and the pool contains only exclusively free VRAM
    /// with correct GPU addresses and firmware/scanout/discovery/training/TMR
    /// exclusions. This is one cold-boot attempt, not attach, resume or reload.
    /// Firmware and any prepared power table must belong to this GPU's board,
    /// including its VBIOS and PCI identity. The VRAM index latch is exclusive.
    /// No active queues/other firmware clients may run. After failure or
    /// cancellation, do not create another owner or reuse quarantined memory
    /// until independent reset/recovery. Drop never resets hardware. Successful
    /// ownership may be transferred via take_psp; all its safety contracts
    /// continue to apply to that caller.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: Firmware,
    ) -> Result<Self, Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        let gpu = snapshot(gpu)?;
        // SAFETY: forwarded trained-VRAM/exclusive-device/mapping/pool contract.
        let bootstrap =
            unsafe { sos::Bootloader::new(&gpu, authority, pool) }.map_err(Error::Sos)?;
        Ok(Self {
            sequence: Sequence {
                backend: Hardware {
                    gpu,
                    authority,
                    pool: pool.clone(),
                    firmware,
                    reset: None,
                    reset_report: None,
                    training: None,
                    bootstrap: Some(bootstrap),
                    psp: None,
                    smu: None,
                    versions: None,
                    gfx_status: None,
                    power_status: None,
                    gmc: None,
                    sdma: None,
                    dmub: None,
                    display: None,
                    dmub_aux: false,
                    display_bios: None,
                    modeset: None,
                    scanout: None,
                    group: None,
                    queues: None,
                    ih: None,
                    media: None,
                    power_saving: None,
                },
                state: State::Prepared,
            },
        })
    }
    /// Add long GDDR6 training before SOS, retaining its preimage/cache for
    /// diagnostics and eventual resume support. All firmware must be prepared
    /// before constructing this session.
    ///
    /// # Safety
    /// All `new` ownership/mapping/exclusion contracts apply except that final
    /// memory training is performed here. In addition, satisfy `Trainer::new`:
    /// stop CPU framebuffer writers and every other VRAM client for the whole
    /// operation. Exchange buffers must be from this GPU's current boot Plan.
    /// Firmware must have provided a readable initial VRAM mapping for backup.
    pub unsafe fn new_with_training(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: Firmware,
        exchange: crate::amdgpu_vram_boot::Training,
    ) -> Result<Self, Error> {
        let gpu = snapshot(gpu)?;
        // SAFETY: caller owns all mappings/clients and reserves both exchanges.
        let training =
            unsafe { gddr6::Trainer::new(&gpu, authority, exchange) }.map_err(Error::Training)?;
        Ok(Self {
            sequence: Sequence {
                backend: Hardware {
                    gpu,
                    authority,
                    pool: pool.clone(),
                    firmware,
                    reset: None,
                    reset_report: None,
                    training: Some(training),
                    bootstrap: None,
                    psp: None,
                    smu: None,
                    versions: None,
                    gfx_status: None,
                    power_status: None,
                    gmc: None,
                    sdma: None,
                    dmub: None,
                    display: None,
                    dmub_aux: false,
                    display_bios: None,
                    modeset: None,
                    scanout: None,
                    group: None,
                    queues: None,
                    ih: None,
                    media: None,
                    power_saving: None,
                },
                state: State::Prepared,
            },
        })
    }
    pub fn training_state(&self) -> Option<gddr6::State> {
        self.sequence
            .backend
            .training
            .as_ref()
            .map(gddr6::Trainer::state)
    }
    /// Reset a posted card before any firmware stage, as Linux does whenever
    /// the VBIOS left SOS running. Production boot calls this; without it the
    /// sequence loads firmware over the inherited SOS/PMFW (test callers).
    /// Performs no I/O; `run` decides from the live SOS sign of life.
    ///
    /// # Safety
    /// `new`'s ownership contract, plus `Reset::new`'s: `device` is this GPU's
    /// PCI function and its config space has no other user. The reset discards
    /// every inherited scanout, so a boot framebuffer on this card goes dark.
    pub unsafe fn prepare_reset(&mut self, device: narf_bus::BusDevice) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.reset.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        // SAFETY: forwarded exclusive GPU/config-space ownership; no I/O here.
        h.reset = Some(
            unsafe { crate::amdgpu_reset_navi22::Reset::new(&h.gpu, h.authority, device) }
                .map_err(Error::Reset)?,
        );
        Ok(())
    }
    /// Reserve the native VMID0 backing pages and the GART table before run.
    /// Production boot calls
    /// this; explicit firmware-only callers can leave memory hubs untouched.
    /// The whole-GPU ownership contract established by new continues to apply.
    pub fn prepare_memory_hubs(&mut self) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.gmc.is_some() {
            return Err(Error::Busy);
        }
        if self.sequence.backend.firmware.power.is_none() {
            return Err(Error::Invalid);
        }
        let hardware = &mut self.sequence.backend;
        // SAFETY: the cold-boot constructor owns the physical GPU/pool and all
        // clients. This constructor reserves pages but performs no hardware I/O.
        hardware.gmc = Some(
            unsafe {
                crate::amdgpu_gmc_navi22::Gmc::new(
                    &hardware.gpu,
                    hardware.authority,
                    &hardware.pool,
                )
            }
            .map_err(Error::MemoryHubs)?,
        );
        if let Some(gmc) = hardware.gmc.as_mut() {
            gmc.prepare_gart().map_err(Error::MemoryHubs)?;
        }
        Ok(())
    }
    /// The live memory-hub owner (GART, GTT binding, per-client VMs and fault
    /// attribution) after a completed boot, including after `take_psp`.
    pub fn memory(&mut self) -> Result<&mut crate::amdgpu_gmc_navi22::Gmc, Error> {
        if !matches!(
            self.sequence.state,
            State::FirmwareReady(_) | State::Released
        ) {
            return Err(Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(Error::Invalid)?;
        if gmc.gart().is_none() {
            return Err(Error::Invalid);
        }
        Ok(gmc)
    }
    /// Reserve SDMA0 ring/writeback storage before run, after memory hubs have
    /// been prepared. This performs no I/O and exposes no submission API.
    pub fn prepare_sdma(&mut self) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.sdma.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        if h.gmc.is_none() {
            return Err(Error::Invalid);
        }
        // SAFETY: forwarded whole-GPU/pool ownership; constructor has no I/O.
        h.sdma = Some(
            unsafe { crate::amdgpu_sdma_navi22::Sdma::new(&h.gpu, h.authority, &h.pool) }
                .map_err(Error::Sdma)?,
        );
        Ok(())
    }
    /// Reserve GFX ring, KIQ/compute and both production SDMA queues before
    /// run. Memory hubs and the SDMA0 proof must already be prepared; no I/O.
    pub fn prepare_queues(
        &mut self,
        doorbells: crate::amdgpu_cp_navi22::Doorbells,
    ) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.queues.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        if h.gmc.is_none() || h.sdma.is_none() {
            return Err(Error::Invalid);
        }
        // SAFETY: forwarded whole-GPU/pool/BAR2 ownership; constructors only
        // reserve VRAM. Stage order keeps the SDMA0 proof ahead of takeover.
        let queues = unsafe {
            Queues {
                doorbells,
                gfx: crate::amdgpu_cp_navi22::Gfx::new(&h.gpu, h.authority, &h.pool, doorbells)
                    .map_err(Error::Queues)?,
                compute: crate::amdgpu_kiq_navi22::Compute::new(
                    &h.gpu,
                    h.authority,
                    &h.pool,
                    doorbells,
                )
                .map_err(Error::Queues)?,
                sdma: crate::amdgpu_sdma_navi22_queues::Sdma::new(
                    &h.gpu,
                    h.authority,
                    &h.pool,
                    doorbells,
                )
                .map_err(Error::Queues)?,
            }
        };
        h.queues = Some(queues);
        Ok(())
    }
    /// Reserve VCN/JPEG VCPU, ring and IB-test storage for the unharvested
    /// VCN instances after the kernel queues (their doorbell page). No I/O;
    /// a set with every VCN instance harvested prepares nothing.
    pub fn prepare_media(
        &mut self,
        doorbells: crate::amdgpu_cp_navi22::Doorbells,
    ) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.media.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        if h.gmc.is_none() || h.queues.is_none() {
            return Err(Error::Invalid);
        }
        let instances = h.firmware.graphics.vcn_instances();
        if instances == 0 {
            return Ok(());
        }
        let bytes = h.firmware.graphics.vcn_size().ok_or(Error::Invalid)?;
        // SAFETY: forwarded whole-GPU/pool/BAR2 ownership; reservations only.
        h.media = Some(
            unsafe {
                crate::amdgpu_vcn_navi22::Media::new(
                    &h.gpu,
                    h.authority,
                    &h.pool,
                    doorbells,
                    instances,
                    bytes,
                )
            }
            .map_err(Error::Media)?,
        );
        Ok(())
    }
    /// Reserve the IH ring/writeback and NBIO dummy page before run, after
    /// memory hubs have been prepared. Host vector routing waits for run.
    pub fn prepare_interrupts(&mut self, device: narf_bus::BusDevice) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.ih.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        if h.gmc.is_none() {
            return Err(Error::Invalid);
        }
        // SAFETY: forwarded whole-GPU/pool/PCI ownership; no I/O here.
        h.ih = Some(
            unsafe { crate::amdgpu_ih_navi22::Ih::new(&h.gpu, h.authority, &h.pool, device) }
                .map_err(Error::Interrupts)?,
        );
        Ok(())
    }
    /// IH dispatch endpoint, valid from preparation onward; waiters receive
    /// a terminal error if the ring never starts or the device is lost.
    pub fn interrupts(&self) -> Option<crate::amdgpu_ih_navi22::Handle> {
        self.sequence
            .backend
            .ih
            .as_ref()
            .map(crate::amdgpu_ih_navi22::Ih::handle)
    }
    /// Reserve DCN3.0 DMUB backing. Firmware preparation and memory hubs must
    /// precede this call; quiesce/start remain part of the ordered run.
    pub fn prepare_dmub(&mut self) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.dmub.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        if h.gmc.is_none() {
            return Err(Error::Invalid);
        }
        let prepared = h.firmware.dmub.take().ok_or(Error::Invalid)?;
        // SAFETY: the whole GPU/pool belongs to this owner; no I/O here.
        h.dmub = Some(
            unsafe { crate::amdgpu_dmub_navi22::Dmub::new(&h.gpu, h.authority, &h.pool, prepared) }
                .map_err(Error::Dmub)?,
        );
        Ok(())
    }
    /// Claim the native DDC/AUX/HPD owner for the prepared board routes. No
    /// I/O; detection runs only after firmware readiness.
    pub fn prepare_display(&mut self) -> Result<(), Error> {
        if self.sequence.state != State::Prepared || self.sequence.backend.display.is_some() {
            return Err(Error::Busy);
        }
        let h = &mut self.sequence.backend;
        let prep = h.firmware.display.take().ok_or(Error::Invalid)?;
        let (paths, crystal) = (prep.paths, prep.crystal);
        h.display_bios = Some((prep.vbios, crystal));
        // SAFETY: this owner holds the whole GPU exclusively; DMUB AUX stays
        // disabled unless explicitly allowed, so no firmware AUX client exists.
        h.display = Some(
            unsafe {
                crate::amdgpu_navi22_display::Display::new(&h.gpu, h.authority, &paths, crystal)
            }
            .map_err(Error::Display)?,
        );
        Ok(())
    }
    /// Detect every board connector over native AUX/DDC/HPD after the firmware
    /// sequence. Reads sinks only; no stream or scanout is changed.
    pub async fn detect_displays(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_display::Report>, Error> {
        self.display_mut()?
            .detect_all()
            .await
            .map_err(Error::Display)
    }
    fn display_mut(&mut self) -> Result<&mut crate::amdgpu_navi22_display::Display, Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_)) {
            return Err(Error::Busy);
        }
        self.sequence.backend.display.as_mut().ok_or(Error::Invalid)
    }
    pub fn display_connectors(&self) -> Option<&[crate::amdgpu_navi22_display::Connector]> {
        self.sequence
            .backend
            .display
            .as_ref()
            .map(crate::amdgpu_navi22_display::Display::connectors)
    }
    /// Light a connector natively with a colour-bar test pattern
    /// (`amdgpu_navi22_modeset`): a connected HDMI sink if there is one, else
    /// the first DisplayPort sink with EDID and receiver caps
    /// ([`crate::amdgpu_navi22_modeset::choose`]). Off unless the platform
    /// opts in; requires firmware readiness, the retained SMU and the display
    /// owner. The GOP's stream, if still lit, is retired first. The pipeline
    /// is retained, lit or failed; there is no retry.
    ///
    /// # Safety
    /// No other display, DMUB or VBIOS client may run, and nothing may write
    /// the new scanout except through the returned framebuffer.
    pub async unsafe fn modeset_hdmi(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_modeset::Output, Error> {
        use crate::amdgpu_navi22_modeset as modeset;
        let reports = self.detect_displays().await?;
        let Some((connector, sink)) = modeset::choose(&reports) else {
            return Err(Error::Modeset(modeset::Error::NoSink));
        };
        let sink = sink.clone();
        // SAFETY: forwarded unchanged.
        unsafe {
            self.modeset_display(connector, &sink, None, modeset::test_pattern)
                .await
        }
    }
    /// HDP flush for CPU writes to the native scanout.
    pub fn flush_display_scanout(&mut self) -> Result<(), Error> {
        self.sequence
            .backend
            .modeset
            .as_mut()
            .ok_or(Error::Invalid)?
            .flush()
            .map_err(Error::Modeset)
    }
    pub fn modeset_state(&self) -> Option<crate::amdgpu_navi22_modeset::State> {
        self.sequence.backend.modeset.as_ref().map(|p| p.state())
    }
    /// Re-enable the DMUB AUX/HPD transport (Linux `enable_dmub_aux_for_legacy_ddc`).
    /// It is still refused unless the running firmware answered
    /// QUERY_FEATURE_CAPS; `dmub_feature_caps` has no AUX bit to check.
    pub fn allow_dmub_aux(&mut self) {
        self.sequence.backend.dmub_aux = true;
    }
    pub fn training_data(&self) -> Option<&[u8]> {
        self.sequence
            .backend
            .training
            .as_ref()
            .and_then(gddr6::Trainer::training_data)
    }
    /// See [`Firmware::uapi_versions`]; the set this owner loads.
    pub fn uapi_versions(&self) -> Option<crate::amdgpu_info_navi22::Firmware> {
        self.sequence.backend.firmware.uapi_versions()
    }
    pub fn state(&self) -> State {
        self.sequence.state
    }
    /// Preserves the last GC sample for timeout/removal diagnostics.
    pub fn gfx_boot_status(&self) -> Option<psp::GfxBootStatus> {
        self.sequence
            .backend
            .psp
            .as_ref()
            .and_then(psp::Psp::gfx_boot_status)
    }
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.sequence.run().await
    }
    fn dmub_mut(&mut self) -> Result<&mut crate::amdgpu_dmub_navi22::Dmub, Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_))
            || self.sequence.backend.psp.is_none()
        {
            return Err(Error::Busy);
        }
        self.sequence.backend.dmub.as_mut().ok_or(Error::Invalid)
    }
    fn dmub_aux_mut(&mut self) -> Result<&mut crate::amdgpu_dmub_navi22::Dmub, Error> {
        let allowed = self.sequence.backend.dmub_aux;
        let dmub = self.dmub_mut()?;
        if !allowed || dmub.status().and_then(|s| s.capabilities).is_none() {
            return Err(Error::Dmub(crate::amdgpu_dmub_navi22::Error::Unsupported));
        }
        Ok(dmub)
    }
    pub fn dmub_mailbox_state(&self) -> Option<crate::amdgpu_dmub_navi22::MailboxState> {
        self.sequence
            .backend
            .dmub
            .as_ref()
            .map(|d| d.mailbox_state())
    }
    /// DMUB AUX/HPD transport, refused unless `allow_dmub_aux` was called and
    /// the firmware reported capabilities. The default path is native
    /// (`detect_displays`). The instance is the DCN AUX/HPD index.
    pub async fn dmub_hpd(&mut self, instance: u8) -> Result<bool, Error> {
        self.dmub_aux_mut()?
            .hpd(instance)
            .await
            .map_err(Error::Dmub)
    }
    pub async fn dmub_aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.dmub_aux_mut()?
            .aux(instance, action, address, data)
            .await
            .map_err(Error::Dmub)
    }
    pub fn dmub_notification(&mut self) -> Result<Option<[u8; 64]>, Error> {
        self.dmub_mut()?.poll_notification().map_err(Error::Dmub)
    }
    /// Board limits of the retained SMU owner once boot power setup ran.
    pub fn power_limits(&self) -> Option<smu::Limits> {
        if !matches!(self.sequence.state, State::FirmwareReady(_)) {
            return None;
        }
        let h = &self.sequence.backend;
        h.power_status.and(h.smu.as_ref()?.limits())
    }
    /// One PMFW telemetry refresh through the retained SMU owner after a
    /// completed boot. It shares only the PPSMC mailbox and the retained
    /// transfer buffer, both serialized by the caller's owner lock.
    pub(crate) async fn power_sample(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_power::Sample, Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_))
            || self.sequence.backend.power_status.is_none()
        {
            return Err(Error::Busy);
        }
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        let telemetry = smu.read_telemetry().await;
        Ok(crate::amdgpu_navi22_power::Sample {
            protected: telemetry.is_ok_and(|t| smu.protected(t.enabled)),
            telemetry,
            limits: smu.limits(),
        })
    }
    /// Arm the SMU11 THM/MP1 alert sources after a completed boot with power
    /// setup (Linux smu_smc_hw_setup runs after IH hw_init). Returns the
    /// acknowledge handle the SMU-to-driver handler uses.
    pub(crate) async fn enable_thermal_alert(
        &mut self,
    ) -> Result<(smu::Alert, smu::InterruptAck), Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_))
            || self.sequence.backend.power_status.is_none()
        {
            return Err(Error::Busy);
        }
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        let alert = smu.enable_thermal_alert().await.map_err(Error::Smu)?;
        Ok((alert, smu.interrupt_ack()))
    }
    /// `ReenableAcDcInterrupt` for an AC/DC SMU-to-driver interrupt.
    pub(crate) async fn reenable_acdc(&mut self) -> Result<(), Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_)) {
            return Err(Error::Busy);
        }
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        smu.reenable_acdc_interrupt().await.map_err(Error::Smu)
    }
    /// Every kernel queue passed its ring and IB tests.
    pub fn queues_verified(&self) -> bool {
        matches!(self.sequence.state, State::FirmwareReady(_))
            && self
                .sequence
                .backend
                .queues
                .as_ref()
                .and_then(Queues::proof)
                .is_some()
    }
    /// TDR sample of every verified kernel queue; empty without queues.
    pub(crate) fn queue_progress(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_tdr::Progress>, Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_)) {
            return Err(Error::Busy);
        }
        let mut samples = alloc::vec::Vec::new();
        let Some(queues) = self.sequence.backend.queues.as_mut() else {
            return Ok(samples);
        };
        if queues.proof().is_none() {
            return Ok(samples);
        }
        samples
            .try_reserve_exact(5)
            .map_err(|_| Error::Allocation)?;
        samples.push(queues.gfx.progress().map_err(Error::Queues)?);
        samples.extend(queues.compute.progress().map_err(Error::Queues)?);
        samples.extend(queues.sdma.progress().map_err(Error::Queues)?);
        Ok(samples)
    }
    /// Whether `into_recovery` can rebuild this owner: a completed boot with
    /// a board power table and IH, and no GDDR6 training to replay (Linux
    /// replays it as `PSP_MEM_TRAIN_RESUME`; NARF has no short training).
    pub fn recoverable(&self) -> bool {
        let h = &self.sequence.backend;
        matches!(self.sequence.state, State::FirmwareReady(_))
            && h.training.is_none()
            && h.firmware.power.is_some()
            && h.psp.is_some()
            && h.ih.is_some()
    }
    /// Recovery quiesce: bounded `navi10_ih_irq_disable`, after which every
    /// IH subscriber (fence routing, thermal) has received `Disabled`.
    ///
    /// # Safety
    /// Recovery's contract (`amdgpu_navi22_platform::recover`): this owner is
    /// about to be reset, and no consumer depends on IH delivery any more.
    pub(crate) async unsafe fn quiesce_for_reset(&mut self) -> Result<(), Error> {
        if !self.recoverable() {
            return Err(Error::Busy);
        }
        // The reset discards PMFW's GFXOFF state; the recovered boot keeps
        // every power-saving feature off.
        crate::amdgpu_navi22_gfxoff::forget_for_reset();
        let ih = self.sequence.backend.ih.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: forwarded recovery contract; the ring is quarantined.
        unsafe { ih.disable().await }.map_err(Error::Interrupts)
    }
    /// Rebuild a fresh cold-boot owner for `amdgpu_device_gpu_recover`: the
    /// same GPU snapshot, authority, pool and prepared firmware, a
    /// `Reset::new_recovery` mode1 reset in `ResetOnInit`, and newly reserved
    /// memory hubs, SDMA proof, IH and kernel queues (same BAR2 doorbells).
    /// With the first boot's display routes, DMUB storage and the native
    /// display owner are prepared again, so the run restarts DMUB as cold
    /// boot did; the modeset is the platform's (`amdgpu_navi22_kms`).
    /// Every old owner is dropped without I/O, so its
    /// published VRAM stays quarantined. No device I/O happens here.
    ///
    /// # Safety
    /// `quiesce_for_reset` completed, `device` is this GPU's PCI function
    /// and recovery's whole-device contract holds. Run the result once.
    pub(crate) unsafe fn into_recovery(self, device: narf_bus::BusDevice) -> Result<Self, Error> {
        if !self.recoverable() {
            return Err(Error::Busy);
        }
        let Hardware {
            gpu,
            authority,
            pool,
            mut firmware,
            queues,
            display,
            display_bios,
            ..
        } = self.sequence.backend;
        // Linux's DM resume re-lights the display: DMUB restarts in the
        // recovered sequence exactly as on cold boot (amdgpu_navi22_kms).
        let relight = match (display, display_bios) {
            (Some(display), Some((vbios, crystal))) => {
                let paths = display.connectors().iter().map(|c| c.path).collect();
                firmware.restore_display(vbios, crystal, paths).is_ok()
            }
            _ => false,
        };
        let doorbells = queues.as_ref().map(|q| q.doorbells);
        drop(queues);
        // SAFETY: forwarded exclusive whole-GPU contract; the mode1 reset
        // below runs before any firmware stage touches the device.
        let mut boot = unsafe { Self::new(&gpu, authority, &pool, firmware) }?;
        let h = &mut boot.sequence.backend;
        // SAFETY: forwarded recovery contract; construction has no I/O.
        h.reset = Some(
            unsafe { crate::amdgpu_reset_navi22::Reset::new_recovery(&h.gpu, h.authority, device) }
                .map_err(Error::Reset)?,
        );
        boot.prepare_memory_hubs()?;
        boot.prepare_sdma()?;
        boot.prepare_interrupts(device)?;
        if relight {
            boot.prepare_dmub()?;
            boot.prepare_display()?;
        }
        if let Some(doorbells) = doorbells {
            boot.prepare_queues(doorbells)?;
        }
        Ok(boot)
    }
    /// Transfer the live ring/TMR owner after full firmware success. It must
    /// remain alive for subsequent GPU initialization; dropping it quarantines
    /// device-owned VRAM. Reset all consumers before calling its unsafe stop.
    pub fn take_psp(&mut self) -> Result<psp::Psp, Error> {
        if !matches!(self.sequence.state, State::FirmwareReady(_)) {
            return Err(Error::Busy);
        }
        let psp = self.sequence.backend.psp.take().ok_or(Error::Invalid)?;
        self.sequence.backend.smu.take();
        self.sequence.state = State::Released;
        Ok(psp)
    }
    /// Queue client IBs on a verified kernel queue under `vm`
    /// (`amdgpu_navi22_submit`). `Busy` means the ring already has two
    /// submissions outstanding; wait for [`ColdBoot::fences`]'s throttle
    /// sequence (without holding this owner) and retry.
    pub fn submit(
        &mut self,
        ring: crate::amdgpu_navi22_submit::Ring,
        state: &mut crate::amdgpu_navi22_submit::RingState,
        vm: crate::amdgpu_navi22_submit::VmRef,
        context: u64,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
    ) -> Result<u32, Error> {
        use crate::amdgpu_navi22_submit::Ring;
        if !self.queues_verified() {
            return Err(Error::Busy);
        }
        let queues = self
            .sequence
            .backend
            .queues
            .as_mut()
            .ok_or(Error::Invalid)?;
        match ring {
            Ring::Gfx => queues.gfx.submit(state, vm, context, ibs),
            Ring::Compute => queues.compute.submit(state, vm, context, ibs),
            Ring::Sdma(i) => queues.sdma.submit(i, state, vm, context, ibs),
        }
        .map_err(Error::Queues)
    }
    /// Lock-free fence reader over the verified kernel queues (client job
    /// completion for `amdgpu_navi22_cs`).
    pub fn client_fence_reader(&self) -> Option<crate::amdgpu_cp_navi22::FenceReader> {
        if !self.queues_verified() {
            return None;
        }
        let q = self.sequence.backend.queues.as_ref()?;
        Some(q.gfx.fence_reader([
            q.gfx.fence_map(),
            q.compute.fence_map(),
            q.sdma.fence_map(0),
            q.sdma.fence_map(1),
        ]))
    }
    /// A VRAM heap for clients, as Navi48's `publish_client_vram`: half the
    /// pool's free VRAM, 2 MiB-aligned and at least 64 MiB, as a pool of its
    /// own, with the GMC framebuffer translation entries need. The chunk is
    /// published (never recycled) and returned for the caller to retain.
    pub fn reserve_client_vram(
        &mut self,
    ) -> Result<(crate::amdgpu_vram::Reservation, crate::amdgpu_gem::VramHeap), Error> {
        const ALIGN: u64 = 2 << 20;
        let hw = &mut self.sequence.backend;
        let (fb_base, fb_offset) = hw
            .gmc
            .as_ref()
            .and_then(crate::amdgpu_gmc_navi22::Gmc::framebuffer)
            .ok_or(Error::Invalid)?;
        let size = (hw.pool.available() / 2) & !(ALIGN - 1);
        if size < 64 << 20 {
            return Err(Error::Allocation);
        }
        let mut chunk = hw
            .pool
            .reserve_aligned(size, ALIGN)
            .map_err(|_| Error::Allocation)?;
        // SAFETY: the reservation is this heap's alone, inside the owned,
        // CPU-mapped VRAM range the boot inventory produced.
        let pool = unsafe { Pool::from_owned_range(chunk.mapping(), chunk.address()) }
            .map_err(|_| Error::Allocation)?;
        chunk.publish();
        Ok((
            chunk,
            crate::amdgpu_gem::VramHeap {
                pool,
                fb_base,
                fb_offset,
            },
        ))
    }
    /// Hold one GMC10 context (VMID) for client jobs: its context registers
    /// carry the 4-level, 48-bit layout every client space shares, and each
    /// job's ring-side VM flush points it at that job's root.
    pub async fn reserve_client_vmid(&mut self) -> Result<crate::amdgpu_gmc_navi22::Vm, Error> {
        self.memory()?.create_vm().await.map_err(Error::MemoryHubs)
    }
    /// (last completed, throttle) fence sequences of `ring`.
    pub fn fences(&mut self, ring: crate::amdgpu_navi22_submit::Ring) -> Result<(u32, u32), Error> {
        use crate::amdgpu_navi22_submit::Ring;
        if !self.queues_verified() {
            return Err(Error::Busy);
        }
        let queues = self
            .sequence
            .backend
            .queues
            .as_mut()
            .ok_or(Error::Invalid)?;
        match ring {
            Ring::Gfx => queues.gfx.fences(),
            Ring::Compute => queues.compute.fences(),
            Ring::Sdma(i) => queues.sdma.fences(i),
        }
        .map_err(Error::Queues)
    }

    // ── Native display presentation (amdgpu_navi22_kms) ────────────────
    /// Light `connector` with `sink` at `want` (None: its preferred mode),
    /// filling rows with `draw` before fetch starts, then adopt the pipe for
    /// presentation (back buffer on demand, flips, cursor, vblank) and arm
    /// its pflip/vupdate interrupts. A previous pipeline that stopped or
    /// failed is dropped (a failed one keeps its surface quarantined); a
    /// running one refuses. Failure retains the new pipeline for diagnosis.
    ///
    /// # Safety
    /// As `modeset_hdmi`; any previous presentation was stopped through
    /// `stop_display`, and every CPU view of its surfaces has retired.
    pub async unsafe fn modeset_display(
        &mut self,
        connector: crate::amdgpu_navi22_display::Connector,
        sink: &crate::amdgpu_navi22_display::Sink,
        want: Option<crate::amdgpu_dml::Timing>,
        draw: impl Fn(u32, &mut [u32]),
    ) -> Result<crate::amdgpu_navi22_modeset::Output, Error> {
        use crate::amdgpu_navi22_modeset::{self as modeset, State as M, Step};
        self.display_mut()?;
        let h = &mut self.sequence.backend;
        if h.scanout.is_some()
            || h.modeset
                .as_ref()
                .is_some_and(|p| !matches!(p.state(), M::At(Step::Stopped) | M::Failed { .. }))
        {
            return Err(Error::Busy);
        }
        h.modeset = None;
        let (vbios, crystal) = h.display_bios.as_ref().ok_or(Error::Invalid)?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(modeset::Error::Bios(e)))?;
        let board = modeset::Board::from_vbios(vbios, *crystal).map_err(Error::Modeset)?;
        let smu = h.smu.as_mut().ok_or(Error::Invalid)?;
        let display = h.display.as_mut().ok_or(Error::Invalid)?;
        let links: alloc::vec::Vec<_> = display.connectors().to_vec();
        let index = links
            .iter()
            .position(|c| *c == connector)
            .ok_or(Error::Invalid)?;
        // One stream: the DCN3.0 pool from empty (the previous pipeline, if
        // any, stopped or failed and was dropped above).
        let route = modeset::Resources::new()
            .acquire(&connector)
            .map_err(Error::Modeset)?;
        // SAFETY: this cold-boot owner holds the whole GPU; the caller's
        // contract excludes other display clients.
        let mut pipeline = unsafe { modeset::Pipeline::new(&h.gpu, h.authority, connector, route) }
            .map_err(Error::Modeset)?;
        pipeline.request(want);
        pipeline.set_lttpr_policy(crate::amdgpu_dcn30_dp_link::VbiosLttpr::from_vbios(vbios));
        pipeline.assume_link_cap(display.verified_link(index, sink.dpcd));
        let mut aux = crate::amdgpu_navi22_display::DisplayAux { display, index };
        // SAFETY: forwarded; the pool and SMU are this owner's, and the
        // display-power future is polled only by ClockManager::start_with.
        let result = unsafe {
            pipeline
                .enable(
                    crate::amdgpu_dcn30_clk::display_power(smu),
                    &h.pool,
                    &tables,
                    board,
                    &links,
                    sink,
                    &mut aux,
                    draw,
                )
                .await
        };
        // A link that failed to train at its verified setting is verified
        // again next time.
        let verified = match result {
            Err(crate::amdgpu_navi22_modeset::Error::Training(_)) => None,
            _ => pipeline.link_cap(),
        };
        aux.display.set_verified_link(index, sink.dpcd, verified);
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                h.modeset = Some(pipeline);
                return Err(Error::Modeset(error));
            }
        };
        let adopted = (|| {
            let address = pipeline.scanout_address()?;
            let map = pipeline.scanout_mapping()?;
            let refclk = pipeline.admitted()?.refclk_khz;
            Some((address, map, refclk))
        })();
        h.modeset = Some(pipeline);
        let (address, map, refclk) = adopted.ok_or(Error::Invalid)?;
        let front = crate::amdgpu_navi22_scanout::Surface {
            address,
            fb: output.scanout,
        };
        // SAFETY: the pipeline just lit its route's pipe with this surface
        // and both owners live in this cold-boot owner, serialized by its
        // caller.
        let mut scanout = unsafe {
            crate::amdgpu_navi22_scanout::Scanout::new(
                &h.gpu,
                h.authority,
                route.pipe,
                front,
                map,
                output.timing,
                refclk,
            )
        }
        .map_err(|e| Error::Modeset(modeset::Error::Block(e)))?;
        if let Some(ih) = h.ih.as_ref().map(crate::amdgpu_ih_navi22::Ih::handle) {
            if let Err(error) = scanout.enable_interrupts(&ih) {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 flip interrupts unavailable ({error:?}); polling"
                );
            }
        }
        h.scanout = Some(scanout);
        Ok(output)
    }
    /// Stop presenting and tear the lit pipe down. On success both scanout
    /// surfaces return to the pool; on failure everything stays reserved.
    ///
    /// # Safety
    /// Every CPU writer of the scanout has been withdrawn and its views
    /// retired (`scanout_access::wait_retired`); no other display client.
    pub async unsafe fn stop_display(&mut self) -> Result<(), Error> {
        let h = &mut self.sequence.backend;
        let pipeline = h.modeset.as_mut().ok_or(Error::Invalid)?;
        let stopped = h.scanout.as_mut().map(|s| s.stop());
        let (vbios, _) = h.display_bios.as_ref().ok_or(Error::Invalid)?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(crate::amdgpu_navi22_modeset::Error::Bios(e)))?;
        let connector = pipeline.connector();
        let display = h.display.as_mut().ok_or(Error::Invalid)?;
        let index = display
            .connectors()
            .iter()
            .position(|c| *c == connector)
            .ok_or(Error::Invalid)?;
        let mut aux = crate::amdgpu_navi22_display::DisplayAux { display, index };
        pipeline
            .disable(&tables, &mut aux)
            .await
            .map_err(Error::Modeset)?;
        // SAFETY: the pipeline stopped cleanly (HUBP drained and blanked, OTG
        // off) and the caller retired every CPU view.
        unsafe {
            if let Some(scanout) = h.scanout.take() {
                if stopped.is_some_and(|r| r.is_ok()) {
                    let _ = scanout.release();
                }
            }
            let _ = pipeline.release_scanout();
        }
        Ok(())
    }
    /// Light `requests` as one multi-stream context
    /// (`amdgpu_navi22_modeset::Group`: joint DML30 admission, shared
    /// clocks, PLL sharing, ODM, DSC and MST), filling stream k's rows with
    /// `draw(k, y, row)` before fetch. The single-pipe owner must be
    /// stopped (or never lit); a previous context that stopped or failed is
    /// dropped. Its scanouts are static: no flips, back buffers or vblank.
    ///
    /// # Safety
    /// As `modeset_display`, for every stream.
    pub async unsafe fn modeset_group(
        &mut self,
        requests: &[crate::amdgpu_navi22_modeset::Request],
        draw: impl Fn(usize, u32, &mut [u32]),
    ) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_modeset::Output>, Error> {
        use crate::amdgpu_navi22_modeset::{self as modeset, GroupState, Phase, State as M, Step};
        self.display_mut()?;
        let h = &mut self.sequence.backend;
        let single_dark = h.scanout.is_none()
            && h.modeset
                .as_ref()
                .is_none_or(|p| matches!(p.state(), M::At(Step::Stopped) | M::Failed { .. }));
        let group_dark = h.group.as_ref().is_none_or(|g| {
            matches!(
                g.state(),
                GroupState::At(Phase::Stopped) | GroupState::Failed { .. }
            )
        });
        if !single_dark || !group_dark {
            return Err(Error::Busy);
        }
        h.modeset = None;
        h.group = None;
        let (vbios, crystal) = h.display_bios.as_ref().ok_or(Error::Invalid)?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(modeset::Error::Bios(e)))?;
        let board = modeset::Board::from_vbios(vbios, *crystal).map_err(Error::Modeset)?;
        let smu = h.smu.as_mut().ok_or(Error::Invalid)?;
        let display = h.display.as_mut().ok_or(Error::Invalid)?;
        let links: alloc::vec::Vec<_> = display.connectors().to_vec();
        // SAFETY: this cold-boot owner holds the whole GPU; the caller's
        // contract excludes other display clients.
        let mut group = unsafe { modeset::Group::new(&h.gpu, h.authority, requests) }
            .map_err(Error::Modeset)?;
        // SAFETY: forwarded; the pool and SMU are this owner's.
        let result = unsafe {
            group
                .enable(
                    crate::amdgpu_dcn30_clk::display_power(smu),
                    &h.pool,
                    &tables,
                    board,
                    &links,
                    display,
                    draw,
                )
                .await
        };
        h.group = Some(group);
        result.map_err(Error::Modeset)
    }
    /// Stop the multi-stream context; on success every scanout returns to
    /// the pool.
    ///
    /// # Safety
    /// Every CPU writer of its scanouts was withdrawn and its views retired.
    pub async unsafe fn stop_group(&mut self) -> Result<(), Error> {
        let h = &mut self.sequence.backend;
        let group = h.group.as_mut().ok_or(Error::Invalid)?;
        let (vbios, _) = h.display_bios.as_ref().ok_or(Error::Invalid)?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(crate::amdgpu_navi22_modeset::Error::Bios(e)))?;
        let display = h.display.as_mut().ok_or(Error::Invalid)?;
        group
            .disable(&tables, display)
            .await
            .map_err(Error::Modeset)?;
        for m in group.members_mut() {
            // SAFETY: stopped cleanly; the caller retired every CPU view.
            let _ = unsafe { m.release_scanout() };
        }
        Ok(())
    }
    /// The running multi-stream context's outputs, in request order.
    pub fn group_outputs(&self) -> Option<alloc::vec::Vec<crate::amdgpu_navi22_modeset::Output>> {
        use crate::amdgpu_navi22_modeset::{GroupState, Phase};
        let g = self.sequence.backend.group.as_ref()?;
        if g.state() != GroupState::At(Phase::Running) {
            return None;
        }
        g.members().iter().map(|m| m.output()).collect()
    }
    /// The multi-stream context's admission, for the power policy.
    pub fn group(&self) -> Option<&crate::amdgpu_navi22_modeset::Group> {
        self.sequence.backend.group.as_ref()
    }
    /// HDP flush for the context's first scanout (the console's).
    pub fn flush_group_scanout(&mut self) -> Result<(), Error> {
        let g = self.sequence.backend.group.as_mut().ok_or(Error::Invalid)?;
        g.members_mut()
            .first_mut()
            .ok_or(Error::Invalid)?
            .flush()
            .map_err(Error::Modeset)
    }
    /// The presentation owner of the lit pipe.
    pub fn display_scanout(
        &mut self,
    ) -> Result<&mut crate::amdgpu_navi22_scanout::Scanout, crate::amdgpu_dcn_clk::Error> {
        self.sequence
            .backend
            .scanout
            .as_mut()
            .ok_or(crate::amdgpu_dcn_clk::Error::Invalid)
    }
    pub fn display_scanout_ref(&self) -> Option<&crate::amdgpu_navi22_scanout::Scanout> {
        self.sequence.backend.scanout.as_ref()
    }
    /// The DCN30 admission of the lit (or last attempted) sink.
    pub fn display_admitted(&self) -> Option<&crate::amdgpu_navi22_modeset::Admitted> {
        self.sequence.backend.modeset.as_ref()?.admitted()
    }
    pub fn display_output(&self) -> Option<crate::amdgpu_navi22_modeset::Output> {
        self.sequence.backend.modeset.as_ref()?.output()
    }
    /// Split borrows for presentation: the scanout, the pool and the
    /// pipeline's HDP flush.
    #[allow(clippy::type_complexity, reason = "a split borrow of three owners")]
    fn presentation(
        &mut self,
    ) -> Result<
        (
            &mut crate::amdgpu_navi22_scanout::Scanout,
            &Pool,
            impl FnMut() -> Result<(), crate::amdgpu_dcn_clk::Error> + '_,
        ),
        crate::amdgpu_dcn_clk::Error,
    > {
        use crate::amdgpu_dcn_clk::Error as E;
        let h = &mut self.sequence.backend;
        let scanout = h.scanout.as_mut().ok_or(E::Invalid)?;
        let pipeline = h.modeset.as_mut().ok_or(E::Invalid)?;
        let flush = move || {
            pipeline.flush().map_err(|e| match e {
                crate::amdgpu_navi22_modeset::Error::Block(e) => e,
                crate::amdgpu_navi22_modeset::Error::Unsupported => E::Unsupported,
                _ => E::Busy,
            })
        };
        Ok((scanout, &h.pool, flush))
    }
    /// Reserve and clear the back buffer of the lit pipe.
    pub async fn prepare_display_back_buffer(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_scanout::Surface, crate::amdgpu_dcn_clk::Error> {
        let (scanout, pool, flush) = self.presentation()?;
        scanout.prepare_back(pool, flush).await
    }
    /// Flip the lit pipe to its back buffer (HDP flush first).
    pub async fn flip_display(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_scanout::FlipDone, crate::amdgpu_dcn_clk::Error> {
        let (scanout, _, flush) = self.presentation()?;
        scanout.flip(flush).await
    }
    /// Show (upload once) a premultiplied ARGB cursor image on the lit pipe.
    pub fn set_display_cursor(
        &mut self,
        image: (u32, u32, &[u32]),
        at: (i32, i32),
    ) -> Result<crate::amdgpu_dcn30_cursor::Shown, crate::amdgpu_dcn_clk::Error> {
        let (scanout, pool, flush) = self.presentation()?;
        scanout.set_cursor(pool, image, at, flush)
    }
}

/// Hot-plug and DP link maintenance of the lit display (Linux's
/// `handle_hpd_irq` / `handle_hpd_rx_irq` → `dc_link_detect`,
/// `dp_handle_link_loss`, and the zero-stream commit after an unplug), for
/// the display monitor in `amdgpu_navi22_platform`.
impl ColdBoot {
    /// Debounced HPD of every board connector, in table order (None: no
    /// HPD wiring or unreadable).
    pub fn display_hpd_senses(&mut self) -> alloc::vec::Vec<Option<bool>> {
        let Ok(display) = self.display_mut() else {
            return alloc::vec::Vec::new();
        };
        (0..display.connectors().len())
            .map(|i| display.hpd_sense(i).ok().flatten())
            .collect()
    }
    /// Forget connector `index`'s verified DP link (its sink left or
    /// changed): the next lighting verifies again, as the next long-pulse
    /// detection does in Linux.
    pub fn forget_display_link(&mut self, index: usize) {
        if let Ok(display) = self.display_mut() {
            display.set_verified_link(index, None, None);
        }
    }
    /// Connector `index`'s verified DP link for a sink reporting `dpcd`.
    pub fn display_link_cap(
        &mut self,
        index: usize,
        dpcd: Option<[u8; 16]>,
    ) -> Option<crate::amdgpu_navi22_modeset::DpLink> {
        self.display_mut().ok()?.verified_link(index, dpcd)
    }
    /// The lit pipeline, its connector's index and the VBIOS tables' bytes.
    fn lit_display(
        &mut self,
    ) -> Result<
        (
            &mut crate::amdgpu_navi22_modeset::Pipeline,
            crate::amdgpu_navi22_display::DisplayAux<'_>,
            &[u8],
        ),
        Error,
    > {
        let h = &mut self.sequence.backend;
        let pipeline = h.modeset.as_mut().ok_or(Error::Invalid)?;
        let (vbios, _) = h.display_bios.as_ref().ok_or(Error::Invalid)?;
        let connector = pipeline.connector();
        let display = h.display.as_mut().ok_or(Error::Invalid)?;
        let index = display
            .connectors()
            .iter()
            .position(|c| *c == connector)
            .ok_or(Error::Invalid)?;
        Ok((
            pipeline,
            crate::amdgpu_navi22_display::DisplayAux { display, index },
            vbios.as_slice(),
        ))
    }
    /// Check the lit DP stream's link (an HPD-RX short pulse, or the
    /// monitor's periodic poll); nothing for HDMI or no stream.
    pub async fn check_display_link(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_modeset::RxEvent, Error> {
        let (pipeline, mut aux, _) = self.lit_display()?;
        pipeline
            .check_dp_link(&mut aux)
            .await
            .map_err(Error::Modeset)
    }
    /// `dp_handle_link_loss` on the lit DP stream: the link stopped and
    /// trained again at the same setting while scanout continues. On
    /// failure the link is down and the caller stops the display
    /// (`stop_display`); the connector's verified link is forgotten so the
    /// next lighting falls back from a fresh verification.
    ///
    /// # Safety
    /// As `stop_display`'s exclusions for the display engine; the scanout
    /// surfaces stay published.
    pub async unsafe fn retrain_display(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_modeset::DpLink, Error> {
        let (pipeline, mut aux, vbios) = self.lit_display()?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(crate::amdgpu_navi22_modeset::Error::Bios(e)))?;
        let result = pipeline.retrain(&tables, &mut aux).await;
        if result.is_err() {
            aux.display.set_verified_link(aux.index, None, None);
        }
        result.map_err(Error::Modeset)
    }
    /// Stop the lit display after its sink left: refused while its HPD is
    /// high; no AUX/DDC transaction to the sink; surfaces released as in
    /// `stop_display`.
    ///
    /// # Safety
    /// As `stop_display`.
    pub async unsafe fn stop_unplugged_display(&mut self) -> Result<(), Error> {
        {
            let (_, aux, _) = self.lit_display()?;
            if aux.display.hpd_sense(aux.index).map_err(Error::Display)? == Some(true) {
                return Err(Error::Busy);
            }
            aux.display.set_verified_link(aux.index, None, None);
        }
        let h = &mut self.sequence.backend;
        let stopped = h.scanout.as_mut().map(|s| s.stop());
        let (pipeline, mut ddc, vbios) = self.lit_display()?;
        let tables = crate::amdgpu_navi22_bios::Tables::new(vbios)
            .map_err(|e| Error::Modeset(crate::amdgpu_navi22_modeset::Error::Bios(e)))?;
        pipeline
            .disable_unplugged(&tables, &mut ddc)
            .await
            .map_err(Error::Modeset)?;
        let h = &mut self.sequence.backend;
        let pipeline = h.modeset.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: as stop_display: stopped cleanly, CPU views retired.
        unsafe {
            if let Some(scanout) = h.scanout.take() {
                if stopped.is_some_and(|r| r.is_ok()) {
                    let _ = scanout.release();
                }
            }
            let _ = pipeline.release_scanout();
        }
        Ok(())
    }
}

/// IH-driven HPD (`amdgpu_dm_hpd_init` / `dm_irq_handler`) for the native
/// display owner.
impl ColdBoot {
    /// Subscribe to the DCN HPD source, then arm every connector's HPD (and
    /// DP HPD_RX) interrupt. Polling detection keeps working without it.
    pub fn arm_display_hpd(&mut self) -> Result<crate::amdgpu_ih_navi22::Subscription, Error> {
        let ih = self.interrupts().ok_or(Error::Invalid)?;
        let subscription = ih
            .subscribe(crate::amdgpu_ih_navi22::source::DCN_HPD)
            .map_err(|_| Error::Busy)?;
        self.display_mut()?
            .arm_hpd_interrupts()
            .map_err(Error::Display)?;
        Ok(subscription)
    }
    /// Acknowledge one HPD/HPD_RX vector; returns the connector index.
    pub fn display_hpd(
        &mut self,
        hpd: crate::amdgpu_ih_navi22::Hpd,
    ) -> Result<Option<usize>, Error> {
        self.display_mut()?
            .hpd_event(hpd.instance, hpd.rx)
            .map_err(Error::Display)
    }
}

/// The explicit `amdgpu.navi22_pg` opt-in (amdgpu_navi22_power_saving).
/// Never reached on a default boot.
impl ColdBoot {
    fn power_saving_parts(
        &mut self,
    ) -> Result<
        (
            crate::amdgpu_navi22_power_saving::Parts<'_>,
            &mut Option<crate::amdgpu_navi22_power_saving::Retained>,
        ),
        Error,
    > {
        if !matches!(self.sequence.state, State::FirmwareReady(_))
            || self.sequence.backend.power_status.is_none()
        {
            return Err(Error::Busy);
        }
        let admission = self.display_admitted().map(|admitted| {
            crate::amdgpu_navi22_kms::display_admission(
                admitted,
                u8::from(self.display_output().is_some()),
            )
        });
        let h = &mut self.sequence.backend;
        let smu = h.smu.as_mut().ok_or(Error::Invalid)?;
        Ok((
            crate::amdgpu_navi22_power_saving::Parts {
                gpu: &h.gpu,
                authority: h.authority,
                pool: &h.pool,
                smu,
                pipeline: h.modeset.as_mut(),
                admission,
            },
            &mut h.power_saving,
        ))
    }
    /// Apply the opted-in features the policy admits, once per boot.
    ///
    /// # Safety
    /// Called with the platform owner lock held and the GFXOFF controller
    /// not started; every GC MMIO client holds a GFXOFF reference.
    pub(crate) async unsafe fn apply_power_saving(
        &mut self,
        optin: crate::amdgpu_navi22_power_policy::OptIn,
    ) -> Result<crate::amdgpu_navi22_power_saving::Applied, Error> {
        let (parts, retained) = self.power_saving_parts()?;
        // SAFETY: forwarded caller contract; parts are this completed boot's.
        unsafe { crate::amdgpu_navi22_power_saving::apply(parts, optin, retained) }
            .await
            .map_err(Error::PowerSaving)
    }
    /// Undo `apply_power_saving`.
    ///
    /// # Safety
    /// As `apply_power_saving`, with the GFXOFF controller stopped.
    pub(crate) async unsafe fn remove_power_saving(&mut self) -> Result<(), Error> {
        let (parts, retained) = self.power_saving_parts()?;
        // SAFETY: forwarded caller contract.
        unsafe { crate::amdgpu_navi22_power_saving::remove(parts, retained) }
            .await
            .map_err(Error::PowerSaving)
    }
    /// What the opt-in applied (None on a default boot).
    pub fn power_saving(&self) -> Option<crate::amdgpu_navi22_power_saving::Applied> {
        self.sequence
            .backend
            .power_saving
            .as_ref()
            .and_then(crate::amdgpu_navi22_power_saving::Retained::applied)
    }
    /// AllowGfxOff/DisallowGfxOff for the GFXOFF controller, refused unless
    /// the opt-in enabled FEATURE_GFXOFF.
    pub(crate) async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        if self.power_saving().is_none_or(|applied| {
            applied.smu_bits & crate::amdgpu_navi22_power_policy::SMU_GFXOFF == 0
        }) {
            return Err(Error::Busy);
        }
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        smu.gfx_off_control(allow).await.map_err(Error::Smu)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_boot_tests.rs"]
pub(crate) mod tests;

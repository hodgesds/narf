//! Ordered, retained Navi48 cold-boot firmware ownership. No automatic probe
//! writes: callers must establish exclusive GPU/VRAM ownership first.
use crate::amdgpu_dcn401_clk as clocks;
use crate::amdgpu_dcn401_dccg as dccg;
use crate::amdgpu_dcn401_otg as otg;
use crate::amdgpu_ddc_navi48 as ddc;
use crate::amdgpu_gfx12_queue as queues;
use crate::amdgpu_gfx12_rs64 as rs64;
use crate::amdgpu_gfx12_setup as setup;
use crate::amdgpu_ih7 as ih;
use crate::amdgpu_mes12_hw as mes;
use crate::amdgpu_navi48_faults as faults;
use crate::amdgpu_navi48_msi as msi;
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_dmub_navi48 as dmub, amdgpu_gddr6 as training,
    amdgpu_gfx12_topology as topology, amdgpu_gmc_navi48 as gmc, amdgpu_navi48_firmware as gfx,
    amdgpu_psp_boot as sos, amdgpu_psp_ring as psp, amdgpu_sdma_navi48 as sdma,
    amdgpu_smu_navi48 as smu, amdgpu_vram::Pool, amdgpu_vram_boot::Training,
};
use crate::{amdgpu_dcn_inventory as inventory, amdgpu_navi48_display as display};
use alloc::vec::Vec;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::FsError;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    MemoryTraining,
    Sos,
    Ring,
    TrustedMemory,
    Smc,
    SmuVersions,
    ReadBoard,
    UploadBoard,
    StopDmub,
    Graphics,
    RlcBoot,
    ConfigureRs64,
    PowerSetup,
    ReadTopology,
    MemoryTranslation,
    InterruptRings,
    DmaProof,
    SetupGraphics,
    StartMes,
    KernelQueueProof,
    StartDmub,
}
const STAGES: [Stage; 21] = [
    Stage::MemoryTraining,
    Stage::Sos,
    Stage::Ring,
    Stage::TrustedMemory,
    Stage::Smc,
    Stage::SmuVersions,
    Stage::ReadBoard,
    Stage::UploadBoard,
    Stage::StopDmub,
    Stage::Graphics,
    Stage::RlcBoot,
    Stage::ConfigureRs64,
    Stage::PowerSetup,
    Stage::ReadTopology,
    Stage::MemoryTranslation,
    Stage::InterruptRings,
    Stage::DmaProof,
    Stage::SetupGraphics,
    Stage::StartMes,
    Stage::KernelQueueProof,
    Stage::StartDmub,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Training(training::Error),
    Sos(sos::Error),
    Psp(psp::Error),
    Smu(smu::Error),
    Firmware(gfx::Error),
    Gmc(gmc::Error),
    Sdma(sdma::Error),
    Vcn(crate::amdgpu_vcn_navi48::Error),
    Jpeg(crate::amdgpu_jpeg_navi48::Error),
    Dmub(dmub::Error),
    Topology(topology::Error),
    Display(display::Error),
    Rs64(rs64::Error),
    Mes(mes::Error),
    Setup(setup::Error),
    Queues(queues::Error),
    Interrupts(ih::Error),
    Faults(faults::Error),
    Reset(crate::amdgpu_reset_navi22::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    MemoryReady,
    Failed(Stage, Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    pub graphics: psp::GfxBootStatus,
    pub power: smu::PowerStatus,
    pub media: psp::MediaFirmware,
    pub aperture: gmc::Aperture,
    pub dma: sdma::Proof,
    pub dmub: dmub::Status,
    pub topology: topology::Topology,
    pub rs64: rs64::Starts,
    pub mes: mes::Report,
    pub setup: setup::Report,
    pub queues: queues::Proof,
    pub interrupts: ih::Report,
}
#[derive(Debug)]
pub struct Firmware {
    sos: sos::Firmware,
    gfx: gfx::Firmware,
    dmub: Option<dmub::Prepared>,
}
impl Firmware {
    /// The validated IP firmware images (not the SOS or DMCUB preparation).
    pub(crate) fn images(&self) -> Result<[gfx::Image<'_>; 11], Error> {
        self.gfx.images().map_err(Error::Firmware)
    }
    pub fn open(
        gpu: &AmdGpu,
        registry: &Cap<narf_firmware::FirmwareRegistry, Read>,
        mes: gfx::MesMode,
    ) -> Result<Self, Error> {
        let sos = sos::Firmware::open(gpu, registry).map_err(Error::Sos)?;
        let gfx = gfx::Firmware::open(gpu, registry, mes).map_err(Error::Firmware)?;
        let bios = gpu.vbios.as_ref().ok_or(Error::Invalid)?;
        let prepared = dmub::Prepared::new(
            gfx.dmcub_bytes(),
            bios.bytes(),
            // dm_dmub_hw_init: hw_params.psp_version = psp.sos.fw_version.
            sos.image().map_err(Error::Sos)?.sos_version(),
        )
        .map_err(Error::Dmub)?;
        Ok(Self {
            sos,
            gfx,
            dmub: Some(prepared),
        })
    }
}
trait Backend {
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
            self.state = State::Running(stage);
            if let Err(e) = self.backend.step(stage).await {
                self.state = State::Failed(stage, e);
                return Err(e);
            }
        }
        let report = self.backend.report().inspect_err(|&e| {
            self.state = State::Failed(Stage::StartDmub, e);
        })?;
        self.state = State::MemoryReady;
        Ok(report)
    }
}
/// Pin the VRAM-offset `range` in whichever pools it falls in, as
/// amdgpu_bo_create_kernel_at pins a fixed range: refused (`Allocation`)
/// if it runs past VRAM, past the BAR with no unmapped pool, or over a
/// range something already allocated.
fn pin_vram(
    pool: &Pool,
    unmapped: Option<&crate::amdgpu_vram::UnmappedPool>,
    vram_size: u64,
    range: core::ops::Range<u64>,
) -> Result<(), Error> {
    if range.is_empty() {
        return Ok(());
    }
    if range.end > vram_size {
        return Err(Error::Allocation);
    }
    let visible = pool.size();
    if range.start < visible {
        pool.claim(range.start..range.end.min(visible))
            .map_err(|_| Error::Allocation)?;
    }
    if range.end > visible {
        unmapped
            .ok_or(Error::Allocation)?
            .claim(range.start.max(visible) - visible..range.end - visible)
            .map_err(|_| Error::Allocation)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MediaRequest {
    keep: bool,
    decode: bool,
    encode: bool,
    jpeg: bool,
    jpeg_decode: bool,
}
impl MediaRequest {
    fn new(keep: bool, decode: bool, encode: bool, jpeg: bool, jpeg_decode: bool) -> Self {
        Self {
            keep,
            decode,
            encode,
            jpeg: jpeg || jpeg_decode || keep,
            jpeg_decode,
        }
    }
    fn ibs(self) -> bool {
        self.keep || self.decode || self.encode || self.jpeg
    }
    fn bytes(self) -> u64 {
        crate::amdgpu_vcn_navi48::proof_bytes(self.ibs(), self.decode, self.encode)
            + if self.jpeg {
                crate::amdgpu_jpeg_navi48::proof_bytes(self.jpeg_decode, self.keep)
            } else {
                0
            }
    }
}
#[derive(Debug)]
struct Hardware {
    media_idle: media_idle::Idle,
    gpu: AmdGpu,
    pci: narf_bus::BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    /// The VRAM past the BAR, if any; `pool` is the CPU-visible prefix.
    unmapped: Option<crate::amdgpu_vram::UnmappedPool>,
    /// psp_hw_start runs psp_update_fw_reservation only when neither in
    /// reset nor in suspend: a cold boot, not the owner `after_reset` makes
    /// for recovery or S3/runtime resume (whose pools keep the pin).
    update_fw_reservation: bool,
    firmware: Firmware,
    dmub: dmub::Dmub,
    trainer: Option<training::Trainer>,
    /// The trainer finished before an ASIC reset; replay its cache
    /// (PSP_MEM_TRAIN_RESUME) instead of cold training.
    training_resume: bool,
    /// Runtime resume from BACO: PMFW kept running, so PSP must not load
    /// SMU firmware again (psp_load_smu_fw's in_runpm BACO/BAMACO skip).
    smu_resident: bool,
    sos: Option<sos::Bootloader>,
    psp: Option<psp::Psp>,
    smu: Option<smu::Smu>,
    versions: Option<smu::Versions>,
    graphics: Option<psp::GfxBootStatus>,
    power: Option<smu::PowerStatus>,
    topology: Option<topology::Topology>,
    rs64: rs64::Rs64,
    setup: setup::Setup,
    ih: Option<ih::Rings>,
    interrupt_report: Option<ih::Report>,
    interrupt_route: Option<Result<msi::Route, msi::Error>>,
    faults: Option<faults::Monitor>,
    gmc: Option<gmc::Gmc>,
    sdma: Option<sdma::Sdma>,
    mes: Option<mes::Mes>,
    queues: Option<queues::Queues>,
    vcn: Option<crate::amdgpu_vcn_navi48::Vcn>,
    jpeg: Option<crate::amdgpu_jpeg_navi48::Jpeg>,
    jpeg_test: Option<Result<crate::amdgpu_jpeg_navi48::Proof, Error>>,
    jpeg_owner: Option<crate::amdgpu_navi48_dispatch::Handle>,
    media_test: Option<Result<crate::amdgpu_vcn_navi48::InterruptProof, Error>>,
    media_request: Option<MediaRequest>,
    media_decode_required: bool,
    media_encode_required: bool,
    media_jpeg_required: bool,
    media_jpeg_decode_required: bool,
    /// Keep JPEG0 running for clients after its proofs (with VCN clients).
    media_jpeg_clients: bool,
    vcn_owner: Option<crate::amdgpu_navi48_dispatch::Handle>,
}
impl Backend for Hardware {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::MemoryTraining => {
                if let Some(t) = &mut self.trainer {
                    if self.training_resume {
                        // SAFETY: after_reset proved the mode1 reset completed
                        // and handed over the retained trainer; no VRAM client
                        // runs before this stage.
                        unsafe { t.resume() }.await.map_err(Error::Training)?;
                    } else {
                        t.run().await.map_err(Error::Training)?;
                    }
                }
            }
            Stage::Sos => {
                // SAFETY: after training, constructor's device/pool ownership persists.
                self.sos = Some(
                    unsafe { sos::Bootloader::new(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Sos)?,
                );
                self.sos
                    .as_mut()
                    .unwrap()
                    .load(&self.firmware.sos)
                    .await
                    .map_err(Error::Sos)?;
            }
            Stage::Ring => {
                // SAFETY: successful SOS/training and exclusive device/pool ownership.
                self.psp = Some(
                    unsafe { psp::Psp::new_navi48(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Psp)?,
                );
                self.psp
                    .as_mut()
                    .unwrap()
                    .start()
                    .await
                    .map_err(Error::Psp)?;
                if self.update_fw_reservation {
                    let sos = self.firmware.sos.image().map_err(Error::Sos)?.sos_version();
                    let reservation = self
                        .psp
                        .as_mut()
                        .unwrap()
                        .update_fw_reservation_navi48(sos, self.gpu.vram.size)
                        .await
                        .map_err(Error::Psp)?;
                    if let Some(r) = reservation {
                        // amdgpu_ttm_mark_vram_reserved for AMDGPU_RESV_FW
                        // then AMDGPU_RESV_FW_EXTEND; either failing fails
                        // psp_hw_start.
                        pin_vram(&self.pool, self.unmapped.as_ref(), self.gpu.vram.size, r.fw)?;
                        pin_vram(
                            &self.pool,
                            self.unmapped.as_ref(),
                            self.gpu.vram.size,
                            r.ext,
                        )?;
                    }
                }
            }
            Stage::TrustedMemory => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .setup_tmr_navi48(&self.firmware.sos)
                .await
                .map_err(Error::Psp)?,
            Stage::Smc if self.smu_resident => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi48 SMU firmware resident across BACO; not reloaded"
                );
            }
            Stage::Smc => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .load_smc_navi48(&self.firmware.gfx)
                .await
                .map_err(Error::Psp)?,
            Stage::SmuVersions => {
                // SAFETY: SMU upload acknowledged; all owners/mappings remain retained.
                self.smu = Some(
                    unsafe { smu::Smu::after_upload(&self.gpu, self.authority, &self.pool) }
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
            Stage::ReadBoard => self
                .smu
                .as_mut()
                .ok_or(Error::Invalid)?
                .read_board()
                .await
                .map_err(Error::Smu)?,
            Stage::UploadBoard => self
                .smu
                .as_mut()
                .ok_or(Error::Invalid)?
                .upload_board()
                .await
                .map_err(Error::Smu)?,
            Stage::StopDmub => self.dmub.quiesce().await.map_err(Error::Dmub)?,
            Stage::Graphics => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .load_gfx_navi48(&self.firmware.gfx)
                .await
                .map_err(Error::Psp)?,
            Stage::RlcBoot => {
                self.graphics = Some(
                    self.psp
                        .as_mut()
                        .ok_or(Error::Invalid)?
                        .wait_gfx_boot_navi48()
                        .await
                        .map_err(Error::Psp)?,
                )
            }
            Stage::PowerSetup => {
                self.power = Some(
                    self.smu
                        .as_mut()
                        .ok_or(Error::Invalid)?
                        .configure_power()
                        .await
                        .map_err(Error::Smu)?,
                )
            }
            Stage::MemoryTranslation => {
                // SAFETY: the owned pool, trained VRAM and accepted firmware
                // persist; automatic gating and all queues are off.
                self.gmc = Some(
                    unsafe { gmc::Gmc::new(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Gmc)?,
                );
                // SAFETY: same retained owners and exclusive hub access.
                unsafe { self.gmc.as_mut().unwrap().initialize().await }.map_err(Error::Gmc)?;
                // Client VMIDs 1..15 at an empty root, before any queue runs,
                // for submissions' in-ring VM flushes to point at a client.
                // SAFETY: the same owners; no queue exists yet.
                unsafe { self.gmc.as_mut().unwrap().prepare_client_contexts().await }
                    .map_err(Error::Gmc)?;
            }
            Stage::ReadTopology => {
                // SAFETY: firmware/power are ready; no concurrent index user,
                // queues or automatic gating exist under this retained owner.
                let topology = unsafe { topology::read(&self.gpu, &self.authority) }
                    .map_err(Error::Topology)?;
                self.topology = Some(topology);
                crate::amdgpu_info::publish_navi48_topology(topology);
                // The GPU clock counter runs once firmware and power are up.
                if let Ok(clock) =
                    crate::amdgpu_smuio14::ClockReader::new(&self.gpu, self.authority)
                {
                    crate::amdgpu_info::publish_navi48_clock(clock);
                }
            }
            Stage::ConfigureRs64 => {
                // SAFETY: PSP authenticated this exact retained set and RLC
                // completed; this boot owns GRBM and all inactive CP queues.
                unsafe { self.rs64.configure() }.map_err(Error::Rs64)?;
            }
            Stage::InterruptRings => {
                let gmc = self.gmc.as_ref().ok_or(Error::Invalid)?;
                // SAFETY: same retained GMC/firmware/pool and exclusive IH;
                // preparation refused inherited rings before memory training.
                self.interrupt_report = Some(
                    unsafe { self.ih.as_mut().ok_or(Error::Invalid)?.initialize(gmc) }
                        .map_err(Error::Interrupts)?,
                );
            }
            Stage::DmaProof => {
                // SAFETY: prior stages retain firmware, memory and both hubs.
                self.sdma = Some(
                    unsafe { sdma::Sdma::new(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Sdma)?,
                );
                let gmc = self.gmc.as_mut().ok_or(Error::Invalid)?;
                // SAFETY: GMC belongs to this same GPU and remains retained.
                unsafe { self.sdma.as_mut().unwrap().initialize(gmc).await }
                    .map_err(Error::Sdma)?;
            }
            Stage::SetupGraphics => {
                // SAFETY: matching authenticated RS64/RLC, restricted power,
                // owned GMC translations and SDMA proof; no CP/MES queue is active.
                unsafe { self.setup.initialize() }
                    .await
                    .map_err(Error::Setup)?;
            }
            Stage::StartMes => {
                // SAFETY: the constructor ties this function to the retained
                // GPU; no config or doorbell access can race the boot owner.
                let doorbells = unsafe { mes::map_doorbells(&self.pci, &self.authority) }
                    .map_err(Error::Mes)?;
                // SAFETY: PSP/RLC/RS64/GMC and the translated DMA proof completed;
                // this owner retains the exact unified firmware, mappings and pool.
                self.mes = Some(
                    unsafe {
                        mes::Mes::new(
                            &self.gpu,
                            self.authority,
                            &self.pool,
                            &self.firmware.gfx,
                            doorbells,
                        )
                    }
                    .map_err(Error::Mes)?,
                );
                // SAFETY: same exclusive completed cold-start prerequisites.
                unsafe { self.mes.as_mut().unwrap().start() }
                    .await
                    .map_err(Error::Mes)?;
            }
            Stage::KernelQueueProof => {
                let mes = self.mes.as_mut().ok_or(Error::Invalid)?;
                // SAFETY: retained GC12/RLC/MES setup, exclusively owned HQDs,
                // doorbells and inventory pool; no application command buffers.
                self.queues = Some(
                    unsafe { queues::Queues::new(&self.gpu, self.authority, &self.pool, mes) }
                        .map_err(Error::Queues)?,
                );
                let gmc = self.gmc.as_mut().ok_or(Error::Invalid)?;
                // SAFETY: same GPU's live MES/GMC and no other proof-page user.
                unsafe { self.queues.as_mut().unwrap().initialize(mes, gmc) }
                    .await
                    .map_err(Error::Queues)?;
            }
            Stage::StartDmub => {
                let psp = self.psp.as_ref().ok_or(Error::Invalid)?;
                // SAFETY: this GPU's PSP/TMR and GMC remain retained, with
                // protected boot clocks and exclusively owned DCN/VRAM.
                unsafe { self.dmub.start(psp).await }.map_err(Error::Dmub)?;
            }
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            graphics: self.graphics.ok_or(Error::Invalid)?,
            power: self.power.ok_or(Error::Invalid)?,
            media: self.psp.as_ref().ok_or(Error::Invalid)?.media_firmware(),
            interrupts: self
                .ih
                .as_ref()
                .and_then(ih::Rings::report)
                .or(self.interrupt_report)
                .ok_or(Error::Invalid)?,
            dmub: self.dmub.status().ok_or(Error::Invalid)?,
            topology: self.topology.ok_or(Error::Invalid)?,
            rs64: self.rs64.starts().ok_or(Error::Invalid)?,
            setup: self.setup.report().ok_or(Error::Invalid)?,
            queues: self
                .queues
                .as_ref()
                .and_then(queues::Queues::proof)
                .ok_or(Error::Invalid)?,
            mes: self
                .mes
                .as_ref()
                .and_then(mes::Mes::report)
                .ok_or(Error::Invalid)?,
            aperture: self
                .gmc
                .as_ref()
                .and_then(gmc::Gmc::aperture)
                .ok_or(Error::Invalid)?,
            dma: self
                .sdma
                .as_ref()
                .and_then(sdma::Sdma::proof)
                .ok_or(Error::Invalid)?,
        })
    }
}
#[derive(Debug)]
pub struct ColdBoot {
    power_profile: smu::PowerProfile,
    custom_profile: smu::CustomCoefficients,
    fams2_active: bool,
    fams2_pending: bool,
    sequence: alloc::boxed::Box<Sequence<Hardware>>,
    reset: Option<crate::amdgpu_reset_navi22::Reset>,
    /// PMFW acknowledged the BACO exit of a runtime resume: SMU firmware
    /// stayed resident (psp_load_smu_fw skips it for BACO runpm).
    baco_exited: bool,
    display: Result<display::Probe, display::Error>,
    ddc: Result<ddc::Ddc, display::Error>,
    crystal: Result<u32, display::Error>,
    /// VBIOS DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE: train DP repeaters hop by hop.
    lttpr_non_transparent: bool,
    clocks: Result<clocks::ClockManager, clocks::Error>,
    dccg: Result<dccg::Dccg, dccg::Error>,
    otg: Result<otg::Otg, otg::Error>,
    /// Ports running DP MST, by `display_paths` index.
    mst: alloc::collections::BTreeMap<usize, mst::MstLink>,
    teardowns: teardown::Teardowns,
    /// Completed modesets survive a dropped configuration/monitor future.
    modesets: modeset::RetainedModesets,
    sst_outputs: Vec<modeset::SstOutput>,
    /// DP SST links training proved below their sinks' caps.
    verified_links: Vec<modeset::VerifiedLink>,
    /// The last scan's DP sinks: port path, DPCD caps and base EDID.
    scanned_sinks: Vec<(inventory::Path, [u8; 16], [u8; 128])>,
    /// The slice of CPU-visible VRAM clients' buffers come from, kept out
    /// of the driver's own pool for good.
    client_vram: Option<crate::amdgpu_vram::Reservation>,
    /// The heap registered for clients, once published.
    client_heap: Option<crate::amdgpu_gem::VramHeap>,
    /// The inventory's VRAM past the BAR, all of it for clients.
    unmapped_vram: Option<crate::amdgpu_vram::UnmappedPool>,
    /// The display power policy's outcome, once the display clocks started.
    display_power_policy: Option<DisplayPowerPolicy>,
}
/// What the display power policy did (`ColdBoot::display_power_policy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayPowerPolicy {
    pub wm_ranges: Result<(), clocks::Error>,
    /// `None` without an SMU owner.
    pub deep_sleep: Option<Result<smu::DeepSleep, smu::Error>>,
}
fn log_policy(args: core::fmt::Arguments<'_>) {
    let _ = core::fmt::Write::write_fmt(
        &mut narf_console::Writer,
        format_args!("amdgpu: navi48 display power policy: {args}\n"),
    );
}
/// Rebind every clock record and every display's timing records from the
/// global clocks `old` to `new`, which are now running.
fn rebind_display_clocks(
    otg: &mut otg::Otg,
    dccg: &mut dccg::Dccg,
    old: clocks::Applied,
    new: clocks::Applied,
) -> Result<(), otg::Error> {
    dccg.rebind_global(old, new);
    let records = dccg.status().pipes;
    // Displays are pipe indices; a fused instance is no display.
    for display in crate::amdgpu_rdna4::pipe_pool().pipes() {
        let Some(status) = otg.display_status(display) else {
            continue;
        };
        let Some(timing) = status.pipes[usize::from(display)] else {
            continue;
        };
        if let Some(clock) = records[usize::from(timing.request.pipe)] {
            otg.rebind_clock(display, clock)?;
        }
    }
    Ok(())
}
/// Future driver-owner headroom, AFTER firmware, existing displays and the
/// complete requested media set are charged to Pool. A small 256 MiB aperture
/// keeps 32 MiB (staging/cursors and checked later display allocation); large
/// apertures keep one eighth, capped 512 MiB. Never derive the floor from the
/// post-proof remainder or silently trim requested codecs to admit a client.
/// Future display requests still need their actual checked allocation; this
/// floor is not a promise that every multi-monitor combination fits a BAR.
fn driver_reserve(aperture: u64, available: u64) -> u64 {
    (32u64 << 20)
        .max((aperture / 8).min(512 << 20))
        .min(available)
}

pub(crate) fn reserve_client_chunk(pool: &Pool) -> Result<crate::amdgpu_vram::Reservation, Error> {
    const ALIGN: u64 = 2 << 20;
    let available = pool.available();
    let mut size = (available - driver_reserve(pool.size(), available)) & !(ALIGN - 1);
    loop {
        if size < 64 << 20 {
            return Err(Error::Allocation);
        }
        match pool.reserve_aligned(size, ALIGN) {
            Ok(chunk) => return Ok(chunk),
            Err(_) => size = (size / 2) & !(ALIGN - 1),
        }
    }
}

impl ColdBoot {
    /// # Safety
    /// Caller owns a physical Navi48 GPU, permanent mappings and a pool made
    /// from its complete boot inventory, excluding every firmware/scanout/client
    /// allocation. Exclude concurrent PSP/SMU/DMUB/index/reset/power access.
    /// This is one cold boot, never attach/resume/reload. VRAM must be trained
    /// when `exchange` is None; otherwise satisfy Trainer::new_navi48's full
    /// quiescence/preimage contract, including stopping CPU framebuffer writers.
    /// Retain this owner after run, failure or cancellation; independent reset
    /// is required before reusing quarantined resources. No queues may run.
    /// `pci` must identify this GPU's exclusively owned physical PCI function,
    /// including its BAR2 doorbells. Firmware must use unified MES for both pipes.
    pub unsafe fn new(
        gpu: &AmdGpu,
        pci: narf_bus::BusDevice,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        unmapped: Option<crate::amdgpu_vram::UnmappedPool>,
        mut firmware: Firmware,
        exchange: Option<Training>,
    ) -> Result<Self, Error> {
        if firmware.gfx.mes_mode() != gfx::MesMode::Unified
            || pci.id.vendor != gpu.chip.vid
            || pci.id.device != gpu.chip.did
            || !matches!(pci.kind, narf_bus::BusKind::Pcie { .. })
        {
            return Err(Error::Unsupported);
        }
        let layout = psp::navi48_layout(gpu).map_err(Error::Psp)?;
        layout
            .validate_pool(gpu, &authority, pool)
            .map_err(Error::Psp)?;
        let target = gfx::Target::resolve(gpu).map_err(Error::Firmware)?;
        topology::validate(gpu).map_err(Error::Topology)?;
        // SAFETY: same exclusive GPU/register ownership; this only prepares.
        let rs64 =
            unsafe { rs64::Rs64::new(gpu, authority, &firmware.gfx) }.map_err(Error::Rs64)?;
        // SAFETY: same exclusive ownership; reserves a page without publishing it.
        let setup = unsafe { setup::Setup::new(gpu, authority, pool) }.map_err(Error::Setup)?;
        // SAFETY: same exclusive ownership. Read-only preparation also refuses
        // inherited IH writers before any training or firmware mutation.
        let ih = unsafe { ih::Rings::new(gpu, authority, pool) }.map_err(Error::Interrupts)?;
        // SAFETY: same physical PCI function, exact banks and exclusive config
        // ownership. MSI preparation errors remain visible to the later service;
        // they do not prevent retained polled IH operation.
        let interrupt_route = unsafe { msi::Route::new(gpu, &pci, authority) };
        // SAFETY: exact same retained GPU; this only validates layout/authority.
        let faults = unsafe { faults::Monitor::new(gpu, authority) }.map_err(Error::Faults)?;
        let mp0 = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_MP0, 0).ok_or(Error::Unsupported)?;
        if target != firmware.gfx.target() || !firmware.sos.is_psp14(mp0.revision) {
            return Err(Error::Unsupported);
        }
        psp::bank(
            gpu,
            ip::HW_ID_MP1,
            crate::amdgpu_rdna4::MP_VERSIONS,
            1,
            0x9a,
        )
        .map_err(Error::Psp)?;
        // Record a display inventory error without blocking non-display engine
        // bring-up. This immutable board copy survives the legacy-owner handoff.
        let display = gpu
            .vbios
            .as_ref()
            .ok_or(inventory::Error::Missing)
            .and_then(|bios| inventory::display_paths(gpu, bios.bytes()))
            .map_err(display::Error::Inventory)
            .and_then(display::Probe::new);
        // dcn401_resource_construct's pipe harvesting: the resource pool
        // every display owner below is built with (all four pipes when the
        // read is unavailable, which also leaves the rest of display
        // bring-up to fail on its own). Every owner (cold boot and the one
        // `after_reset` builds for recovery or resume) publishes its own
        // read, so no earlier device's or boot's pool survives an
        // unreadable fuse register.
        crate::amdgpu_rdna4::publish_pipe_pool(
            // SAFETY: same exclusive register ownership; one read, no writes.
            unsafe { crate::amdgpu_rdna4::read_pipe_pool(gpu, &authority) }
                .unwrap_or(crate::amdgpu_rdna4::PipePool::FULL),
        );
        // Linux's DCN crystal (`dce_refclk_10khz`), the reference DDC and the
        // DCHUB global timer both divide.
        let crystal = gpu
            .vbios
            .as_ref()
            .ok_or(inventory::Error::Missing)
            .and_then(|bios| inventory::dchub_refclk_khz(bios.bytes()))
            .map_err(display::Error::Inventory);
        // DCN401 is always VBIOS-LTTPR-aware; the VBIOS chooses between
        // transparent and hop-by-hop repeater training.
        let lttpr_non_transparent = gpu
            .vbios
            .as_ref()
            .is_some_and(|bios| inventory::lttpr_non_transparent(bios.bytes()) == Ok(true));
        let ddc = crystal.and_then(|clock| {
            // SAFETY: same exclusive DCN/pin/reset ownership; preparation
            // only. All subsequent DDC and DMUB access shares this owner.
            unsafe { ddc::Ddc::new(gpu, authority, clock) }.map_err(display::Error::Ddc)
        });
        // SAFETY: same exclusive display/MP1 ownership, metadata validation
        // only. Optional display failures do not block non-display engines.
        let clocks = unsafe { clocks::ClockManager::new(gpu, authority) };
        // SAFETY: matching retained display owner; metadata validation only.
        let dccg = unsafe { dccg::Dccg::new(gpu, authority) };
        // SAFETY: matching display/PM owner; no timing or firmware writers.
        let otg = unsafe { otg::Otg::new(gpu, authority) };
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(gpu.ip_blocks.len())
            .map_err(|_| Error::Allocation)?;
        blocks.extend_from_slice(&gpu.ip_blocks);
        let saved = AmdGpu {
            regs: gpu.regs,
            fb_bar: gpu.fb_bar,
            chip: gpu.chip,
            vram: gpu.vram,
            ip_blocks: blocks,
            gc_info: gpu.gc_info,
            vbios: gpu
                .vbios
                .as_ref()
                .map(|v| v.try_clone())
                .transpose()
                .map_err(|_| Error::Allocation)?,
            mode: None,
            fw_loaded: false,
        };
        let trainer = if let Some(exchange) = exchange {
            // SAFETY: caller reserves exchange and excludes all conflicting clients.
            Some(
                unsafe { training::Trainer::new_navi48(&saved, authority, exchange) }
                    .map_err(Error::Training)?,
            )
        } else {
            None
        };
        let prepared = firmware.dmub.take().ok_or(Error::Invalid)?;
        // SAFETY: caller grants DCN and pool ownership for this GPU and board.
        let dmub =
            unsafe { dmub::Dmub::new(&saved, authority, pool, prepared) }.map_err(Error::Dmub)?;
        Ok(Self {
            display,
            ddc,
            crystal,
            lttpr_non_transparent,
            clocks,
            dccg,
            otg,
            mst: alloc::collections::BTreeMap::new(),
            teardowns: teardown::Teardowns::new(),
            modesets: modeset::RetainedModesets::new(),
            sst_outputs: Vec::new(),
            verified_links: Vec::new(),
            scanned_sinks: Vec::new(),
            client_vram: None,
            client_heap: None,
            unmapped_vram: unmapped.clone(),
            display_power_policy: None,
            power_profile: smu::PowerProfile::BootupDefault,
            custom_profile: [None; 2],
            fams2_active: false,
            fams2_pending: false,
            reset: None,
            baco_exited: false,
            sequence: alloc::boxed::Box::new(Sequence {
                backend: Hardware {
                    media_idle: media_idle::Idle::new(),
                    gpu: saved,
                    pci,
                    authority,
                    pool: pool.clone(),
                    unmapped,
                    update_fw_reservation: true,
                    firmware,
                    dmub,
                    trainer,
                    training_resume: false,
                    smu_resident: false,
                    sos: None,
                    psp: None,
                    smu: None,
                    versions: None,
                    graphics: None,
                    power: None,
                    topology: None,
                    rs64,
                    setup,
                    ih: Some(ih),
                    interrupt_report: None,
                    interrupt_route: Some(interrupt_route),
                    faults: Some(faults),
                    gmc: None,
                    sdma: None,
                    vcn: None,
                    jpeg: None,
                    jpeg_test: None,
                    jpeg_owner: None,
                    media_test: None,
                    media_request: None,
                    media_decode_required: false,
                    media_encode_required: false,
                    media_jpeg_required: false,
                    media_jpeg_decode_required: false,
                    media_jpeg_clients: false,
                    vcn_owner: None,
                    mes: None,
                    queues: None,
                },
                state: State::Prepared,
            }),
        })
    }
    /// Prepare reset before withdrawing any service. Training replay is not
    /// supported; refuse that configuration before changing hardware.
    pub(crate) fn prepare_reset(&mut self) -> Result<(), Error> {
        // A finished trainer is replayed after the reset (PSP_MEM_TRAIN_RESUME);
        // one that failed or never finished cannot be.
        if self.sequence.backend.trainer.as_ref().is_some_and(|t| {
            !matches!(
                t.state(),
                training::State::Ready | training::State::ResidentSos | training::State::Disabled
            )
        }) {
            return Err(Error::Unsupported);
        }
        if self.state() != State::MemoryReady || self.reset.is_some() {
            return Err(Error::Busy);
        }
        let hw = &self.sequence.backend;
        // SAFETY: preparation performs no writes; the platform establishes
        // exclusive reader/writer exclusion before polling run_reset.
        self.reset = Some(
            unsafe {
                crate::amdgpu_reset_navi22::Reset::new_navi48_recovery(
                    &hw.gpu,
                    hw.authority,
                    hw.pci,
                )
            }
            .map_err(Error::Reset)?,
        );
        Ok(())
    }
    /// Prepare system suspend: the same preflight as `prepare_reset`, with
    /// a resume-mode reset owner (PCI restore, then post or mode1). The
    /// platform must first commit zero streams and finish every teardown;
    /// saving PCI state under a live display is never a valid suspend.
    pub(crate) fn prepare_suspend(&mut self) -> Result<(), Error> {
        if self.display_retirement_busy()
            || self.teardowns.check_idle().is_err()
            || self.display_modesets().iter().any(Option::is_some)
        {
            return Err(Error::Busy);
        }
        self.prepare_reset()?;
        let hw = &self.sequence.backend;
        // SAFETY: preparation performs no I/O; the platform establishes
        // exclusive access before saving PCI state.
        self.reset = Some(
            unsafe {
                crate::amdgpu_reset_navi22::Reset::new_navi48_resume(&hw.gpu, hw.authority, hw.pci)
            }
            .map_err(Error::Reset)?,
        );
        Ok(())
    }
    /// # Safety
    /// Every engine, IH and CPU accessor is quiesced (after the platform
    /// withdrew them), immediately before the system enters S3.
    pub(crate) unsafe fn save_for_suspend(&mut self) -> Result<(), Error> {
        let reset = self.reset.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: forwarded contract.
        unsafe { reset.save_for_resume() }.map_err(Error::Reset)
    }
    /// Abandon a prepared suspend whose PCI state was never saved.
    pub(crate) fn cancel_suspend(&mut self) {
        self.reset = None;
    }
    /// # Safety
    /// Stop every external register/VRAM accessor, including IH and clock
    /// readers. Retain this owner on failure/cancellation; never retry it.
    pub(crate) async unsafe fn run_reset(&mut self) -> Result<(), Error> {
        self.reset
            .as_mut()
            .ok_or(Error::Invalid)?
            .run()
            .await
            .map_err(Error::Reset)?;
        Ok(())
    }
    /// Fresh firmware/queue/display owners after a proven full reset. Old
    /// reservations stay quarantined; the client heap's allocator is reused
    /// so live allocations cannot overlap the new owner's reservations.
    pub(crate) unsafe fn after_reset(&mut self) -> Result<Self, Error> {
        let Some(crate::amdgpu_reset_navi22::State::Complete(report)) =
            self.reset.as_ref().map(|r| r.state())
        else {
            return Err(Error::Busy);
        };
        let hw = &self.sequence.backend;
        let registry: Cap<narf_firmware::FirmwareRegistry, Read> =
            narf_firmware::trusted_loader_authority()
                .ok_or(Error::Invalid)?
                .derive()
                .map_err(|_| Error::Revoked)?;
        let firmware = Firmware::open(&hw.gpu, &registry, gfx::MesMode::Unified)?;
        // SAFETY: reset and ASIC_Init completed; old owners are never polled
        // again, their published reservations remain excluded by this pool.
        let mut new = unsafe {
            Self::new(
                &hw.gpu,
                hw.pci,
                hw.authority,
                &hw.pool,
                self.unmapped_vram.clone(),
                firmware,
                None,
            )
        }?;
        new.power_profile = self.power_profile();
        new.custom_profile = self.custom_profile;
        new.client_heap = self.client_heap.take();
        if let Some(heap) = &mut new.client_heap {
            heap.unmapped = None;
        }
        // The trained state did not survive mode1: the new boot replays it.
        if let Some(trainer) = self.sequence.backend.trainer.take() {
            new.sequence.backend.trainer = Some(trainer);
            new.sequence.backend.training_resume = true;
        }
        new.client_vram = self.client_vram.take();
        new.sequence.backend.update_fw_reservation = false;
        // Only a BACO exit that needed no reset keeps PMFW resident; a
        // mode1 on resume (SOS survived) reloads it as recovery does.
        new.sequence.backend.smu_resident =
            self.baco_exited && report.method == crate::amdgpu_reset_navi22::Method::PowerCycle;
        Ok(new)
    }
    /// Why the prepared reset runs (S3/runtime resume or recovery).
    pub(crate) fn reset_mode(&self) -> Option<crate::amdgpu_reset_navi22::Mode> {
        self.reset.as_ref().map(|r| r.mode())
    }
    /// Return the VRAM of dropped, published reservations to the pool.
    ///
    /// # Safety
    /// As `amdgpu_vram::Pool::reclaim_retired`: every owner that published
    /// a retired range was quiesced and dropped before a completed resume
    /// post (power cycle or mode1) of this GPU.
    pub(crate) unsafe fn reclaim_retired_vram(&self) -> u64 {
        // SAFETY: forwarded contract.
        unsafe { self.sequence.backend.pool.reclaim_retired() }
    }
    /// This GPU's PCI function and its device authority.
    pub(crate) fn pci_function(&self) -> (narf_bus::BusDevice, Cap<BusDeviceCap, Write>) {
        (self.sequence.backend.pci, self.sequence.backend.authority)
    }
    /// `amdgpu_device_supports_baco` for this owner's PMFW and board.
    pub(crate) fn bamaco_support(&self) -> u8 {
        self.sequence
            .backend
            .smu
            .as_ref()
            .map_or(0, smu::Smu::bamaco_support)
    }
    /// `amdgpu_device_baco_enter` (no RAS doorbell interrupt on NBIF 6.3.1).
    ///
    /// # Safety
    /// After `prepare_suspend` + `save_for_suspend` on this quiesced owner;
    /// see `Smu::baco_enter`.
    pub(crate) async unsafe fn enter_baco(
        &mut self,
        bamaco: bool,
        armd3: bool,
    ) -> Result<(), Error> {
        if self.reset.as_ref().map(|r| r.mode()) != Some(crate::amdgpu_reset_navi22::Mode::Resume) {
            return Err(Error::Busy);
        }
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: forwarded contract.
        unsafe { smu.baco_enter(bamaco, armd3) }
            .await
            .map_err(Error::Smu)
    }
    /// `amdgpu_device_baco_exit`: ExitBaco (and the BIOS scratch clear) or
    /// ArmD3(ULPS). The resume reset then restores PCI state and posts.
    ///
    /// # Safety
    /// After `enter_baco`, with the PCI function back in D0.
    pub(crate) async unsafe fn exit_baco(&mut self, armd3: bool) -> Result<(), Error> {
        let smu = self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: forwarded contract.
        let clear = unsafe { smu.baco_exit(armd3) }.await.map_err(Error::Smu)?;
        if clear {
            let reset = self.reset.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: ExitBaco acknowledged; the reset has not run.
            unsafe { reset.clear_post_scratch() }.map_err(Error::Reset)?;
        }
        self.baco_exited = true;
        Ok(())
    }
    pub(crate) fn republish_client_vram(&self) {
        if let (Some(card), Some(heap)) = (Self::drm_card(), &self.client_heap) {
            crate::amdgpu_gem::register_vram_heap(card, heap.clone());
        }
    }
    pub fn state(&self) -> State {
        self.sequence.state
    }
    /// Inputs for the fixed draw, from this retained boot and loaded image.
    pub(crate) fn draw_inputs(&self) -> Option<crate::amdgpu_gfx12_draw::Inputs> {
        if self.state() != State::MemoryReady {
            return None;
        }
        let backend = &self.sequence.backend;
        let images = backend.firmware.images().ok()?;
        Some(crate::amdgpu_gfx12_draw::Inputs {
            chip: crate::amdgpu_rdna4::Rdna4Chip::of(&backend.gpu)?,
            max_se: backend.gpu.gc_info?.num_se,
            pfp_version: images
                .iter()
                .find(|i| i.source() == gfx::Source::Pfp)?
                .version(),
        })
    }
    pub fn report(&self) -> Option<Report> {
        (self.state() == State::MemoryReady)
            .then(|| self.sequence.backend.report().ok())
            .flatten()
    }
    /// Bounded native interrupt-vector draining before service handoff (MSI is
    /// still disabled). Afterwards use the service's diagnostic history API.
    pub fn poll_interrupts(&mut self) -> Result<ih::Batch, Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        self.sequence
            .backend
            .ih
            .as_mut()
            .ok_or(Error::Busy)?
            .drain()
            .map_err(Error::Interrupts)
    }
    /// # Safety
    /// CPU IRQ control and executor are initialized; continue to exclude all
    /// reset/PM transitions after transferring IH to its permanent service.
    pub(crate) async unsafe fn start_interrupt_service(&mut self) -> Result<(), Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        let hardware = &mut self.sequence.backend;
        let thermal = crate::amdgpu_navi48_power::thermal::Monitor::new(
            &hardware.gpu,
            hardware.authority,
            hardware.smu.as_ref().and_then(smu::Smu::limits),
        );
        let vupdate = crate::amdgpu_navi48_interrupts::vupdate::Monitor::new(
            &hardware.gpu,
            hardware.authority,
        );
        let allow_thermal = thermal.is_some();
        let result = async {
            // SAFETY: same retained objects and exclusive post-boot handoff.
            unsafe {
                crate::amdgpu_navi48_interrupts::install(
                    &mut hardware.ih,
                    &mut hardware.interrupt_route,
                    &mut hardware.faults,
                    hardware.gmc.as_mut().ok_or(Error::Invalid)?,
                    thermal,
                    vupdate,
                )
            }
            .map_err(Error::Interrupts)?;
            if allow_thermal {
                hardware
                    .smu
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .allow_ih_interrupt()
                    .await
                    .map_err(Error::Smu)?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = crate::amdgpu_navi48_interrupts::stop_for_reset().await;
            self.sequence.state = State::Failed(Stage::InterruptRings, error);
        }
        result
    }
    pub fn queue_state(&self) -> Option<queues::State> {
        self.sequence
            .backend
            .queues
            .as_ref()
            .map(queues::Queues::state)
    }
    pub fn queue_interrupts(&self) -> Option<Result<queues::InterruptProof, queues::Error>> {
        self.sequence
            .backend
            .queues
            .as_ref()
            .and_then(queues::Queues::interrupt_result)
    }
    /// # Safety
    /// Run from an executor task after service handoff, with all kernel queues,
    /// test pages and reset/PM still exclusively owned. Masked CPU IRQs cause
    /// the MSI proof to fail before submission.
    /// Queue a client job on the graphics ring (`Queues::submit`).
    /// # Safety
    /// As for `Queues::submit`: the job's page directory, IB and what it
    /// reaches stay alive until `completed_client_job` passes the sequence.
    pub(crate) unsafe fn submit_client_job(
        &mut self,
        pipe: queues::Pipe,
        job: queues::Job,
    ) -> Result<u32, queues::Error> {
        if !self.media_submission_ready() {
            return Err(queues::Error::Busy);
        }
        let queues = self
            .sequence
            .backend
            .queues
            .as_mut()
            .ok_or(queues::Error::Invalid)?;
        // SAFETY: the caller's obligations.
        unsafe { queues.submit(pipe, job) }
    }
    /// Recover a ring after its job on VMID `vmid` hung. The graphics ring
    /// as gfx_v12_0_reset_kgq: MES resets the legacy HQD in place. The
    /// compute ring as gfx_v12_0_reset_kcq (amdgpu_gfx_reset_mes_compute,
    /// GFX12 resetting MEC queues by MMIO): MES suspends every gang, the
    /// HQD is dequeued by MMIO, MES unmaps it, its descriptor and ring are
    /// restored and MES maps it again, then MES resumes the gangs, whatever
    /// failed. Either way a fence-only slot then tests the ring
    /// (amdgpu_ring_test_ring). Once that fence lands the CP has moved past
    /// every earlier slot, so the hung and abandoned jobs' fences read
    /// complete through it. Returns that fence's sequence.
    ///
    /// A drained suspend rejection asks MES which queues hung before MMIO;
    /// a report naming a foreign queue refuses recovery. An undrained MES
    /// command requires whole-device recovery. No user or KFD queues exist.
    /// # Safety
    /// As `submit_client_job`, and every job on the ring keeps what it
    /// reaches until this returns Ok.
    pub(crate) async unsafe fn recover_client_ring(
        &mut self,
        pipe: queues::Pipe,
        vmid: u8,
    ) -> Result<u32, queues::Error> {
        let hardware = &mut self.sequence.backend;
        let queues = hardware.queues.as_mut().ok_or(queues::Error::Invalid)?;
        let mes = hardware.mes.as_mut().ok_or(queues::Error::Invalid)?;
        let queue = queues.kernel_queue(pipe);
        match pipe {
            // SAFETY: the platform serializes both queues and MES under its
            // owner; the caller keeps the ring's jobs' memory until Ok.
            queues::Pipe::Graphics => unsafe { mes.reset_kernel_queue(queue, vmid) }
                .await
                .map_err(queues::Error::Mes)?,
            queues::Pipe::Compute => {
                // SAFETY: as above; every suspend is followed by a resume.
                let suspended = unsafe { mes.prepare_compute_reset(queue) }.await;
                let reset = async {
                    suspended.map_err(queues::Error::Mes)?;
                    // SAFETY: gangs suspended or MES identified only our
                    // owned hung HQD; OWNER excludes other GRBM selector users.
                    unsafe { queues.reset_compute_hqd() }.await?;
                    // SAFETY: the HQD was just reset.
                    unsafe { mes.unmap_reset_queue(queue) }
                        .await
                        .map_err(queues::Error::Mes)?;
                    // SAFETY: reset and unmapped.
                    unsafe { queues.restore(pipe) }?;
                    // SAFETY: the queue's restored descriptor and ring stay
                    // retained with the rest of the queue memory.
                    unsafe { mes.map_bootstrap_queue(queue) }
                        .await
                        .map_err(queues::Error::Mes)
                }
                .await;
                // Resume on every returned path, but never reopen submissions
                // when MES did not confirm that scheduling resumed.
                // SAFETY: resumes the suspend above.
                let resumed = unsafe { mes.all_gangs(false) }.await;
                reset?;
                resumed.map_err(queues::Error::Mes)?;
            }
        }
        // SAFETY: as above; the slot reaches only the queue's own fence.
        let seq = unsafe { queues.submit_fence(pipe) }?;
        // amdgpu's usec_timeout for a ring test.
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            let done = queues.completed_job(pipe)?;
            if done.wrapping_sub(seq) as i32 >= 0 {
                return Ok(seq);
            }
            if deadline.expired() {
                return Err(queues::Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }
    /// Recover SDMA0's ring after a job on it hung, as sdma_v7_0_reset_queue:
    /// the MMIO queue reset and the ring programmed again past its queued
    /// slots (`sdma::Sdma::reset_ring`), then a fence-only slot tests it,
    /// landing within 100 ms. Before the test, `skipped` learns the last
    /// sequence the engine completed: every slot past it was skipped, and
    /// will read complete through the test's fence. Returns that fence's
    /// sequence.
    ///
    /// The platform replays healthy client jobs after this test under their
    /// original logical tickets; `skipped` separately requeues kernel clears.
    /// # Safety
    /// As `submit_client_sdma_job`, and every job on the ring keeps what it
    /// reaches until this returns Ok. Work that must not be skipped is
    /// queued again by `skipped` before its fence can be trusted.
    pub(crate) async unsafe fn recover_client_sdma(
        &mut self,
        skipped: impl FnOnce(u32),
    ) -> Result<u32, sdma::Error> {
        let sdma = self
            .sequence
            .backend
            .sdma
            .as_mut()
            .ok_or(sdma::Error::Invalid)?;
        // SAFETY: the caller's obligations.
        unsafe { sdma.reset_ring() }.await?;
        skipped(sdma.completed_job()?);
        // SAFETY: as above; the slot reaches only the ring's own fence.
        let seq = unsafe { sdma.submit_fence() }?;
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            if sdma.completed_job()?.wrapping_sub(seq) as i32 >= 0 {
                return Ok(seq);
            }
            if deadline.expired() {
                return Err(sdma::Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }
    /// Queue a client job on SDMA0 (see `sdma::Sdma::submit`).
    /// # Safety
    /// As `submit_client_job`.
    pub(crate) unsafe fn submit_client_sdma_job(
        &mut self,
        job: queues::Job,
    ) -> Result<u32, sdma::Error> {
        if !self.media_submission_ready() {
            return Err(sdma::Error::Busy);
        }
        let sdma = self
            .sequence
            .backend
            .sdma
            .as_mut()
            .ok_or(sdma::Error::Invalid)?;
        // SAFETY: the caller's obligations.
        unsafe { sdma.submit(job) }
    }
    /// Queue a kernel job of fills and copies on SDMA0 (VMID0 addresses),
    /// in the client jobs' sequence.
    /// # Safety
    /// As `Sdma::submit_kernel`: the platform serializes ring users under
    /// OWNER, and every range named is client VRAM no one uses until the
    /// returned sequence completes.
    pub(crate) unsafe fn submit_client_sdma_kernel(
        &mut self,
        ops: &[sdma::KernelOp],
    ) -> Result<u32, sdma::Error> {
        if !self.media_submission_ready() {
            return Err(sdma::Error::Busy);
        }
        let sdma = self
            .sequence
            .backend
            .sdma
            .as_mut()
            .ok_or(sdma::Error::Invalid)?;
        // SAFETY: the caller's obligations.
        unsafe { sdma.submit_kernel(ops) }
    }
    /// A reader of SDMA0's client-job fence. Jobs are refused (busy)
    /// until both SDMA proofs pass, which the platform runs after boot.
    pub(crate) fn client_sdma_fence_reader(&self) -> Option<sdma::FenceReader> {
        self.sequence
            .backend
            .sdma
            .as_ref()
            .map(sdma::Sdma::fence_reader)
    }
    /// A reader of the graphics ring's job fence that needs no access to
    /// this owner.
    pub(crate) fn client_fence_reader(&self) -> Option<queues::FenceReader> {
        self.sequence
            .backend
            .queues
            .as_ref()
            .map(queues::Queues::fence_reader)
    }

    /// This GPU's DRM card: the registered RDNA4 board, by the probed PCI
    /// id (any listed RDNA4 id before a probe, as in the register models).
    pub(crate) fn drm_card() -> Option<u32> {
        let probed = crate::amdgpu::pci_device().map(|d| (d.id.vendor, d.id.device));
        (0..crate::drm_registry::count() as u32).find(|&i| {
            crate::drm_registry::pci_id(i).is_some_and(|(vid, did)| match probed {
                Some(id) => id == (vid, did),
                None => {
                    vid == crate::amdgpu::AMD_VENDOR
                        && crate::amdgpu_rdna4::known_device(did).is_some()
                }
            })
        })
    }
    pub(crate) async unsafe fn prove_queue_interrupts(
        &mut self,
    ) -> Result<queues::InterruptProof, queues::Error> {
        if self.state() != State::MemoryReady || self.sequence.backend.ih.is_some() {
            return Err(queues::Error::Busy);
        }
        let hardware = &mut self.sequence.backend;
        let queues = hardware.queues.as_mut().ok_or(queues::Error::Invalid)?;
        let gmc = hardware.gmc.as_mut().ok_or(queues::Error::Invalid)?;
        // SAFETY: matching retained owners and independent interrupt service;
        // the platform serializes all other accesses while this is pending.
        unsafe { queues.prove_interrupts(gmc).await }
    }
    /// # Safety
    /// OWNER retains this device and every job VM/BO and excludes other
    /// queue publishers/reset/PM until publication or discard.
    pub(crate) unsafe fn prepare_client_gang(
        &mut self,
        jobs: [queues::Job; 2],
    ) -> Result<queues::PreparedGang, queues::Error> {
        if self.state() != State::MemoryReady || crate::amdgpu_navi48_interrupts::blocked() {
            return Err(queues::Error::Busy);
        }
        let queues = self
            .sequence
            .backend
            .queues
            .as_mut()
            .ok_or(queues::Error::Busy)?;
        // SAFETY: caller retains the matching serialized queue/VM owners.
        unsafe { queues.prepare_gang(jobs) }
    }
    /// # Safety
    /// Same retained owner as prepare_client_gang. Both constituent jobs
    /// already have durable VM/BO/VMID/watch receipts, including on failure.
    pub(crate) unsafe fn publish_client_gang(
        &mut self,
        prepared: queues::PreparedGang,
        leader: queues::Pipe,
    ) -> Result<(), queues::Error> {
        let queues = self
            .sequence
            .backend
            .queues
            .as_mut()
            .ok_or(queues::Error::Busy)?;
        // SAFETY: matching preparation, exclusion and durable receipts.
        unsafe { queues.publish_gang(prepared, leader) }
    }
    /// Deterministic shader proof, after GC12/SDMA interrupt proofs and
    /// before any client work; the caller excludes all test-page users.
    /// # Safety
    /// Continue the exclusive queue/GMC/reset ownership and enabled CPU IRQ
    /// contract of prove_queue_interrupts. Failed/canceled proof stays retained.
    pub(crate) async unsafe fn prove_shaders(
        &mut self,
    ) -> Result<crate::amdgpu_gfx12_shader::Proof, queues::Error> {
        if self.state() != State::MemoryReady {
            return Err(queues::Error::Busy);
        }
        let hw = &mut self.sequence.backend;
        if hw
            .sdma
            .as_ref()
            .is_none_or(|s| s.state() != sdma::State::InterruptVerified)
        {
            return Err(queues::Error::Busy);
        }
        let queues = hw.queues.as_mut().ok_or(queues::Error::Invalid)?;
        let gmc = hw.gmc.as_mut().ok_or(queues::Error::Invalid)?;
        // SAFETY: same retained GPU; caller excludes every queue/test-page user.
        unsafe { queues.prove_shaders(gmc).await }
    }
    pub(crate) fn shader_result(
        &self,
    ) -> Option<Result<crate::amdgpu_gfx12_shader::Proof, queues::Error>> {
        self.sequence
            .backend
            .queues
            .as_ref()
            .and_then(queues::Queues::shader_result)
    }
    pub fn sdma_state(&self) -> Option<sdma::State> {
        self.sequence.backend.sdma.as_ref().map(sdma::Sdma::state)
    }
    pub fn sdma_interrupts(&self) -> Option<Result<sdma::InterruptProof, sdma::Error>> {
        self.sequence
            .backend
            .sdma
            .as_ref()
            .and_then(sdma::Sdma::interrupt_result)
    }
    /// # Safety
    /// Same retained owners and executor context as `prove_queue_interrupts`.
    /// Run after both GC12 proofs have drained the shared GMC test pages.
    pub(crate) async unsafe fn prove_sdma_interrupts(
        &mut self,
    ) -> Result<sdma::InterruptProof, sdma::Error> {
        if self.state() != State::MemoryReady
            || self.sequence.backend.ih.is_some()
            || self.queue_state() != Some(queues::State::InterruptVerified)
        {
            return Err(sdma::Error::Busy);
        }
        let hardware = &mut self.sequence.backend;
        let sdma = hardware.sdma.as_mut().ok_or(sdma::Error::Invalid)?;
        let gmc = hardware.gmc.as_mut().ok_or(sdma::Error::Invalid)?;
        // SAFETY: matching retained owners, serialized shared test pages and
        // independent IRQ service; the GC12 proofs have already drained.
        unsafe { sdma.prove_interrupts(gmc).await }
    }
    /// Board power limits and GFX level of the configured SMU, after boot.
    /// Give clients of this card's DRM node a VRAM heap: the CPU-visible
    /// VRAM the driver's pool still has free after boot, less what the
    /// driver keeps for its own later owners (`driver_reserve`), 2 MiB-
    /// aligned and at least 64 MiB, as a pool of its own, so with no
    /// eviction they can never take what the driver's owners need. Entries
    /// address it as the GMC's framebuffer geometry translates it.
    /// Returns the heap's size.
    pub(crate) fn publish_client_vram(&mut self) -> Result<u64, Error> {
        if self.client_vram.is_some() {
            return Err(Error::Busy);
        }
        let hw = &mut self.sequence.backend;
        let regs = hw.gpu.regs;
        let context = hw
            .gmc
            .as_mut()
            .ok_or(Error::Invalid)?
            .display_context(regs)
            .map_err(Error::Gmc)?;
        let card = Self::drm_card().ok_or(Error::Invalid)?;
        let mut chunk = reserve_client_chunk(&hw.pool)?;
        let size = chunk.size();
        // SAFETY: the reservation is this heap's alone, inside the owned,
        // CPU-mapped VRAM range the boot inventory produced.
        let heap = unsafe { Pool::from_owned_range(chunk.mapping(), chunk.address()) }
            .map_err(|_| Error::Allocation)?;
        // Clients' buffers outlive any one owner here; never recycle it.
        chunk.publish();
        let heap = crate::amdgpu_gem::VramHeap {
            pool: heap,
            fb_base: context.fb_base,
            fb_offset: context.fb_offset,
            unmapped: None,
        };
        // amdgpu_gmc_get_dcc_alignment from discovery's GC version and its
        // gc_info TCC count (max_texture_channel_caches), before any client
        // buffer is placed.
        let gc = ip::find_ip(&hw.gpu.ip_blocks, ip::HW_ID_GC, 0)
            .map_or((0, 0, 0), |gc| (gc.major, gc.minor, gc.revision));
        let tccs = hw.gpu.gc_info.map_or(0, |info| info.num_tccs);
        crate::amdgpu_gem::set_gfx12_dcc(
            card,
            Some(u64::from(crate::amdgpu_gem::gmc_v12_dcc_alignment(
                gc, tccs,
            ))),
        );
        // Evictions see every buffer of the card, framebuffer-only ones
        // included, as TTM's LRU does.
        crate::amdgpu_gem::set_lru_eviction(card, true);
        crate::amdgpu_gem::register_vram_heap(card, heap.clone());
        self.client_heap = Some(heap);
        self.client_vram = Some(chunk);
        Ok(size)
    }
    /// Add the VRAM past the BAR to the clients' heap, for `NO_CPU_ACCESS`
    /// buffers, once SDMA0 runs jobs: `clear` zeroes each buffer there
    /// before use (`submit_client_sdma_kernel`). Returns its size.
    pub(crate) fn publish_unmapped_vram(
        &mut self,
        clear: alloc::sync::Arc<dyn crate::amdgpu_gem::VramClear>,
        transfer: Option<alloc::sync::Arc<dyn crate::amdgpu_gem::VramTransfer>>,
    ) -> Result<u64, Error> {
        let sdma_ready = self
            .sequence
            .backend
            .sdma
            .as_ref()
            .is_some_and(|s| s.state() == sdma::State::InterruptVerified);
        let card = Self::drm_card().ok_or(Error::Invalid)?;
        let (Some(heap), Some(pool), true) = (
            self.client_heap.as_mut(),
            self.unmapped_vram.as_ref(),
            sdma_ready,
        ) else {
            return Err(Error::Busy);
        };
        if heap.unmapped.is_some() {
            return Err(Error::Busy);
        }
        heap.unmapped = Some(crate::amdgpu_gem::UnmappedHeap {
            transfer,
            pool: pool.clone(),
            clear,
        });
        crate::amdgpu_gem::register_vram_heap(card, heap.clone());
        Ok(pool.size())
    }
    /// A 1 MiB CPU-mapped window of the driver's pool for migration copies,
    /// once SDMA0 runs jobs (the RX 6000 `reserve_transfer_stage`).
    pub(crate) fn reserve_transfer_stage(&self) -> Result<crate::amdgpu_vram::Reservation, Error> {
        let hw = &self.sequence.backend;
        if !hw
            .sdma
            .as_ref()
            .is_some_and(|s| s.state() == sdma::State::InterruptVerified)
        {
            return Err(Error::Busy);
        }
        hw.pool.reserve(1 << 20).map_err(|_| Error::Allocation)
    }
    /// A bounded BAR access under the live device grant, followed by an HDP
    /// flush (amdgpu_hdp_generic_flush) so CPU writes reach VRAM before any
    /// engine reads them.
    pub(crate) fn access_vram<T>(
        &self,
        f: impl FnOnce() -> Result<T, narf_filesystem::FsError>,
    ) -> Result<T, narf_filesystem::FsError> {
        use narf_capabilities::{CapError, CapOp};
        use narf_filesystem::FsError;
        struct Op<F>(F);
        impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
            type Output = T;
            fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
                Ok((self.0)())
            }
        }
        let hw = &self.sequence.backend;
        let regs = hw.gpu.regs;
        let nbio = crate::amdgpu_psp_ring::bank(
            &hw.gpu,
            crate::amdgpu_discovery::HW_ID_NBIF,
            &[(6, 3, 1)],
            2,
            0xc3,
        )
        .map_err(|_| FsError::NoDevice)?;
        if regs.len < 0x7f004 {
            return Err(FsError::NoDevice);
        }
        hw.authority
            .invoke(Op(|| {
                let result = f();
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                // SAFETY: the remapped HDP flush word and NBIO's posting read
                // lie inside the bounded, owned register BAR.
                let posted = unsafe {
                    regs.write32(0x7f000, 0);
                    regs.read32(nbio + 0xc3 * 4)
                };
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                if posted == u32::MAX {
                    return Err(FsError::NoDevice);
                }
                result
            }))
            .map_err(|_| FsError::NoDevice)?
    }
    pub(crate) fn read_timestamp(&self) -> Result<u64, FsError> {
        if self.state() != State::MemoryReady {
            return Err(FsError::NoDevice);
        }
        let h = &self.sequence.backend;
        crate::amdgpu_smuio14::ClockReader::new(&h.gpu, h.authority)
            .map_err(|_| FsError::InvalidData)?
            .read()
            .ok_or(FsError::NoDevice)
    }
    pub(crate) fn sensor_dpm_enabled(&self) -> Result<bool, FsError> {
        if self.state() != State::MemoryReady {
            return Err(FsError::NoDevice);
        }
        Ok(self.power_info().is_some())
    }
    pub(crate) async fn sensor_pstates(
        &mut self,
    ) -> Result<crate::amdgpu_info_stats::Pstates, FsError> {
        if !self.sensor_dpm_enabled()? {
            return Err(FsError::NotFound);
        }
        self.power_owner()
            .map_err(|_| FsError::NoDevice)?
            .read_pstates()
            .await
            .map_err(crate::amdgpu_info_stats::smu14_error)
    }
    pub(crate) fn power_info(
        &self,
    ) -> Option<(Option<smu::Limits>, smu::GfxLevel, smu::PowerProfile)> {
        let smu = self.sequence.backend.smu.as_ref()?;
        (self.state() == State::MemoryReady && smu.power_status().is_some())
            .then(|| (smu.limits(), smu.gfx_level(), smu.power_profile()))
    }
    fn power_owner(&mut self) -> Result<&mut smu::Smu, Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        self.sequence.backend.smu.as_mut().ok_or(Error::Invalid)
    }
    /// One PMFW telemetry refresh. It shares only the PPSMC mailbox, which
    /// this owner serializes with the display power transition.
    pub(crate) async fn power_sample(
        &mut self,
    ) -> Result<crate::amdgpu_navi48_power::Sample, Error> {
        let smu = self.power_owner()?;
        let telemetry = smu.read_telemetry().await;
        Ok(crate::amdgpu_navi48_power::Sample {
            protected: telemetry.is_ok_and(|t| smu.protected(t.enabled)),
            telemetry,
            limits: smu.limits(),
            gfx_level: smu.gfx_level(),
            profile: smu.power_profile(),
            coefficients: smu.profile_coefficients(),
        })
    }
    /// PPT only; display and memory constraints stay with the display owner.
    pub async fn set_power_cap(&mut self, watts: u32) -> Result<(), Error> {
        self.power_owner()?
            .set_ppt_limit(watts)
            .await
            .map_err(Error::Smu)
    }
    pub async fn set_gfx_level(&mut self, level: smu::GfxLevel) -> Result<(), Error> {
        self.power_owner()?
            .set_gfx_level(level)
            .await
            .map_err(Error::Smu)
    }
    pub(crate) async fn enable_gfxoff(&mut self) -> Result<bool, Error> {
        if !self.power_owner()?.gfxoff_supported() {
            return Ok(false);
        }
        self.sequence
            .backend
            .rs64
            .enable_gfxoff()
            .map_err(Error::Rs64)?;
        let enabled = self
            .power_owner()?
            .configure_gfxoff()
            .await
            .map_err(Error::Smu)?;
        self.sequence.backend.power = self
            .sequence
            .backend
            .smu
            .as_ref()
            .and_then(smu::Smu::power_status);
        Ok(enabled)
    }
    pub(crate) async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        self.power_owner()?
            .gfx_off_control(allow)
            .await
            .map_err(Error::Smu)
    }
    pub fn display_clock_status(&self) -> Result<clocks::Status, clocks::Error> {
        self.clocks
            .as_ref()
            .map(clocks::ClockManager::status)
            .map_err(|e| *e)
    }
    /// Prepare DCN4 clocks after kernel queue work drains. All inherited
    /// display consumers must already be retired; clock preflight enforces it.
    pub async fn prepare_display_clocks(
        &mut self,
        request: clocks::Request,
    ) -> Result<clocks::Applied, clocks::Error> {
        self.start_display_clocks().await?;
        self.clocks
            .as_mut()
            .map_err(|e| *e)?
            .prepare(request)
            .await?;
        self.configure_display_saving().await?;
        self.display_clock_status()?
            .applied
            .ok_or(clocks::Error::Invalid)
    }
    /// Query board DPM limits without requesting any active displays or
    /// programming pipe clocks. The same ownership checks govern both paths.
    async fn start_display_clocks(&mut self) -> Result<(), clocks::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
        {
            return Err(clocks::Error::Busy);
        }
        // Never change the global reference under an uncertain per-pipe
        // transaction (including a cancelled dentist completion wait).
        if self
            .dccg
            .as_ref()
            .is_ok_and(|d| !matches!(d.status().state, dccg::State::Ready | dccg::State::Applied))
            || self
                .otg
                .as_ref()
                .is_ok_and(|o| !o.status().state.reusable())
        {
            return Err(clocks::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| *e)?;
        let smu = self
            .sequence
            .backend
            .smu
            .as_mut()
            .ok_or(clocks::Error::Invalid)?;
        let starting = clocks.status().state == clocks::State::Prepared;
        if starting {
            // SAFETY: retained matching SMU and drained owned engines. The
            // clock owner checks every display consumer before changing DPM.
            unsafe { clocks.start(smu).await }?;
        }
        if !matches!(
            clocks.status().state,
            clocks::State::Ready | clocks::State::Applied
        ) {
            return Err(clocks::Error::Busy);
        }
        if starting {
            self.install_display_power_policy().await;
        }
        Ok(())
    }
    /// What Linux does once DC knows the clocks, and then at COMPLETE_INIT:
    /// dcn401_init_hw's dcn401_notify_wm_ranges hands PMFW the watermark
    /// range table (set A, and set 1A for the dummy P-state), and
    /// smu_bump_power_profile_mode's smu_v14_0_2_set_power_profile_mode runs
    /// smu_v14_0_deep_sleep_control for the retained workload: enable for
    /// non-COMPUTE, disable for COMPUTE. Table acknowledgement precedes
    /// admission; runtime bandwidth replays require strict replies. As in Linux,
    /// a table that cannot be placed is skipped, and firmware refusals are
    /// logged and recorded (`display_power_policy`). An interrupted or
    /// authority-failed watermark transaction leaves the clock owner
    /// unusable; subsequent preparation refuses it. The table stays excluded.
    async fn install_display_power_policy(&mut self) {
        let wm_ranges = self.notify_display_wm_ranges().await;
        if let Err(e) = wm_ranges {
            log_policy(format_args!("watermark ranges not sent: {e:?}"));
        }
        let deep_sleep = match self.sequence.backend.smu.as_mut() {
            // SAFETY: the kernel engines' owners tolerate GFXCLK deep sleep
            // as Linux's do; every plan's watermarks carry DML's
            // self-refresh exit latencies and the deep-sleep DCFCLK floor,
            // and the watermark ranges were offered to PMFW above.
            Some(smu)
                if self
                    .clocks
                    .as_ref()
                    .is_ok_and(|c| c.status().watermarks_ready) =>
            {
                // SAFETY: the retained display owner acknowledged the table
                // and its DML plans retain the required latency constraints.
                Some(unsafe { smu.deep_sleep_control() }.await)
            }
            Some(_) => None,
            None => None,
        };
        match deep_sleep {
            Some(Ok(smu::DeepSleep {
                refused: Some(r), ..
            })) => log_policy(format_args!(
                "failed to enable {} DS: {:?}",
                r.feature, r.error
            )),
            Some(Err(e)) => log_policy(format_args!("deep sleep not enabled: {e:?}")),
            _ => {}
        }
        self.display_power_policy = Some(DisplayPowerPolicy {
            wm_ranges,
            deep_sleep,
        });
    }
    /// dcn401_notify_wm_ranges with a table in a 4-KiB VRAM range kept out
    /// of reuse (Linux's wm_range_table, which is skipped when it could
    /// not be allocated).
    async fn notify_display_wm_ranges(&mut self) -> Result<(), clocks::Error> {
        let mut table = self
            .sequence
            .backend
            .pool
            .reserve(4096)
            .map_err(|_| clocks::Error::Invalid)?;
        let bytes = clocks::ClockManager::wm_range_table();
        let virt = table.mapping().virt;
        self.access_vram(|| {
            for (k, b) in bytes.iter().enumerate() {
                // SAFETY: a fresh, privately reserved, mapped 4 KiB range no
                // engine reads before the notify below; HDP is flushed after.
                unsafe { core::ptr::write_volatile((virt as *mut u8).add(k), *b) };
            }
            Ok(())
        })
        .map_err(|_| clocks::Error::DeviceGone)?;
        // PMFW may read the table at any later time: never recycle it.
        table.publish();
        let address = table.address();
        drop(table);
        let regs = self.sequence.backend.gpu.regs;
        let clocks = self.clocks.as_mut().map_err(|e| *e)?;
        clocks.notify_wm_ranges(regs, address).await
    }
    /// What the display power policy did once the display clocks started:
    /// the watermark-range notify and the deep-sleep walk.
    pub fn display_power_policy(&self) -> Option<DisplayPowerPolicy> {
        self.display_power_policy
    }
    pub fn display_pipe_clock_status(&self) -> Result<dccg::Status, dccg::Error> {
        self.dccg.as_ref().map(dccg::Dccg::status).map_err(|e| *e)
    }
    /// Divide acknowledged global clocks for a retired native display pipe.
    /// The link/modeset owner must still program its PLL, PHY and scanout.
    /// Attach the selected display to the port's running MST link.
    /// # Safety
    /// Fulfil `Otg::attach_mst_link` obligations.
    pub unsafe fn attach_display_mst_link(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .attach_mst_link(path.transmitter)
        }
    }
    /// Detach the selected display from the port's MST link.
    pub fn detach_display_mst_link(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        self.otg
            .as_mut()
            .map_err(|e| *e)?
            .detach_mst_link(path.transmitter)
    }
    /// Program the port's MST link's VC payload table and trigger ACT.
    /// # Safety
    /// Fulfil `Otg::update_mst_allocation` obligations.
    pub async unsafe fn update_display_mst_allocation(
        &mut self,
        port: usize,
        table: &[otg::MstAllocation],
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .update_mst_allocation(path.transmitter, table)
                .await
        }
    }
    /// Set DIO stream `stream`'s VC rate on the port's MST link.
    /// # Safety
    /// Fulfil `Otg::set_mst_vc_rate` obligations.
    pub async unsafe fn set_display_mst_vc_rate(
        &mut self,
        port: usize,
        stream: u8,
        rate: (u32, u32),
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .set_mst_vc_rate(path.transmitter, stream, rate)
                .await
        }
    }
    /// Run DSC `pipe`'s DSCCLK from its DTO for the stream on `pipe`'s
    /// prepared pixel clock (above 48 MHz, as Linux does). Returns whether
    /// the DTO runs.
    pub fn start_display_dscclk(&mut self, pipe: u8) -> Result<bool, otg::Error> {
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        self.otg
            .as_mut()
            .map_err(|e| *e)?
            .start_dscclk(clocks, dccg, pipe)
    }
    /// Return DSC `pipe`'s DSCCLK to REFCLK after its DSC stopped.
    pub fn stop_display_dscclk(&mut self, pipe: u8) -> Result<(), otg::Error> {
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        self.otg.as_mut().map_err(|e| *e)?.stop_dscclk(dccg, pipe)
    }
    pub async fn prepare_display_pipe_clocks(
        &mut self,
        request: dccg::Request,
    ) -> Result<dccg::Applied, dccg::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
            || self
                .otg
                .as_ref()
                .is_ok_and(|o| !o.status().state.reusable())
        {
            return Err(dccg::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| dccg::Error::Clocks(*e))?;
        self.dccg
            .as_mut()
            .map_err(|e| *e)?
            .prepare(clocks, request)
            .await
    }
    /// Connect a prepared pixel DTO to a retired HPO DP or FRL stream clock.
    pub fn route_display_stream_clock(
        &mut self,
        route: dccg::StreamRoute,
    ) -> Result<(), dccg::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
            || self
                .otg
                .as_ref()
                .is_ok_and(|o| !o.status().state.reusable())
        {
            return Err(dccg::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| dccg::Error::Clocks(*e))?;
        self.dccg
            .as_mut()
            .map_err(|e| *e)?
            .route_stream(clocks, route)
    }
    /// Read-only: pipes whose timing generator runs, by bit.
    pub fn display_running_timing(&mut self) -> Result<u8, otg::Error> {
        self.otg.as_mut().map_err(|e| *e)?.running_timing()
    }
    pub fn display_timing_status(&self) -> Result<otg::Status, otg::Error> {
        self.otg.as_ref().map(otg::Otg::status).map_err(|e| *e)
    }
    /// Make `display` (0-3) the one following display operations address;
    /// see `Otg::select_display`. Global and pipe clocks are programmed with
    /// every display idle, so a configuration's clocks precede its first
    /// display.
    pub fn select_display(&mut self, display: u8) -> Result<(), otg::Error> {
        self.otg.as_mut().map_err(|e| *e)?.select_display(display)
    }
    pub fn selected_display(&self) -> Result<u8, otg::Error> {
        self.otg
            .as_ref()
            .map(otg::Otg::selected_display)
            .map_err(|e| *e)
    }
    /// Any display's records.
    pub fn display_status(&self, display: u8) -> Result<Option<otg::Status>, otg::Error> {
        self.otg
            .as_ref()
            .map(|o| o.display_status(display))
            .map_err(|e| *e)
    }
    /// Prepare native timing while retaining its matching clock owners.
    /// The generator remains disabled; this does not establish scanout readiness.
    pub async fn prepare_display_timing(
        &mut self,
        request: otg::Request,
    ) -> Result<otg::Applied, otg::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
        {
            return Err(otg::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        self.otg
            .as_mut()
            .map_err(|e| *e)?
            .prepare(clocks, dccg, request)
            .await
    }
    /// Stage the native OPP RGB formatter and black pattern for disabled timing.
    pub async fn prepare_display_blank(
        &mut self,
        request: otg::BlankRequest,
    ) -> Result<otg::BlankApplied, otg::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
        {
            return Err(otg::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        self.otg
            .as_mut()
            .map_err(|e| *e)?
            .prepare_blank(clocks, dccg, request)
            .await
    }
    /// Start internal black timing after the drained kernel queue proofs.
    /// # Safety
    /// Stop CPU scanout writers, exclude other fetcher/cursor/metadata writers
    /// and retain all inherited and owned surfaces, page tables, HUBP and OPP
    /// resources. Completion does not authorize freeing them or starting links.
    pub async unsafe fn start_display_blank(
        &mut self,
        pipe: u8,
    ) -> Result<otg::BlankRunning, otg::Error> {
        if self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
        {
            return Err(otg::Error::Busy);
        }
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        // SAFETY: caller retains scanout resources and excludes other writers;
        // retained matching owners serialize native timing and clocks.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_blank(clocks, dccg, pipe)
                .await
        }
    }
    /// # Safety
    /// All associated scanout resources remain retained and CPU writers have
    /// stopped. This retires timing only, never HUBP fetches or surface memory.
    pub async unsafe fn retire_display_timing(&mut self, pipe: u8) -> Result<(), otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: caller retains scanout memory; matching exclusive display owner.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.retire(pipe).await }
    }
    /// Retire one OTG and its clocks while retaining TMDS transmitters.
    /// # Safety
    /// Fulfil `Otg::retire_tmds_timing` frontend/audio/metadata/HDCP retirement
    /// and writer-exclusion obligations. Retain all memory and translations;
    /// future PHY shutdown needs fresh checks of every timing and clock user.
    pub async unsafe fn retire_display_tmds_timing(
        &mut self,
        pipe: u8,
    ) -> Result<otg::TmdsTimingRetired, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: matching retained owner; caller fulfils the documented obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_tmds_timing(pipe)
                .await
        }
    }
    /// Disconnect all inherited native planes while retaining their resources.
    /// # Safety
    /// Stop CPU writers, exclude concurrent surface/cursor/metadata/LUT, MPC,
    /// firmware/FAMS and power writers, and retain every associated allocation
    /// and translation. Completion does not permit freeing or reusing memory.
    pub async unsafe fn retire_display_planes(&mut self) -> Result<otg::PlanesRetired, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: matching retained display owner; caller retains all resources
        // and excludes writers, including firmware and inherited scanout users.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.retire_planes().await }
    }
    /// Power a disconnected HUBP on to blank readiness, or gate a drained HUBP.
    /// # Safety
    /// Stop CPU scanout writers, exclude firmware/FAMS and concurrent display,
    /// auxiliary fetcher, clock and power writers, and retain every allocation
    /// and translation on every outcome. Completion never permits memory reuse.
    pub async unsafe fn set_display_hubp_power(
        &mut self,
        pipe: u8,
        powered: bool,
    ) -> Result<otg::HubpPower, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers and retains memory.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .set_hubp_power(pipe, powered)
                .await
        }
    }
    /// Allocate and stage an owned linear framebuffer without enabling fetch.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP/clock/power writers;
    /// retain the owner and inherited resources on every outcome.
    pub async unsafe fn prepare_display_surface(
        &mut self,
        request: otg::SurfaceRequest,
    ) -> Result<otg::SurfaceApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: this boot owner retains its validated pool and serializes access.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_surface(&self.sequence.backend.pool, request)
                .await
        }
    }
    /// Release one pipe's display-only front/back/cursor reservations after
    /// plane retirement. The selected display must own the pipe.
    /// # Safety
    /// Fulfil `Otg::release_surfaces`: withdraw and drain all CPU views, exclude
    /// other GPU engines and firmware writers, and retain exclusive ownership.
    pub unsafe fn release_display_surfaces(&mut self, pipe: u8) -> Result<u64, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: retained matching owner; caller supplies lifetime exclusions.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.release_surfaces(pipe) }
    }
    /// Upload a visible row segment into a staged, stopped framebuffer.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP/clock/power writers;
    /// retain the owner and inherited resources on every outcome.
    pub unsafe fn upload_display_surface(
        &mut self,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: retained owner serializes access; upload checks bounds and live state.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .upload_surface(pipe, x, y, pixels)
        }
    }
    /// Prepare DCN framebuffer translation using this boot owner's retained GMC.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent hub/VM/display/clock/reset/power
    /// writers; retain both owners and all inherited resources on every outcome.
    pub async unsafe fn prepare_display_memory(
        &mut self,
        pipe: u8,
    ) -> Result<otg::MemoryApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners, serialized here; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_memory(gmc, pipe)
                .await
        }
    }
    /// Prepare native unscaled RGB processing for the retained full-frame surface.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/hub/VM/clock/reset/power
    /// writers; retain every owner and inherited resource on every outcome.
    pub async unsafe fn prepare_display_dpp(
        &mut self,
        pipe: u8,
    ) -> Result<otg::DppApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_dpp(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                )
                .await
        }
    }
    /// Stage opaque RGB composition for the retained full-frame surface.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/hub/VM/clock/reset/power
    /// writers; retain every owner and inherited resource on every outcome.
    pub unsafe fn prepare_display_mpc(&mut self, pipe: u8) -> Result<otg::MpcApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg.as_mut().map_err(|e| *e)?.prepare_mpc(
                self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                gmc,
                pipe,
            )
        }
    }
    /// Stage bounded requests and native single-pipe display-buffer allocation.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/clock/reset/power
    /// writers; retain every owner and resource on every outcome, including cancellation.
    pub async unsafe fn prepare_display_requestor(
        &mut self,
        pipe: u8,
    ) -> Result<otg::RequestorApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_requestor(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                )
                .await
        }
    }
    /// `prepare_display_requestor` for the primary on `pipe` and the
    /// overlay planes staged on `overlays` (bottom first).
    /// # Safety
    /// As for `prepare_display_requestor`.
    pub async unsafe fn prepare_display_requestor_planes(
        &mut self,
        pipe: u8,
        overlays: &[u8],
        plan: &crate::amdgpu_dcn401_dml::Plan,
    ) -> Result<otg::RequestorApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_requestor_planes(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    overlays,
                    Some(plan),
                )
                .await
        }
    }
    /// Admit one single-pipe scanout mode against the live board: started
    /// PMFW levels, the DENTIST VCO, the DCHUB timer and the VBIOS crystal.
    /// Read-only; the plan's clocks and global sync feed the later requests.
    pub fn display_admission(
        &mut self,
        mode: &crate::amdgpu_dcn401_dml::Mode,
    ) -> Result<crate::amdgpu_dcn401_dml::Plan, otg::Error> {
        let soc = self.display_soc()?;
        modeset::admit_native_modes(&soc, core::slice::from_ref(mode))
            .map(|plans| plans[0])
            .map_err(otg::Error::Admission)
    }
    /// DTBCLK's highest usable DPM level, which FRL streams hold
    /// (dcn401_update_clocks).
    pub fn top_dtb_khz(&self) -> Result<u32, otg::Error> {
        Ok(self
            .clocks
            .as_ref()
            .map_err(|e| otg::Error::Clocks(*e))?
            .status()
            .levels
            .ok_or(otg::Error::Busy)?
            .range(crate::amdgpu_dcn401_clk::Clock::Dtb)
            .max_khz())
    }
    /// The board inputs of display admission: the PMFW DPM levels the clock
    /// owner published, the DENTIST VCO and the DCHUB reference.
    pub fn display_soc(&mut self) -> Result<crate::amdgpu_dcn401_dml::Soc, otg::Error> {
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let levels = self
            .clocks
            .as_ref()
            .map_err(|e| otg::Error::Clocks(*e))?
            .status()
            .levels
            .ok_or(otg::Error::Busy)?;
        let vco = self
            .dccg
            .as_mut()
            .map_err(|e| otg::Error::PipeClocks(*e))?
            .dentist_vco_khz()
            .map_err(otg::Error::PipeClocks)?;
        self.otg
            .as_mut()
            .map_err(|e| *e)?
            .admission_soc(&levels, vco, crystal)
    }
    /// Program an admitted plan's deadlines and watermarks for the staged pipe.
    /// The plan is re-admitted and bound to the current owners first.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/clock/reset/power
    /// writers; retain every owner and resource on every outcome, including cancellation.
    pub async unsafe fn prepare_display_deadlines(
        &mut self,
        pipe: u8,
        plan: &crate::amdgpu_dcn401_dml::Plan,
    ) -> Result<otg::DeadlinesApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_deadlines(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    plan,
                    crystal,
                )
                .await
        }
    }
    /// Move display `pipe`'s live scanout to `plan`, its stream and planes
    /// admitted in a new configuration, without leaving scanout
    /// (`Otg::update_live_plan`; `raise` for prepare_bandwidth's
    /// raise-only watermarks).
    /// # Safety
    /// As for `prepare_display_deadlines`; the scanout's surfaces stay live.
    pub async unsafe fn update_live_display_plan(
        &mut self,
        pipe: u8,
        plan: &crate::amdgpu_dcn401_dml::Plan,
        raise: bool,
    ) -> Result<otg::DeadlinesApplied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .update_live_plan(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    plan,
                    raise,
                    crystal,
                )
                .await
        }
    }
    /// Retry a compbuf grow a slow DET acknowledgement deferred
    /// (`Otg::retry_compbuf`), as Linux's next optimize_bandwidth programs
    /// the compbuf again. `None` with nothing pending.
    /// # Safety
    /// As for `update_live_display_plan`.
    pub async unsafe fn retry_display_compbuf(&mut self) -> Result<Option<[u8; 5]>, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        if !otg.compbuf_pending() {
            return Ok(None);
        }
        // SAFETY: the caller's obligations.
        unsafe { otg.retry_compbuf() }.await
    }
    /// Move display `pipe`'s live scanout to the planes `request` under
    /// `plan` without relighting it (`Otg::update_live_planes`: DC's medium
    /// or full plane update under the OTG lock, new pipes enabled off-tree
    /// first, freed ones retired after the update latched), fresh surfaces
    /// holding `content`'s first frame.
    /// # Safety
    /// As for `prepare_display_deadlines`; the scanout stays live. Every CPU
    /// view of a surface the update replaces must be withdrawn.
    pub async unsafe fn update_live_display_planes(
        &mut self,
        pipe: u8,
        request: &otg::LivePlanes,
        plan: &crate::amdgpu_dcn401_dml::Plan,
        content: &mut dyn otg::PlaneContent,
    ) -> Result<alloc::boxed::Box<otg::PlanesUpdated>, otg::Error> {
        // dcn401_prepare_bandwidth: pinned before any configuration change.
        self.pin_display_uclk().await?;
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .update_live_planes(
                    &self.sequence.backend.pool,
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    request,
                    plan,
                    crystal,
                    content,
                )
                .await
        }
    }
    /// Program a DPP-only clock (`request`, an `OdmSegment` pipe) for a
    /// free pipe a live display's new plane takes, every display's
    /// consumers (the selected one's too) left to them.
    pub async fn prepare_display_plane_clock_live(
        &mut self,
        request: dccg::Request,
    ) -> Result<dccg::Applied, dccg::Error> {
        if self.display_retirement_busy() || request.pixel != dccg::PixelClock::OdmSegment {
            return Err(dccg::Error::Busy);
        }
        let held = self.otg.as_ref().map_err(|_| dccg::Error::Busy)?.all_held();
        let clocks = self.clocks.as_mut().map_err(|e| dccg::Error::Clocks(*e))?;
        self.dccg
            .as_mut()
            .map_err(|e| *e)?
            .prepare_except(clocks, request, &held)
            .await
    }
    /// dcn401_update_clocks on the running configuration: the global floors
    /// moved to `request` (only raised unless `safe_to_lower`) with every
    /// display live, the DPP DTOs of the running pipes `targets` (pipe,
    /// DPPCLK) updated at Linux's points, then every clock record and every
    /// display's timing records rebound to the clocks now running.
    /// Failure leaves the clock owner failed.
    pub async fn update_live_display_clocks(
        &mut self,
        request: clocks::Request,
        targets: &[(u8, u32)],
        safe_to_lower: bool,
    ) -> Result<clocks::Applied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let held = otg.all_held();
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        let regs = self.sequence.backend.gpu.regs;
        let old = clocks
            .retained_pipe_clocks(regs)
            .map_err(otg::Error::Clocks)?;
        let mut dto = |ref_khz: u32| {
            dccg.update_dpp_dtos(regs, ref_khz, targets, safe_to_lower)
                .map_err(|_| clocks::Error::Dto)
        };
        let new = clocks
            .update_live(regs, request, safe_to_lower, &held, &mut dto)
            .await
            .map_err(otg::Error::Clocks)?;
        rebind_display_clocks(otg, dccg, old, new)?;
        Ok(new)
    }
    /// Whether PMFW may switch UCLK under the running displays now
    /// (`clocks::Status::uclk_switching`: a bandwidth sequence this owner
    /// ran allowed it).
    pub fn uclk_switching(&self) -> bool {
        self.clocks
            .as_ref()
            .is_ok_and(|c| c.status().uclk_switching())
    }
    /// dcn401_update_clocks' bandwidth part on the running configuration:
    /// the UCLK/FCLK P-state policy and floors and the deep-sleep DCFCLK
    /// moved to `bandwidth` (`safe_to_lower` false raises and disallows,
    /// true lowers and allows), every display's clock records then rebound.
    /// Failure leaves the clock owner failed.
    pub async fn update_live_display_bandwidth(
        &mut self,
        bandwidth: clocks::Bandwidth,
        safe_to_lower: bool,
    ) -> Result<clocks::Applied, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let held = otg.all_held();
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        let regs = self.sequence.backend.gpu.regs;
        let old = clocks
            .retained_pipe_clocks(regs)
            .map_err(otg::Error::Clocks)?;
        clocks
            .admit_dynamic_power(regs, &held)
            .await
            .map_err(otg::Error::Clocks)?;
        let new = clocks
            .update_bandwidth(regs, bandwidth, safe_to_lower, &held)
            .await
            .map_err(otg::Error::Clocks)?;
        rebind_display_clocks(otg, dccg, old, new)?;
        Ok(new)
    }
    /// dcn401_optimize_bandwidth once no display is left (dc_commit_streams
    /// with no stream, as the last CRTC's disable and dm_suspend commit
    /// it): FAMS2 disabled (`disable_display_fams2`), then
    /// `clocks::ClockManager::release` (NumOfDisplays 0, DCFCLK, UCLK and
    /// FCLK at their lowest levels, UCLK switching allowed), every clock
    /// record rebound. Nothing before the display clocks were prepared, or
    /// when it already ran. Busy while a display or teardown remains.
    pub async fn release_display_bandwidth(&mut self) -> Result<(), otg::Error> {
        if self.display_retirement_busy()
            || self.teardowns.check_idle().is_err()
            || self.display_modesets().iter().any(Option::is_some)
        {
            return Err(otg::Error::Busy);
        }
        // Only an applied configuration that still counts displays.
        if !self.display_clock_status().is_ok_and(|s| {
            s.state == clocks::State::Applied && s.applied.is_some_and(|a| a.request.displays != 0)
        }) {
            return Ok(());
        }
        self.disable_display_fams2().await?;
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let clocks = self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?;
        let dccg = self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?;
        let regs = self.sequence.backend.gpu.regs;
        let old = clocks
            .retained_pipe_clocks(regs)
            .map_err(otg::Error::Clocks)?;
        let new = clocks.release(regs).await.map_err(otg::Error::Clocks)?;
        rebind_display_clocks(otg, dccg, old, new)
    }
    /// Whether DC keeps FAMS2 on for the running DMCUB firmware (FAMS 2.1).
    pub fn display_fams2(&self) -> bool {
        self.sequence.backend.dmub.fams2() == Some(true)
            && self.sequence.backend.dmub.fams2_lock_ready()
    }
    /// dcn401_prepare_bandwidth before a configuration change
    /// (`bandwidth::pin_uclk`): when PMFW may switch UCLK, UCLK and FCLK
    /// raised to their highest levels with switching disallowed, then FAMS2
    /// disabled, so that every plan (pinned or not) runs again. Nothing when
    /// nothing allowed switching: a fresh owner (cold boot, S3 or runtime
    /// resume, before the display clocks are prepared) or one already pinned.
    pub async fn pin_display_uclk(&mut self) -> Result<(), otg::Error> {
        bandwidth::pin_uclk(self).await
    }
    /// `pin_display_uclk` before a teardown: best-effort, as Linux's void
    /// prepare_bandwidth never stops a stream from being disabled (a
    /// failure is logged and the teardown goes on).
    pub(crate) async fn pin_display_uclk_for_teardown(&mut self) {
        let _ = bandwidth::pin_uclk_for_teardown(self).await;
    }
    /// Program `request`'s pipe clock for the selected display while the
    /// others run (their consumers left to them).
    pub async fn prepare_display_pipe_clocks_beside(
        &mut self,
        request: dccg::Request,
    ) -> Result<dccg::Applied, dccg::Error> {
        if self.display_retirement_busy() {
            return Err(dccg::Error::Busy);
        }
        let held = self
            .otg
            .as_ref()
            .map_err(|_| dccg::Error::Busy)?
            .siblings_held();
        let clocks = self.clocks.as_mut().map_err(|e| dccg::Error::Clocks(*e))?;
        self.dccg
            .as_mut()
            .map_err(|e| *e)?
            .prepare_except(clocks, request, &held)
            .await
    }
    /// Make the staged surface the visible source of the pipe's running black
    /// DP video, after re-binding its programmed deadlines.
    /// # Safety
    /// The surface must hold the intended image and stay allocated until a
    /// successful stop. Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/
    /// clock/reset/power writers; retain everything on failure or cancellation.
    pub async unsafe fn start_display_scanout(
        &mut self,
        pipe: u8,
    ) -> Result<otg::ScanoutRunning, otg::Error> {
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_scanout(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    crystal,
                )
                .await
        }
    }
    /// Re-verify a live scanout and return its frame count; an underflow
    /// returns the pipe to black and is retained in the OTG status.
    /// # Safety
    /// As for `start_display_scanout`.
    pub async unsafe fn check_display_scanout(&mut self, pipe: u8) -> Result<u32, otg::Error> {
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .check_scanout(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    crystal,
                )
                .await
        }
    }
    /// The live scanout as a CPU framebuffer (bus-physical BAR address).
    /// Read-only: display `pipe`'s running timing generator frame count and
    /// scanout position (`pipe` is the display's head pipe).
    pub fn display_scanout_position(
        &mut self,
        pipe: u8,
    ) -> Result<otg::ScanoutPosition, otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        self.otg.as_mut().map_err(|e| *e)?.scanout_position(pipe)
    }
    pub fn display_scanout_framebuffer(
        &self,
        pipe: u8,
    ) -> Result<narf_graphics_driver::generic::GenericFb, otg::Error> {
        self.otg.as_ref().map_err(|e| *e)?.scanout_framebuffer(pipe)
    }
    /// Allocate, clear and retain a back buffer for a staged or live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers.
    pub async unsafe fn prepare_display_back_buffer(
        &mut self,
        pipe: u8,
    ) -> Result<u64, otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: this owner retains its pool and GMC; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_back_buffer(&self.sequence.backend.pool, gmc, pipe)
                .await
        }
    }
    /// `prepare_display_back_buffer` for plane `pipe` (an overlay's) of
    /// display `display`.
    /// # Safety
    /// As for `prepare_display_back_buffer`.
    pub async unsafe fn prepare_display_plane_back_buffer(
        &mut self,
        display: u8,
        pipe: u8,
    ) -> Result<u64, otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: this owner retains its pool and GMC; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_plane_back_buffer(&self.sequence.backend.pool, gmc, display, pipe)
                .await
        }
    }
    /// `upload_display_back` into plane `pipe` of display `display`.
    /// # Safety
    /// As for `upload_display_back`.
    pub unsafe fn upload_display_plane_back(
        &mut self,
        display: u8,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .upload_plane_back_buffer(display, pipe, x, y, pixels)
        }
    }
    /// `upload_display_plane_back` by byte offset into the plane's surface
    /// (tiled and 4:2:0 frames are copied whole, block row by block row).
    /// # Safety
    /// As for `upload_display_back`.
    pub unsafe fn upload_display_plane_back_bytes(
        &mut self,
        display: u8,
        pipe: u8,
        offset: u64,
        words: &[u32],
    ) -> Result<(), otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .upload_plane_back_bytes(display, pipe, offset, words)
        }
    }
    /// Flip the planes in `planes` (bit 0 the primary, bit k the k-th
    /// overlay) of display `pipe` to their back buffers at one VUPDATE.
    /// # Safety
    /// As for `flip_display`, for every flipping plane.
    pub async unsafe fn flip_display_planes(
        &mut self,
        pipe: u8,
        planes: u8,
    ) -> Result<[Option<otg::FlipDone>; 1 + otg::MAX_OVERLAYS], otg::Error> {
        let locked = self.begin_fams2_io().await?;
        let result = async {
            let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
            let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
            // SAFETY: matching retained owners are serialized; caller excludes writers.
            unsafe {
                self.otg
                    .as_mut()
                    .map_err(|e| *e)?
                    .flip_planes(
                        self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                        self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                        gmc,
                        pipe,
                        planes,
                        crystal,
                    )
                    .await
            }
        }
        .await;
        self.finish_fams2_io(locked, result).await
    }
    /// `flip_display_planes` with each plane's source: its back buffer or a
    /// client framebuffer scanned out in place (`otg::FlipSource`).
    /// # Safety
    /// As for `flip_display_planes`; every client framebuffer stays pinned
    /// in VRAM until a later flip or stop shows it no longer fetched
    /// (`display_fetched_addresses`).
    pub async unsafe fn flip_display_sources(
        &mut self,
        pipe: u8,
        sources: [Option<otg::FlipSource>; 1 + otg::MAX_OVERLAYS],
    ) -> Result<[Option<otg::FlipDone>; 1 + otg::MAX_OVERLAYS], otg::Error> {
        let locked = self.begin_fams2_io().await?;
        let result = async {
            let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
            let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
            // SAFETY: matching retained owners are serialized; caller excludes
            // writers and keeps every client framebuffer pinned.
            unsafe {
                self.otg
                    .as_mut()
                    .map_err(|e| *e)?
                    .flip_sources(
                        self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                        self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                        gmc,
                        pipe,
                        sources,
                        crystal,
                    )
                    .await
            }
        }
        .await;
        self.finish_fams2_io(locked, result).await
    }
    /// What display `pipe`'s HUBPs fetch, when known (`Otg::fetched_addresses`);
    /// none without a display owner.
    pub fn display_fetched_addresses(
        &self,
        pipe: u8,
    ) -> Option<[Option<u64>; 1 + otg::MAX_OVERLAYS]> {
        self.otg.as_ref().ok()?.fetched_addresses(pipe)
    }
    /// The back buffer as a CPU framebuffer (bus-physical BAR address).
    pub fn display_back_framebuffer(
        &self,
        pipe: u8,
    ) -> Result<narf_graphics_driver::generic::GenericFb, otg::Error> {
        self.otg.as_ref().map_err(|e| *e)?.back_framebuffer(pipe)
    }
    /// Write part of one row of the next frame into a live pipe's back
    /// buffer; the next `flip_display` publishes it.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers.
    pub unsafe fn upload_display_back(
        &mut self,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .upload_back_buffer(pipe, x, y, pixels)
        }
    }
    /// Flip a live scanout to its back buffer at the next VUPDATE.
    /// # Safety
    /// The back buffer must hold the complete next frame with no CPU writer
    /// until the next flip. Exclude firmware/FAMS and concurrent display/hub/
    /// VM/IRQ/clock/reset/power writers; a failure quarantines the pipe.
    pub async unsafe fn flip_display(&mut self, pipe: u8) -> Result<otg::FlipDone, otg::Error> {
        let locked = self.begin_fams2_io().await?;
        let result = async {
            let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
            let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
            // SAFETY: matching retained owners are serialized; caller excludes writers.
            unsafe {
                self.otg
                    .as_mut()
                    .map_err(|e| *e)?
                    .flip(
                        self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                        self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                        gmc,
                        pipe,
                        crystal,
                    )
                    .await
            }
        }
        .await;
        self.finish_fams2_io(locked, result).await
    }
    /// Show a premultiplied ARGB8888 cursor (at most 64x64) on a live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers.
    pub unsafe fn set_display_cursor(
        &mut self,
        pipe: u8,
        image: (u32, u32, &[u32]),
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        if self.fams2_active || self.fams2_pending {
            return Err(otg::Error::Busy);
        }
        // SAFETY: no firmware scheduling, and the caller retains the display.
        unsafe { self.set_cursor_inner(pipe, image, position) }
    }
    /// Await firmware exclusion before changing cursor registers.
    /// # Safety
    /// As for [`Self::set_display_cursor`].
    pub async unsafe fn set_display_cursor_async(
        &mut self,
        pipe: u8,
        image: (u32, u32, &[u32]),
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        let locked = self.begin_fams2_io().await?;
        // SAFETY: the acknowledged lock excludes firmware; caller excludes writers.
        let result = unsafe { self.set_cursor_inner(pipe, image, position) };
        self.finish_fams2_io(locked, result).await
    }
    unsafe fn set_cursor_inner(
        &mut self,
        pipe: u8,
        image: (u32, u32, &[u32]),
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: this owner retains its pool and GMC; caller excludes writers.
        unsafe {
            self.otg.as_mut().map_err(|e| *e)?.set_cursor(
                &self.sequence.backend.pool,
                gmc,
                pipe,
                image,
                position,
            )
        }
    }
    /// Move the live cursor; it hides itself when entirely off screen.
    /// # Safety
    /// As for `set_display_cursor`.
    pub unsafe fn move_display_cursor(
        &mut self,
        pipe: u8,
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        if self.fams2_active || self.fams2_pending {
            return Err(otg::Error::Busy);
        }
        // SAFETY: no firmware scheduling, and the caller retains the display.
        unsafe { self.move_cursor_inner(pipe, position) }
    }
    /// Await firmware exclusion before changing cursor registers.
    /// # Safety
    /// As for [`Self::move_display_cursor`].
    pub async unsafe fn move_display_cursor_async(
        &mut self,
        pipe: u8,
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        let locked = self.begin_fams2_io().await?;
        // SAFETY: the acknowledged lock excludes firmware; caller excludes writers.
        let result = unsafe { self.move_cursor_inner(pipe, position) };
        self.finish_fams2_io(locked, result).await
    }
    unsafe fn move_cursor_inner(
        &mut self,
        pipe: u8,
        position: (i32, i32),
    ) -> Result<otg::CursorApplied, otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .move_cursor(pipe, position)
        }
    }
    /// Run (`Some`) or stop (`None`) DRR on a live pipe's timing; `Busy`
    /// for DRR while PMFW may switch UCLK (pin it first).
    /// # Safety
    /// As for `set_display_cursor`.
    pub async unsafe fn set_display_drr(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<Option<otg::DrrApplied>, otg::Error> {
        // Changing refresh limits invalidates any existing P-state plan.
        if self.fams2_active
            || self.fams2_pending
            || self.state() != State::MemoryReady
            || self.uclk_switching()
        {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.set_drr(pipe, drr) }.await
    }
    /// Configure LFC from the admitted variable-refresh range. Nominal
    /// DML and the pinned memory-clock contract remain unchanged.
    /// # Safety
    /// As for `set_display_cursor`.
    pub async unsafe fn set_display_lfc(
        &mut self,
        pipe: u8,
        config: Option<crate::amdgpu_freesync::LfcConfig>,
    ) -> Result<(), otg::Error> {
        if self.fams2_active
            || self.fams2_pending
            || self.state() != State::MemoryReady
            || (config.is_some() && self.uclk_switching())
        {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes timing writers.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.set_lfc(pipe, config) }.await
    }
    /// Advance LFC only from a real observed frame transition.
    /// # Safety
    /// As for `set_display_cursor`; no cancelled display operation may be serviced.
    pub unsafe fn display_lfc_progress(&mut self, pipe: u8, lost: bool) -> Result<(), otg::Error> {
        if self.fams2_active
            || self.fams2_pending
            || self.state() != State::MemoryReady
            || self.uclk_switching()
        {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes timing writers.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.lfc_progress(pipe, lost) }
    }
    /// Apply a finite native MID-for-MAX sequence independently of BTR.
    /// # Safety
    /// As for `set_display_cursor`; keep UCLK pinned until DRR is disabled.
    pub unsafe fn set_display_drr_mid(
        &mut self,
        pipe: u8,
        mid: Option<otg::DrrMid>,
    ) -> Result<(), otg::Error> {
        if self.fams2_active
            || self.fams2_pending
            || self.state() != State::MemoryReady
            || self.uclk_switching()
        {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes timing writers.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.set_drr_mid(pipe, mid) }
    }
    /// Apply the live FreeSync timing and SPD under the same display owner.
    /// # Safety
    /// As for `set_display_cursor`.
    pub async unsafe fn set_display_freesync(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<Option<otg::DrrApplied>, otg::Error> {
        if self.fams2_active
            || self.fams2_pending
            || self.state() != State::MemoryReady
            || self.uclk_switching()
        {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .set_freesync(pipe, drr, packet)
        }
        .await
    }
    /// Set display `pipe`'s CRTC color: a live scanout is reprogrammed at
    /// once (no modeset), otherwise its next scanout start programs it.
    /// # Safety
    /// As for `set_display_cursor`.
    pub async unsafe fn set_display_color(
        &mut self,
        pipe: u8,
        program: Option<alloc::sync::Arc<otg::ColorProgram>>,
    ) -> Result<(), otg::Error> {
        let locked = self.begin_fams2_io().await?;
        let result = async {
            if self.state() != State::MemoryReady {
                return Err(otg::Error::Busy);
            }
            // SAFETY: serialized retained owner; caller excludes writers.
            unsafe { self.otg.as_mut().map_err(|e| *e)?.set_color(pipe, program) }.await
        }
        .await;
        self.finish_fams2_io(locked, result).await
    }
    /// New HDR metadata on display `pipe`'s running stream (no modeset).
    /// # Safety
    /// As for `set_display_cursor`.
    pub async unsafe fn set_display_hdr(
        &mut self,
        pipe: u8,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), otg::Error> {
        let locked = self.begin_fams2_io().await?;
        let result = async {
            if self.state() != State::MemoryReady {
                return Err(otg::Error::Busy);
            }
            // SAFETY: serialized retained owner; caller excludes writers.
            unsafe { self.otg.as_mut().map_err(|e| *e)?.set_hdr(pipe, packet) }.await
        }
        .await;
        self.finish_fams2_io(locked, result).await
    }
    /// The HDR packet display `pipe`'s running stream sends.
    pub fn display_hdr(&self, pipe: u8) -> Option<crate::amdgpu_hdr::InfoPacket> {
        self.otg.as_ref().ok().and_then(|o| o.hdr(pipe))
    }
    /// The CRTC color display `pipe` was last given.
    pub fn display_color(&self, pipe: u8) -> Option<alloc::sync::Arc<otg::ColorProgram>> {
        self.otg.as_ref().ok().and_then(|o| o.color(pipe))
    }
    /// HDP-flush CPU writes to the live scanout surface.
    pub fn flush_display_scanout(&mut self) -> Result<(), otg::Error> {
        if self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        self.otg.as_mut().map_err(|e| *e)?.flush_scanout_writes()
    }
    /// Return a live pipe to black video with fetch drained and clocks gated.
    /// # Safety
    /// As for `start_display_scanout`; on failure the surface stays allocated.
    pub async unsafe fn stop_display_scanout(&mut self, pipe: u8) -> Result<(), otg::Error> {
        let crystal = *self.crystal.as_ref().map_err(|_| otg::Error::Unsupported)?;
        let gmc = self.sequence.backend.gmc.as_mut().ok_or(otg::Error::Busy)?;
        // SAFETY: matching retained owners are serialized; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_scanout(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    gmc,
                    pipe,
                    crystal,
                )
                .await
        }
    }
    /// Blank one native DP video stream before separate encoder/PHY retirement.
    /// # Safety
    /// Stop CPU scanout writers, exclude firmware/FAMS and concurrent display,
    /// audio/packet/link/clock/power writers, and retain all associated memory
    /// and translations. This proves video blanking only, never memory retirement.
    pub async unsafe fn blank_display_dp_stream(
        &mut self,
        stream: otg::DpStream,
    ) -> Result<otg::DpBlanked, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: matching retained owner; caller excludes writers and retains memory.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .blank_dp_stream(stream)
                .await
        }
    }
    /// Retire a blank native DP stream encoder, retaining PHYs and allocations.
    /// # Safety
    /// Exclude CPU/firmware/FAMS and concurrent display/audio/link/power writers;
    /// retain all allocations and translations. Independently retire sink/MST
    /// bookkeeping and audio/metadata producers. This does not retire memory.
    pub async unsafe fn retire_display_dp_encoder(
        &mut self,
        stream: otg::DpStream,
    ) -> Result<otg::DpEncoderRetired, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: serialized retained owner; caller excludes writers and retains memory.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_dp_encoder(stream)
                .await
        }
    }
    /// Retire a TMDS HDMI frontend, preserving backend/PHY/OTG clocks.
    /// # Safety
    /// Fulfil `Otg::retire_hdmi_tmds_encoder` sink/SCDC/retimer, audio/metadata/
    /// HDCP and writer-exclusion obligations. Retain all memory/translations;
    /// success is not link or memory retirement.
    pub async unsafe fn retire_display_hdmi_tmds_encoder(
        &mut self,
        stream: u8,
    ) -> Result<otg::HdmiTmdsRetired, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: retained matching owner; caller fulfils the documented obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_hdmi_tmds_encoder(stream)
                .await
        }
    }
    /// Retire the native FRL frontend, preserving link/PHY and timing clocks.
    /// # Safety
    /// Fulfil `Otg::retire_hdmi_frl_encoder` sink/SCDC/retimer, audio/ACR/metadata/
    /// HDCP and writer-exclusion obligations. Retain all memory/translations;
    /// success is not link or memory retirement.
    pub async unsafe fn retire_display_hdmi_frl_encoder(
        &mut self,
    ) -> Result<otg::FrlEncoderRetired, otg::Error> {
        if self.display_retirement_busy() {
            return Err(otg::Error::Busy);
        }
        // SAFETY: retained matching owner; caller fulfils the documented obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_hdmi_frl_encoder()
                .await
        }
    }
    /// Enable an untrained external legacy DP PHY after display clock preparation.
    /// # Safety
    /// Fulfil `Otg::enable_dp_phy` board/sink/cable limits, direct-port, producer
    /// and writer-exclusion obligations. Retain all memory/translations. Sink
    /// power, link training and scanout are separate operations.
    pub async unsafe fn enable_display_dp_phy(
        &mut self,
        port: usize,
        settings: otg::DpPhySettings,
    ) -> Result<otg::DpPhyReady, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: validated board route and matching retained owners; caller
        // establishes link limits, platform interlocks and resource obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .enable_dp_phy(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                    settings,
                )
                .await
        }
    }
    /// Disable only this owner's matching, still-untrained DP PHY.
    /// # Safety
    /// Fulfil the same direct-port, producer/writer exclusion and retention
    /// obligations as `enable_display_dp_phy`. No analog power or memory release.
    pub async unsafe fn disable_display_dp_phy(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained owner; caller fulfils the documented obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .disable_dp_phy(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    fn dp_phy_path(&self, port: usize) -> Result<inventory::Path, otg::Error> {
        if self.display_retirement_busy()
            || self.display_state() != Ok(display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(otg::Error::Busy);
        }
        self.display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .copied()
            .ok_or(otg::Error::Invalid)
    }
    /// Train the retained legacy DP PHY at its current lane count and rate.
    /// # Safety
    /// Fulfil `Otg::train_dp_link` direct-port, board SSC, producer/writer
    /// exclusion and memory-retention obligations. No scanout or rate fallback.
    pub async unsafe fn train_display_dp_link(
        &mut self,
        port: usize,
        downspread: bool,
    ) -> Result<otg::DpLinkTrained, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained board path and serialized owners; caller
        // establishes physical topology, SSC setting and lifetime obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .train_dp_link(
                    &mut self.sequence.backend.dmub,
                    path,
                    downspread,
                    self.lttpr_non_transparent,
                )
                .await
        }
    }
    /// Enable a 128b/132b link on HPO link encoder `link` and train the sink.
    /// # Safety
    /// Fulfil `Otg::train_uhbr_link` obligations.
    pub async unsafe fn train_display_uhbr_link(
        &mut self,
        port: usize,
        settings: otg::UhbrSettings,
        link: u8,
    ) -> Result<otg::UhbrLinkTrained, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: validated board route and matching retained owners; the
        // caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .train_uhbr_link(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                    settings,
                    link,
                )
                .await
        }
    }
    /// Stop the port's trained or refused 128b/132b link; `unplugged` skips
    /// the sink and requires HPD low.
    /// # Safety
    /// Fulfil `Otg::stop_uhbr_link` obligations.
    pub async unsafe fn stop_display_uhbr_link(
        &mut self,
        port: usize,
        unplugged: bool,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let dmub = &mut self.sequence.backend.dmub;
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            if unplugged {
                otg.stop_unplugged_uhbr_link(dmub, path).await
            } else {
                otg.stop_uhbr_link(dmub, path).await
            }
        }
    }
    /// Prepare a blank frontend for the retained trained DP link and staged OPP.
    /// # Safety
    /// Fulfil `Otg::prepare_dp_frontend` direct-port, clock/timing ownership and
    /// writer/resource obligations. This does not enable video or scanout.
    pub async unsafe fn prepare_display_dp_frontend(
        &mut self,
        port: usize,
        request: otg::DpFrontendRequest,
    ) -> Result<otg::DpFrontendReady, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained owners and board path; caller excludes
        // external producers/writers and keeps all resources alive.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_dp_frontend(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                    request,
                )
                .await
        }
    }
    /// Start RGB black video on the prepared, trained legacy DP frontend.
    /// # Safety
    /// Fulfil `Otg::start_dp_video` exclusive writer and resource obligations
    /// for the whole running lifetime. This does not enable surface scanout.
    pub async unsafe fn start_display_dp_video(
        &mut self,
        port: usize,
    ) -> Result<otg::DpVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_dp_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                )
                .await
        }
    }
    /// enable_stream_features on the port's running DP SST stream: the
    /// sink's IGNORE_MSA_TIMING_PARAM set as the stream is VRR-capable.
    /// # Safety
    /// As for `start_display_dp_video`.
    pub async unsafe fn set_display_dp_ignore_msa(
        &mut self,
        port: usize,
        ignore_msa: bool,
    ) -> Result<bool, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .set_dp_ignore_msa(&mut self.sequence.backend.dmub, path, ignore_msa)
                .await
        }
    }
    /// Start black 128b/132b video on the port's trained UHBR link through
    /// HPO stream encoder `stream`, from `pipe`'s prepared timing, sending
    /// the VSC/HDR SDPs `sdp` asks for.
    /// # Safety
    /// Fulfil `Otg::start_uhbr_video` obligations.
    pub async unsafe fn start_display_uhbr_video(
        &mut self,
        port: usize,
        stream: u8,
        pipe: u8,
        sdp: otg::UhbrSdp,
    ) -> Result<otg::UhbrVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_uhbr_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                    stream,
                    pipe,
                    sdp,
                )
                .await
        }
    }
    /// Stop the port's 128b/132b video, retaining the trained link.
    /// # Safety
    /// Fulfil `Otg::stop_uhbr_video` obligations.
    pub async unsafe fn stop_display_uhbr_video(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller fulfils the lifetime contract.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_uhbr_video(
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                )
                .await
        }
    }
    /// Prepare the selected display's MST stream on the port's 128b/132b
    /// MST link through HPO stream encoder `stream`, from `pipe`'s prepared
    /// timing, blank, for a payload of `slots`, with the VSC/HDR SDPs `sdp`.
    /// # Safety
    /// Fulfil `Otg::prepare_uhbr_mst_stream` obligations.
    pub async unsafe fn prepare_display_uhbr_mst_stream(
        &mut self,
        port: usize,
        stream: u8,
        pipe: u8,
        slots: u8,
        sdp: otg::UhbrSdp,
    ) -> Result<otg::UhbrVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_uhbr_mst_stream(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                    stream,
                    pipe,
                    slots,
                    sdp,
                )
                .await
        }
    }
    /// Unblank the selected display's prepared 128b/132b MST stream.
    /// # Safety
    /// Fulfil `Otg::start_uhbr_mst_video` obligations.
    pub async unsafe fn start_display_uhbr_mst_video(
        &mut self,
        port: usize,
    ) -> Result<otg::UhbrVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_uhbr_mst_video(path)
                .await
        }
    }
    /// Blank the selected display's running 128b/132b MST stream.
    /// # Safety
    /// Fulfil `Otg::blank_uhbr_mst_video` obligations.
    pub async unsafe fn blank_display_uhbr_mst_video(
        &mut self,
        port: usize,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .blank_uhbr_mst_video(path)
                .await
        }
    }
    /// Stop the selected display's blanked 128b/132b MST stream, its
    /// payload removed.
    /// # Safety
    /// Fulfil `Otg::stop_uhbr_mst_stream` obligations.
    pub async unsafe fn stop_display_uhbr_mst_stream(
        &mut self,
        port: usize,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_uhbr_mst_stream(
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                )
                .await
        }
    }
    /// Blank video and stop timing, retaining the prepared frontend and link.
    /// # Safety
    /// Fulfil `Otg::stop_dp_video` writer/resource lifetime obligations.
    pub async unsafe fn stop_display_dp_video(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller fulfils the lifetime contract.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_dp_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                )
                .await
        }
    }
    /// Stop the matching blank frontend and return to the trained DP link.
    /// # Safety
    /// Fulfil `Otg::stop_dp_frontend` writer/resource and stopped-video obligations.
    pub async unsafe fn stop_display_dp_frontend(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained owner; caller fulfils documented obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_dp_frontend(path)
                .await
        }
    }
    /// Request sink D3 and stop this owner's trained, streamless legacy DP PHY.
    /// # Safety
    /// Fulfil `Otg::stop_dp_link` direct-port and writer/resource obligations.
    pub async unsafe fn stop_display_dp_link(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained board path/owners; caller excludes writers
        // and retains all allocations/translations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_dp_link(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Stop the trained link of a departed sink (debounced HPD low) without
    /// addressing the sink.
    /// # Safety
    /// As for `stop_display_dp_link`; the port's HPD must have been enabled.
    pub async unsafe fn stop_unplugged_display_dp_link(
        &mut self,
        port: usize,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_unplugged_dp_link(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Program the PHY PLL, encoders and transmitter of an HDMI port for the
    /// staged black timing of `request.pipe`, with that timing still stopped.
    /// # Safety
    /// Fulfil `Otg::prepare_hdmi_link` direct-port, sink and writer obligations.
    pub async unsafe fn prepare_display_hdmi_link(
        &mut self,
        port: usize,
        request: otg::HdmiLinkRequest,
    ) -> Result<otg::HdmiLinkReady, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .prepare_hdmi_link(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    &mut self.sequence.backend.dmub,
                    path,
                    request,
                )
                .await
        }
    }
    /// Start black video on the prepared HDMI link and release AVMUTE.
    /// # Safety
    /// Fulfil `Otg::start_hdmi_video` obligations for the running lifetime.
    pub async unsafe fn start_display_hdmi_video(
        &mut self,
        port: usize,
    ) -> Result<otg::HdmiVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller excludes external writers.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_hdmi_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                )
                .await
        }
    }
    /// Mute and stop the HDMI timing, keeping the link transmitting.
    /// # Safety
    /// Fulfil `Otg::stop_hdmi_video` obligations; scanout already stopped.
    pub async unsafe fn stop_display_hdmi_video(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; caller fulfils the lifetime contract.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_hdmi_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                )
                .await
        }
    }
    /// Disable the owned HDMI transmitter and frontend; timing is stopped.
    /// # Safety
    /// Fulfil `Otg::stop_hdmi_link` obligations.
    pub async unsafe fn stop_display_hdmi_link(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_hdmi_link(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Start audio on the port's running HDMI or DP video, on the Azalia
    /// `endpoint` its stream acquired (`StreamEncoders::audio`).
    /// # Safety
    /// Fulfil `Otg::start_hdmi_audio` or `Otg::start_dp_audio` obligations.
    /// For MST also exclude payload changes; the retained manager allocation
    /// and fresh source SAT/VC witnesses must agree before endpoint exposure.
    pub async unsafe fn start_display_audio(
        &mut self,
        port: usize,
        hdmi: bool,
        info: otg::AudioInfo,
        endpoint: u8,
    ) -> Result<otg::DisplayAudio, otg::Error> {
        let path = self.dp_phy_path(port)?;
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let status = otg.status();
        let mst_stream = status
            .dp_video_running
            .filter(|v| v.frontend.link.phy.settings.mst)
            .map(|v| v.frontend.request.stream)
            .or(status
                .uhbr_video_running
                .filter(|v| v.link.settings.mst)
                .map(|v| v.stream));
        let mst_slots = if !hdmi {
            mst_stream
                .map(|stream| {
                    let link = self.mst.get(&port).ok_or(otg::Error::Invalid)?;
                    link.audio_slots(stream)
                })
                .transpose()?
        } else {
            None
        };
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            if hdmi {
                otg.start_hdmi_audio(path, info, endpoint).await
            } else if let Some(slots) = mst_slots {
                otg.start_mst_audio(path, info, slots, endpoint).await
            } else {
                otg.start_dp_audio(path, info, endpoint).await
            }
        }
    }
    /// Mute and stop the port's HDMI or DP audio.
    /// # Safety
    /// Fulfil `Otg::stop_hdmi_audio` or `Otg::stop_dp_audio` obligations.
    pub async unsafe fn stop_display_audio(
        &mut self,
        port: usize,
        hdmi: bool,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            if hdmi {
                otg.stop_hdmi_audio(path).await
            } else {
                otg.stop_dp_audio(path).await
            }
        }
    }
    /// Enable an HDMI port's PHY for FRL on `lanes` lanes at the character
    /// clock, the link left training.
    /// # Safety
    /// Fulfil `Otg::start_frl_link` obligations.
    pub async unsafe fn start_display_frl_link(
        &mut self,
        port: usize,
        lanes: u8,
        character_khz: u32,
    ) -> Result<otg::FrlLinkUp, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: validated board route and retained owners; caller's
        // obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_frl_link(&mut self.sequence.backend.dmub, path, lanes, character_khz)
                .await
        }
    }
    /// Set the port's FRL training patterns (LTP - 1 per lane).
    /// # Safety
    /// Fulfil `Otg::frl_training_pattern` obligations.
    pub unsafe fn display_frl_pattern(
        &mut self,
        port: usize,
        patterns: [u8; 4],
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .frl_training_pattern(path, patterns)
        }
    }
    /// Last acknowledged FRL FFE level, after checking this port's live route.
    pub fn display_frl_current_ffe(&mut self, port: usize) -> Result<u8, otg::Error> {
        let path = self.dp_phy_path(port)?;
        self.otg.as_mut().map_err(|e| *e)?.frl_current_ffe(path)
    }
    /// Program the port's FRL TxFFE lane set.
    /// # Safety
    /// Fulfil `Otg::frl_ffe` obligations.
    pub async unsafe fn display_frl_ffe(
        &mut self,
        port: usize,
        lane_set: u8,
    ) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .frl_ffe(&mut self.sequence.backend.dmub, path, lane_set)
                .await
        }
    }
    /// End FRL training: FRL output on the port's trained link.
    /// # Safety
    /// Fulfil `Otg::frl_link_output` obligations.
    pub unsafe fn display_frl_output(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.frl_link_output(path) }
    }
    /// Stop the port's FRL link.
    /// # Safety
    /// Fulfil `Otg::stop_frl_link` obligations.
    pub async unsafe fn stop_display_frl_link(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_frl_link(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Start black FRL video on the port's active FRL link.
    /// # Safety
    /// Fulfil `Otg::start_frl_video` obligations.
    pub async unsafe fn start_display_frl_video(
        &mut self,
        port: usize,
        request: otg::FrlVideoRequest,
    ) -> Result<otg::FrlVideoRunning, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .start_frl_video(
                    self.clocks.as_mut().map_err(|e| otg::Error::Clocks(*e))?,
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                    request,
                )
                .await
        }
    }
    /// Stop the port's FRL video, keeping the link active.
    /// # Safety
    /// Fulfil `Otg::stop_frl_video` obligations.
    pub async unsafe fn stop_display_frl_video(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: retained matching owners; the caller's obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .stop_frl_video(
                    self.dccg.as_mut().map_err(|e| otg::Error::PipeClocks(*e))?,
                    path,
                )
                .await
        }
    }
    /// Read one SCDC register of an HDMI port's sink over native DDC.
    pub async fn display_scdc_read(&mut self, port: usize, offset: u8) -> Result<u8, ddc::Error> {
        let channel = self.scdc_channel(port)?;
        self.ddc
            .as_mut()
            .map_err(|_| ddc::Error::Unsupported)?
            .scdc_read(channel, offset)
            .await
    }
    /// Write one SCDC register of an HDMI port's sink over native DDC.
    pub async fn display_scdc_write(
        &mut self,
        port: usize,
        offset: u8,
        value: u8,
    ) -> Result<(), ddc::Error> {
        let channel = self.scdc_channel(port)?;
        self.ddc
            .as_mut()
            .map_err(|_| ddc::Error::Unsupported)?
            .scdc_write(channel, offset, value)
            .await
    }
    fn scdc_channel(&self, port: usize) -> Result<u8, ddc::Error> {
        let path = self
            .display_paths()
            .map_err(|_| ddc::Error::Invalid)?
            .get(port)
            .copied()
            .ok_or(ddc::Error::Invalid)?;
        if path.connector != inventory::Connector::HdmiTypeA {
            return Err(ddc::Error::Unsupported);
        }
        path.aux.ok_or(ddc::Error::Unsupported)
    }
    /// Give a board connector's HPD pin to its HPD block and enable it.
    /// # Safety
    /// The board's HPD selector must name this connector's pin, and nothing
    /// else may drive or sample that pin as a GPIO.
    pub unsafe fn enable_display_hpd(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: board-routed selector; the caller excludes GPIO users.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.enable_hpd(path) }
    }
    /// Arm the HPD interrupt of an enabled port (and HPD-RX for DP).
    /// # Safety
    /// The interrupt service must be ready to route DCN vectors.
    pub unsafe fn enable_display_hpd_irq(&mut self, port: usize) -> Result<(), otg::Error> {
        let path = self.dp_phy_path(port)?;
        let rx = path.connector == inventory::Connector::DisplayPort;
        // SAFETY: the caller's routing obligation.
        unsafe { self.otg.as_mut().map_err(|e| *e)?.enable_hpd_irq(path, rx) }
    }
    /// Acknowledge a raised HPD/HPD-RX interrupt of a port; its sense after.
    pub fn ack_display_hpd(&mut self, port: usize) -> Result<bool, otg::Error> {
        let path = self.dp_phy_path(port)?;
        self.otg.as_mut().map_err(|e| *e)?.ack_hpd_irq(path)
    }
    /// Debounced hot-plug sense of an enabled port.
    pub fn display_hpd(&mut self, port: usize) -> Result<bool, otg::Error> {
        let path = self.dp_phy_path(port)?;
        self.otg.as_mut().map_err(|e| *e)?.hpd_sense(path)
    }
    /// The sink's lane lock on this owner's live DP link, read over AUX.
    /// # Safety
    /// Exclude other AUX users of the port.
    pub async unsafe fn display_dp_link_status(
        &mut self,
        port: usize,
    ) -> Result<otg::DpLinkStatus, otg::Error> {
        let path = self.dp_phy_path(port)?;
        // SAFETY: matching retained owner; AUX only.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .dp_link_status(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Disable a board-routed legacy DP SST transmitter before frontend retirement.
    /// # Safety
    /// Select a direct external DP port without USB-C/ACPI PHY interlocks or
    /// SSC workarounds. Independently stop sink/audio/metadata/HDCP/FEC producers,
    /// exclude CPU/firmware/FAMS and concurrent display/link/clock/power writers,
    /// and retain every allocation/translation. Success proves firmware disable
    /// and backend clock-off, not analog power gating or memory retirement.
    pub async unsafe fn disable_display_dp_sst(
        &mut self,
        port: usize,
    ) -> Result<otg::DpSstDisabled, otg::Error> {
        if self.display_retirement_busy()
            || self.display_state() != Ok(display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: validated retained board route and matching serialized owners;
        // caller fulfils the sink/platform-interlock and resource obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .disable_dp_sst(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Drain native HPO timeslots and retire the board-routed digital link.
    /// # Safety
    /// Retire sink/MST bookkeeping, audio/metadata/HDCP producers and associated
    /// streams. Exclude CPU/firmware/FAMS and concurrent display/link/clock/power
    /// writers; retain all memory/translations. PHY output and clocks stay owned.
    pub async unsafe fn retire_display_hpo_link(
        &mut self,
        port: usize,
    ) -> Result<otg::HpoLinkRetired, otg::Error> {
        if self.display_retirement_busy() || self.display_state() != Ok(display::State::Ready) {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: retained validated board route; caller excludes producers and retains memory.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_hpo_link(path)
                .await
        }
    }
    /// Retire the board-routed FRL digital link, retaining its PHY/root clocks.
    /// # Safety
    /// Fulfil `Otg::retire_frl_link` frontend, sink/SCDC/retimer, audio/metadata/
    /// HDCP and writer-exclusion obligations. Retain all allocations and
    /// translations. Success is not PHY, root-clock or memory retirement.
    pub async unsafe fn retire_display_frl_link(
        &mut self,
        port: usize,
    ) -> Result<otg::FrlLinkRetired, otg::Error> {
        if self.display_retirement_busy() || self.display_state() != Ok(display::State::Ready) {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: validated retained board path; caller excludes producers and retains memory.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .retire_frl_link(path)
                .await
        }
    }
    /// Disable the direct FRL PHY after frontend and digital-link retirement.
    /// # Safety
    /// Fulfil `Otg::disable_frl` direct-port, sink/SCDC/retimer, producer and
    /// writer-exclusion obligations. Retain every allocation and translation;
    /// forced input clocks, timing and analog power remain owned.
    pub async unsafe fn disable_display_frl(
        &mut self,
        port: usize,
    ) -> Result<otg::FrlDisabled, otg::Error> {
        if self.display_retirement_busy()
            || self.display_state() != Ok(display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: validated board path and retained matching owners; caller
        // establishes platform interlocks, producer exclusion and memory lifetime.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .disable_frl(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    /// Disable an HPO PHY after digital-link retirement, then park its root route.
    /// # Safety
    /// Signal matches the inherited link. Use a direct external DP port without
    /// USB-C/ACPI PHY interlocks or SSC workarounds. Retire sink/MST bookkeeping,
    /// audio/metadata/HDCP producers and associated streams/link. Exclude CPU,
    /// firmware/FAMS and concurrent display/link/clock/power/reset writers;
    /// retain all memory/translations. No analog power-gating or memory-reuse proof.
    pub async unsafe fn disable_display_hpo_dp(
        &mut self,
        port: usize,
        signal: dmub::DpSignal,
    ) -> Result<otg::HpoDpDisabled, otg::Error> {
        if self.display_retirement_busy()
            || self.display_state() != Ok(display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: retained board route and matching owners; caller establishes
        // link signal, platform interlocks, producer exclusion and memory lifetime.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .disable_hpo_dp(&mut self.sequence.backend.dmub, path, signal)
                .await
        }
    }
    /// Disable direct TMDS HDMI after frontend and timing-clock retirement.
    /// # Safety
    /// Fulfil `Otg::disable_tmds` direct-port, sink/SCDC/retimer, producer and
    /// writer-exclusion obligations. Retain every allocation and translation;
    /// completion proves backend/lane/TX-clock stop, not analog power gating.
    pub async unsafe fn disable_display_tmds(
        &mut self,
        port: usize,
    ) -> Result<otg::TmdsDisabled, otg::Error> {
        if self.display_retirement_busy()
            || self.display_state() != Ok(display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(otg::Error::Busy);
        }
        let path = *self
            .display_paths()
            .map_err(|_| otg::Error::Invalid)?
            .get(port)
            .ok_or(otg::Error::Invalid)?;
        // SAFETY: validated board path and retained matching owners; caller fulfils
        // platform interlocks, producer exclusion and memory lifetime obligations.
        unsafe {
            self.otg
                .as_mut()
                .map_err(|e| *e)?
                .disable_tmds(&mut self.sequence.backend.dmub, path)
                .await
        }
    }
    fn display_retirement_busy(&self) -> bool {
        self.fams2_pending
            || self.state() != State::MemoryReady
            || self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
            || self.dccg.as_ref().is_ok_and(|d| {
                !matches!(d.status().state, dccg::State::Ready | dccg::State::Applied)
            })
            || self.clocks.as_ref().is_ok_and(|c| {
                !matches!(
                    c.status().state,
                    clocks::State::Prepared | clocks::State::Ready | clocks::State::Applied
                )
            })
    }
    pub fn display_state(&self) -> Result<display::State, display::Error> {
        self.display
            .as_ref()
            .map(display::Probe::state)
            .map_err(|e| *e)
    }
    pub fn display_paths(&self) -> Result<&[inventory::Path], display::Error> {
        self.display
            .as_ref()
            .map(display::Probe::paths)
            .map_err(|e| *e)
    }
    /// Read routed native DP/eDP/HDMI sinks while retaining the DMUB/DDC and any
    /// incomplete I2C transaction. Cancellation prevents this scanner's reuse.
    pub async fn scan_display(&mut self) -> Result<Vec<display::Port>, Error> {
        if self.state() != State::MemoryReady
            || self
                .otg
                .as_ref()
                .is_ok_and(|o| !o.status().state.reusable())
        {
            return Err(Error::Busy);
        }
        let display = self.display.as_mut().map_err(|e| Error::Display(*e))?;
        if display
            .paths()
            .iter()
            .any(|p| p.connector == inventory::Connector::HdmiTypeA)
        {
            self.ddc.as_ref().map_err(|e| Error::Display(*e))?;
        }
        // retrieve_link_cap: the LTTPR AUX timeout before probing a DP port,
        // the default again where no repeater answered.
        let dp: Vec<inventory::Path> = display
            .paths()
            .iter()
            .filter(|p| p.connector == inventory::Connector::DisplayPort && p.aux.is_some())
            .copied()
            .collect();
        if let Ok(otg) = self.otg.as_mut() {
            for path in &dp {
                // SAFETY: the scan below is this engine's only AUX user.
                let _ = unsafe { otg.set_aux_timeout(*path, otg::Otg::AUX_TIMEOUT_LTTPR_US) };
            }
        }
        let mut ports = display
            .scan(&mut self.sequence.backend.dmub, self.ddc.as_mut().ok())
            .await
            .map_err(Error::Display)?;
        self.scanned_sinks = ports
            .iter()
            .filter_map(|p| {
                let sink = p.sink.as_ref().ok()?;
                Some((p.path, sink.dpcd?, sink.edid.get(..128)?.try_into().ok()?))
            })
            .collect();
        modeset::apply_verified_links(&mut self.verified_links, &mut ports);
        if let Ok(otg) = self.otg.as_mut() {
            for port in &ports {
                let repeater = port.sink.as_ref().is_ok_and(|s| s.lttpr.is_some());
                if dp.contains(&port.path) && !repeater {
                    // SAFETY: as above.
                    let _ =
                        unsafe { otg.set_aux_timeout(port.path, otg::Otg::AUX_TIMEOUT_DEFAULT_US) };
                }
            }
        }
        Ok(ports)
    }
    /// MemoryReady proves firmware, power, an owned VMID0 SDMA write/copy,
    /// the unified MES12 firmware queues and the DMUB capability handshake.
    /// It does not establish userspace queues or a native display mode.
    pub async fn run(&mut self) -> Result<Report, Error> {
        let report = self.sequence.run().await?;
        // Restore before fresh queue/media/display power admission or clients.
        let profile = self.power_profile;
        self.set_profile_tuned(profile, self.custom_profile).await?;
        if let Err(error) = self.power_owner()?.read_profiles().await {
            log_policy(format_args!("workload coefficients unavailable: {error:?}"));
            // Clean firmware refusal is optional. An interrupted mailbox is not.
            if !matches!(error, smu::Error::Rejected(_)) {
                return Err(Error::Smu(error));
            }
        }
        Ok(report)
    }
    /// Access the live display mailbox while retaining this session's PSP/TMR.
    pub fn dmub(&mut self) -> Result<&mut dmub::Dmub, Error> {
        if self.state() != State::MemoryReady
            || self
                .otg
                .as_ref()
                .is_ok_and(|o| !o.status().state.reusable())
            || self
                .display
                .as_ref()
                .is_ok_and(|p| p.state() != display::State::Ready)
            || self
                .ddc
                .as_ref()
                .is_ok_and(|d| d.state() != ddc::State::Ready)
        {
            return Err(Error::Busy);
        }
        Ok(&mut self.sequence.backend.dmub)
    }
}

impl bandwidth::UclkPin for ColdBoot {
    fn clock_status(&self) -> Result<clocks::Status, otg::Error> {
        self.display_clock_status().map_err(otg::Error::Clocks)
    }
    fn firmware_active(&self) -> bool {
        self.fams2_active || self.fams2_pending
    }
    async fn raise_bandwidth(&mut self, bandwidth: clocks::Bandwidth) -> Result<(), otg::Error> {
        self.update_live_display_bandwidth(bandwidth, false)
            .await
            .map(|_| ())
    }
    async fn disable_fams2(&mut self) -> Result<(), otg::Error> {
        self.disable_display_fams2().await
    }
}

#[path = "amdgpu_navi48_bandwidth.rs"]
pub(crate) mod bandwidth;
#[path = "amdgpu_navi48_boot_media_clients.rs"]
mod media_clients;
#[path = "amdgpu_navi48_boot_media_idle.rs"]
mod media_idle;
#[path = "amdgpu_navi48_boot_media.rs"]
mod media_transport;

#[path = "amdgpu_navi48_mst.rs"]
mod mst;
pub use mst::{
    select_mst, DscAux, MstDsc, MstFailure, MstLink, MstOutput, MstOutputId, MstPayload,
    MstPayloadChange, MstService, PayloadAllocation, MST_OUTPUTS,
};
#[path = "amdgpu_navi48_modeset.rs"]
mod modeset;
pub(crate) use modeset::{admit_native_modes, hdmi_depths, hdmi_encodings};
#[path = "amdgpu_navi48_teardown.rs"]
mod teardown;
pub use modeset::{
    beside_pipes, broadcast_rgb, connector_max_bpc, dc_state, display_pipes, edid_timings,
    frl_audio, frl_cap, frl_carries, frl_dsc, frl_dsc_caps, frl_dsc_carries, frl_dsc_link,
    frl_enabled, frl_link, frl_video_params, frl_video_params_in, hdmi_avi, hdmi_candidates,
    hdmi_caps, hdmi_stream, head_pipes, light_pipes, limited_range, live_pipes, max_bpc,
    output_color, plan_pipes, plane_format, plane_mode, plane_requests, plane_setup, requested_bpc,
    requested_color_format, selection_mode, set_broadcast_rgb, set_crtc_color, set_frl,
    set_max_bpc, set_output_color, set_plane_format, set_plane_setup, set_requested_bpc,
    set_requested_color_format, sink_audio_info, stream_planes, with_planes, BesideRefusal,
    Configuration, DisplayPipes, DrmPlaneState, FirstFrames, FrlDscStream, FrlRate, HdmiCaps,
    HdmiStream, Health, InheritedRetired, Modeset, ModesetError, MstRoute, MstStream, OverlayPlane,
    PlaneGeometry, PlanePipes, PlaneSetup, PlanesChange, Selection, SstOutput, StreamPipes,
    BROADCAST_RGB_AUTO, BROADCAST_RGB_FULL, BROADCAST_RGB_LIMITED, MAX_REQUESTED_BPC,
    MIN_REQUESTED_BPC,
};
pub use teardown::{TeardownStatus, TeardownStep};
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_boot_tests.rs"]
mod tests;

#[path = "amdgpu_navi48_boot_power.rs"]
mod power_policy;

#[path = "amdgpu_navi48_fams2.rs"]
mod fams2;

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
    Dmub(dmub::Error),
    Topology(topology::Error),
    Display(display::Error),
    Rs64(rs64::Error),
    Mes(mes::Error),
    Setup(setup::Error),
    Queues(queues::Error),
    Interrupts(ih::Error),
    Faults(faults::Error),
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
            sos.image().map_err(Error::Sos)?.version(),
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
#[derive(Debug)]
struct Hardware {
    gpu: AmdGpu,
    pci: narf_bus::BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    firmware: Firmware,
    dmub: dmub::Dmub,
    trainer: Option<training::Trainer>,
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
}
impl Backend for Hardware {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::MemoryTraining => {
                if let Some(t) = &mut self.trainer {
                    t.run().await.map_err(Error::Training)?;
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
            }
            Stage::TrustedMemory => self
                .psp
                .as_mut()
                .ok_or(Error::Invalid)?
                .setup_tmr_navi48(&self.firmware.sos)
                .await
                .map_err(Error::Psp)?,
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
            }
            Stage::ReadTopology => {
                // SAFETY: firmware/power are ready; no concurrent index user,
                // queues or automatic gating exist under this retained owner.
                let topology = unsafe { topology::read(&self.gpu, &self.authority) }
                    .map_err(Error::Topology)?;
                self.topology = Some(topology);
                crate::amdgpu_info::publish_navi48_topology(topology);
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
    sequence: Sequence<Hardware>,
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
        psp::bank(gpu, ip::HW_ID_MP1, &[(14, 0, 2), (14, 0, 3)], 1, 0x9a).map_err(Error::Psp)?;
        // Record a display inventory error without blocking non-display engine
        // bring-up. This immutable board copy survives the legacy-owner handoff.
        let display = gpu
            .vbios
            .as_ref()
            .ok_or(inventory::Error::Missing)
            .and_then(|bios| inventory::display_paths(gpu, bios.bytes()))
            .map_err(display::Error::Inventory)
            .and_then(display::Probe::new);
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
            vbios: None,
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
            sequence: Sequence {
                backend: Hardware {
                    gpu: saved,
                    pci,
                    authority,
                    pool: pool.clone(),
                    firmware,
                    dmub,
                    trainer,
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
                    mes: None,
                    queues: None,
                },
                state: State::Prepared,
            },
        })
    }
    pub fn state(&self) -> State {
        self.sequence.state
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
    pub(crate) unsafe fn start_interrupt_service(&mut self) -> Result<(), Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        let hardware = &mut self.sequence.backend;
        // SAFETY: same retained objects and exclusive post-boot handoff.
        unsafe {
            crate::amdgpu_navi48_interrupts::install(
                &mut hardware.ih,
                &mut hardware.interrupt_route,
                &mut hardware.faults,
            )
        }
        .map_err(|e| {
            let error = Error::Interrupts(e);
            self.sequence.state = State::Failed(Stage::InterruptRings, error);
            error
        })
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
    pub(crate) fn power_info(&self) -> Option<(Option<smu::Limits>, smu::GfxLevel)> {
        let smu = self.sequence.backend.smu.as_ref()?;
        (self.state() == State::MemoryReady && smu.power_status().is_some())
            .then(|| (smu.limits(), smu.gfx_level()))
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
        })
    }
    /// GFXCLK soft limits only; display/memory clocks stay pinned.
    pub async fn set_gfx_level(&mut self, level: smu::GfxLevel) -> Result<(), Error> {
        self.power_owner()?
            .set_gfx_level(level)
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
        self.clocks.as_mut().map_err(|e| *e)?.prepare(request).await
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
        if clocks.status().state == clocks::State::Prepared {
            // SAFETY: retained matching SMU and drained owned engines. The
            // clock owner checks every display consumer before changing DPM.
            unsafe { clocks.start(smu).await }?;
        }
        match clocks.status().state {
            clocks::State::Ready | clocks::State::Applied => Ok(()),
            _ => Err(clocks::Error::Busy),
        }
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
                .map(|_| ())
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
    /// Admit one single-pipe scanout mode against the live board: started
    /// PMFW levels, the DENTIST VCO, the DCHUB timer and the VBIOS crystal.
    /// Read-only; the plan's clocks and global sync feed the later requests.
    pub fn display_admission(
        &mut self,
        mode: &crate::amdgpu_dcn401_dml::Mode,
    ) -> Result<crate::amdgpu_dcn401_dml::Plan, otg::Error> {
        let soc = self.display_soc()?;
        crate::amdgpu_dcn401_dml::admit(&soc, mode).map_err(otg::Error::Admission)
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
    /// scanout position (display k scans out on pipe k).
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
    /// Show a premultiplied ARGB8888 cursor (at most 64x64) on a live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers.
    pub unsafe fn set_display_cursor(
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
    /// Start black 128b/132b video on the port's trained UHBR link through
    /// HPO stream encoder `stream`, from `pipe`'s prepared timing.
    /// # Safety
    /// Fulfil `Otg::start_uhbr_video` obligations.
    pub async unsafe fn start_display_uhbr_video(
        &mut self,
        port: usize,
        stream: u8,
        pipe: u8,
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
    /// Start audio on the port's running HDMI or DP video.
    /// # Safety
    /// Fulfil `Otg::start_hdmi_audio` or `Otg::start_dp_audio` obligations.
    /// For MST also exclude payload changes; the retained manager allocation
    /// and fresh source SAT/VC witnesses must agree before endpoint exposure.
    pub async unsafe fn start_display_audio(
        &mut self,
        port: usize,
        hdmi: bool,
        info: otg::AudioInfo,
    ) -> Result<otg::DisplayAudio, otg::Error> {
        let path = self.dp_phy_path(port)?;
        let otg = self.otg.as_mut().map_err(|e| *e)?;
        let mst_slots = if !hdmi {
            otg.status()
                .dp_video_running
                .filter(|v| v.frontend.link.phy.settings.mst)
                .map(|v| {
                    let link = self.mst.get(&port).ok_or(otg::Error::Invalid)?;
                    link.audio_slots(v.frontend.request.stream)
                })
                .transpose()?
        } else {
            None
        };
        // SAFETY: matching retained board path/owners; caller's obligations.
        unsafe {
            if hdmi {
                otg.start_hdmi_audio(path, info).await
            } else if let Some(slots) = mst_slots {
                otg.start_mst_audio(path, info, slots).await
            } else {
                otg.start_dp_audio(path, info).await
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
        self.state() != State::MemoryReady
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
        self.sequence.run().await
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

#[path = "amdgpu_navi48_mst.rs"]
mod mst;
pub use mst::{
    select_mst, MstFailure, MstLink, MstOutput, MstOutputId, MstPayload, MstPayloadChange,
};
#[path = "amdgpu_navi48_modeset.rs"]
mod modeset;
#[path = "amdgpu_navi48_teardown.rs"]
mod teardown;
pub use modeset::{
    broadcast_rgb, frl_audio, frl_cap, frl_carries, frl_enabled, frl_link, limited_range, max_bpc,
    set_broadcast_rgb, set_frl, set_max_bpc, Configuration, FrlRate, Health, InheritedRetired,
    Modeset, ModesetError, MstStream, Selection, SstOutput, BROADCAST_RGB_AUTO, BROADCAST_RGB_FULL,
    BROADCAST_RGB_LIMITED,
};
pub use teardown::{TeardownStatus, TeardownStep};
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_boot_tests.rs"]
mod tests;

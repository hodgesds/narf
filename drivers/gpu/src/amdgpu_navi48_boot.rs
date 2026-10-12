//! Ordered, retained Navi48 cold-boot firmware ownership. No automatic probe
//! writes: callers must establish exclusive GPU/VRAM ownership first.
use crate::amdgpu_gfx12_rs64 as rs64;
use crate::amdgpu_mes12_hw as mes;
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
    DmaProof,
    StartMes,
    StartDmub,
}
const STAGES: [Stage; 18] = [
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
    Stage::DmaProof,
    Stage::StartMes,
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
    gmc: Option<gmc::Gmc>,
    sdma: Option<sdma::Sdma>,
    mes: Option<mes::Mes>,
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
            dmub: self.dmub.status().ok_or(Error::Invalid)?,
            topology: self.topology.ok_or(Error::Invalid)?,
            rs64: self.rs64.starts().ok_or(Error::Invalid)?,
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
                    gmc: None,
                    sdma: None,
                    mes: None,
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
    /// Read routed native DisplayPort sinks while retaining the DMUB and any
    /// incomplete I2C transaction. Cancellation prevents this scanner's reuse.
    pub async fn scan_display(&mut self) -> Result<Vec<display::Port>, Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        self.display
            .as_mut()
            .map_err(|e| Error::Display(*e))?
            .scan(&mut self.sequence.backend.dmub)
            .await
            .map_err(Error::Display)
    }
    /// MemoryReady proves firmware, power, an owned VMID0 SDMA write/copy,
    /// the unified MES12 firmware queues and the DMUB capability handshake.
    /// It does not establish userspace queues or a native display mode.
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.sequence.run().await
    }
    /// Access the live display mailbox while retaining this session's PSP/TMR.
    pub fn dmub(&mut self) -> Result<&mut dmub::Dmub, Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        Ok(&mut self.sequence.backend.dmub)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_boot_tests.rs"]
mod tests;

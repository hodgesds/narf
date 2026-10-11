//! Ordered cold-boot firmware bring-up for Navi22. The caller supplies an
//! exclusive pool and trained VRAM or an explicit training inventory. No implicit reset, pool carving, platform
//! initcall, modeset or acceleration publication happens here.
use crate::{
    amdgpu::AmdGpu, amdgpu_gddr6 as gddr6, amdgpu_gfx_navi22 as gfx, amdgpu_psp_boot as sos,
    amdgpu_psp_ring as psp, amdgpu_smu_navi22 as smu, amdgpu_vram::Pool,
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
}
/// All files are validated and copied before the first device operation.
#[derive(Debug)]
pub struct Firmware {
    sos: sos::Firmware,
    smc: smu::Firmware,
    graphics: gfx::Firmware,
}
impl Firmware {
    pub fn open(
        gpu: &AmdGpu,
        registry: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        psp::validate_navi22_layout(gpu).map_err(Error::Psp)?;
        Ok(Self {
            sos: sos::Firmware::open(gpu, registry).map_err(Error::Sos)?,
            smc: smu::Firmware::open(gpu, registry).map_err(Error::Smu)?,
            graphics: gfx::Firmware::open(gpu, registry).map_err(Error::Graphics)?,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    MemoryTraining,
    Sos,
    Ring,
    TrustedMemory,
    Smc,
    SmuVersions,
    Graphics,
    RlcBoot,
}
const STAGES: [Stage; 8] = [
    Stage::MemoryTraining,
    Stage::Sos,
    Stage::Ring,
    Stage::TrustedMemory,
    Stage::Smc,
    Stage::SmuVersions,
    Stage::Graphics,
    Stage::RlcBoot,
];
/// Firmware observations only: queues, memory hubs, SDMA startup, power policy
/// and display are not initialized by this sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    pub gfx: psp::GfxBootStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    FirmwareReady(Report),
    Failed { stage: Stage, error: Error },
    Released,
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
            // Stored outside the future, so dropping the future cannot permit
            // replay or discard the backend's outstanding hardware owners.
            self.state = State::Running(stage);
            if let Err(error) = self.backend.step(stage).await {
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
                    stage: Stage::RlcBoot,
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
    training: Option<gddr6::Trainer>,
    bootstrap: Option<sos::Bootloader>,
    psp: Option<psp::Psp>,
    smu: Option<smu::Smu>,
    versions: Option<smu::Versions>,
    gfx_status: Option<psp::GfxBootStatus>,
}
impl Backend for Hardware {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::MemoryTraining => {
                if let Some(training) = self.training.as_mut() {
                    training.run().await.map_err(Error::Training)?;
                }
            }
            Stage::Sos => {
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
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            gfx: self.gfx_status.ok_or(Error::Invalid)?,
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
        gc_info: None,
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
                    training: None,
                    bootstrap: Some(bootstrap),
                    psp: None,
                    smu: None,
                    versions: None,
                    gfx_status: None,
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
                    training: Some(training),
                    bootstrap: None,
                    psp: None,
                    smu: None,
                    versions: None,
                    gfx_status: None,
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
    pub fn training_data(&self) -> Option<&[u8]> {
        self.sequence
            .backend
            .training
            .as_ref()
            .and_then(gddr6::Trainer::training_data)
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
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_boot_tests.rs"]
pub(crate) mod tests;

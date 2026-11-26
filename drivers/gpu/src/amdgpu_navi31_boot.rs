//! Ordered, retained Navi31 cold-boot firmware ownership. No automatic probe
//! writes: callers must establish exclusive GPU/VRAM ownership first.
//!
//! The skeleton order is the programme's lane order (tracker #2455):
//! MemoryTraining, Psp, Smu, Gmc, then the five parked owners (Ih, Dcn,
//! Cp, Sdma, Submitter, Vcn, Thermal). Stages 1-4 execute here; every
//! later stage fails closed with [`Error::StageUnavailable`] until its
//! owner lane lands — never a silent skip. The PSP/SMU/GMC dependency
//! order is honored (PSP/SMU before GMC, GMC before IH/SDMA), and the
//! run quarantines the boot console on the first failing stage, as the
//! framebuffer handoff requires.
//!
//! What this file deliberately does NOT build: the GFX11 MES/RLC owner,
//! the IH v6 rings, SDMA 6.0, the GFX11 submitter, VCN/JPEG 4.0 and
//! Thermal/DPM (parked lanes 4, 6-10); the GFX11 RS64/Setup equivalents,
//! a Navi31 MSI route and a faults monitor (no shared modules exist for
//! any of them yet — only the GFX12/Navi48 ones). The DMUB firmware is
//! retained as validated bytes; the live DMUB owner waits for the DCN
//! executor lane (the shared `Prepared` borrows its image and VBIOS,
//! so it cannot be retained here).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dmub as dmub, amdgpu_gddr6 as training, amdgpu_gmc_navi31 as gmc,
    amdgpu_navi31_platform::{Skeleton, Stage, STAGES},
    amdgpu_psp13::Psp13FirmwareSet,
    amdgpu_psp_boot as sos, amdgpu_psp_ring as psp,
    amdgpu_rdna3::Rdna3Chip,
    amdgpu_smu as smu,
    amdgpu_vram::Pool,
    amdgpu_vram_boot::Training,
};
use alloc::vec::Vec;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    MemoryReady,
    Failed(Stage, Error),
}

/// What `run` reports once every stage completes: the die, the stage
/// count, the SMU handshake versions and the GMC aperture. All fields
/// are `Copy` so the platform report maps without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub chip: Rdna3Chip,
    pub stages_completed: u8,
    pub next_stage: Option<Stage>,
    pub smu: Option<smu::SmuInfo>,
    pub aperture: Option<gmc::Aperture>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    /// A stage whose owner does not exist yet (IH v6, the DCN executor,
    /// CP/RLC/MES, SDMA 6.0, the GFX11 submitter, VCN/JPEG 4.0,
    /// Thermal/DPM): fail closed, never a silent skip. The stage's lane
    /// owns the owner.
    StageUnavailable(Stage),
    Training(training::Error),
    Sos(sos::Error),
    Psp(psp::Error),
    SmuBringUp(smu::BringUpError),
    Gmc(gmc::Error),
    Dmub(dmub::FirmwareError),
    Registry(narf_firmware::FirmwareError),
}

/// The validated firmware set for one Navi31 cold boot: the PSP 13.0.0
/// SOS container, the PSP-loaded SMU 13.0.0 microcode, and the validated
/// DMCUB blob bytes for this die's DCN 3.2 profile.
#[derive(Debug)]
pub struct Firmware {
    sos: sos::Firmware,
    /// `smu_13_0_0.bin` microcode, PSP-loaded by `load_smc_navi31`
    /// (never MP1-mailbox-loaded: no LoadMicrocode message exists on
    /// 13.0.0; see `amdgpu_psp13`).
    smc: Vec<u8>,
    /// Validated DMCUB blob bytes. The shared `Prepared` borrows its
    /// image and VBIOS, so the bytes are retained here and prepared by
    /// the DCN executor lane, not in this file.
    dmcub: Vec<u8>,
}

struct OpenBlob(&'static str);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenBlob {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(Error::Registry(error))),
        };
        blob.invoke(CopyBlob)
    }
}
struct CopyBlob;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyBlob {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Registry)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}

impl Firmware {
    /// Open and validate every blob before any hardware is touched: the
    /// PSP 13.0.0 SOS container, the SMU 13.0.0 microcode (base set —
    /// the kicker rule is unresolved, see `amdgpu_psp13`), and the
    /// DMCUB image for this die's DCN 3.2 profile (opened and prepared
    /// once here to validate it; the bytes are retained for the DCN
    /// lane's later preparation).
    pub fn open(
        gpu: &AmdGpu,
        registry: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, Error> {
        let sos = sos::Firmware::open(gpu, registry).map_err(Error::Sos)?;
        let smc = registry
            .invoke(OpenBlob(Psp13FirmwareSet::select(false).smu))
            .map_err(|_| Error::Revoked)??;
        let dmub_firmware = dmub::Firmware::open(gpu, registry).map_err(Error::Dmub)?;
        let _ = dmub_firmware.prepare_from_gpu(gpu).map_err(Error::Dmub)?;
        Ok(Self {
            sos,
            smc,
            dmcub: dmub_firmware.bytes().to_vec(),
        })
    }
    /// The retained DMCUB bytes, for the DCN executor lane.
    pub fn dmcub(&self) -> &[u8] {
        &self.dmcub
    }
    /// The SOS container's embedded TOC, for the PSP stage's TMR setup.
    fn sos_toc(&self) -> Result<Option<&[u8]>, Error> {
        Ok(self.sos.image().map_err(Error::Sos)?.toc())
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
            self.state = State::Failed(Stage::Thermal, e);
        })?;
        self.state = State::MemoryReady;
        Ok(report)
    }
}

#[derive(Debug)]
struct Hardware {
    chip: Rdna3Chip,
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    firmware: Firmware,
    trainer: Option<training::Trainer>,
    sos: Option<sos::Bootloader>,
    psp: Option<psp::Psp>,
    smu: Option<smu::SmuInfo>,
    gmc: Option<gmc::Gmc>,
}
impl Backend for Hardware {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        match stage {
            Stage::MemoryTraining => {
                if let Some(t) = &mut self.trainer {
                    // SAFETY: constructor's device/pool ownership persists;
                    // no VRAM client runs before this stage.
                    t.run().await.map_err(Error::Training)?;
                }
            }
            Stage::Psp => {
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
                // SAFETY: successful SOS/training and exclusive device/pool ownership.
                self.psp = Some(
                    unsafe { psp::Psp::new_navi31(&self.gpu, self.authority, &self.pool) }
                        .map_err(Error::Psp)?,
                );
                self.psp
                    .as_mut()
                    .unwrap()
                    .start()
                    .await
                    .map_err(Error::Psp)?;
                // TMR reservation from the SOS container's embedded TOC.
                // SETUP_TMR itself runs inside `load_smc_navi31`
                // (PMFW-centralized C-state order). A container with no
                // embedded TOC fails closed here: no default-TMR entry
                // is grounded for PSP 13.0.0.
                // No PSP14-style FW-reservation pin exists for MP0
                // 13.0.0 (`update_fw_reservation` is 14.0-only); the
                // Plan's PSP runtime-DB reservation stands instead.
                let toc = self
                    .firmware
                    .sos_toc()?
                    .ok_or(Error::Psp(psp::Error::Invalid))?;
                self.psp
                    .as_mut()
                    .unwrap()
                    .setup_tmr_navi31(toc)
                    .await
                    .map_err(Error::Psp)?;
            }
            Stage::Smu => {
                // SAFETY: PSP ring and TMR reservation persist; SMU
                // firmware is PSP-loaded, never MP1-mailbox-loaded.
                self.psp
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .load_smc_navi31(&self.firmware.smc)
                    .await
                    .map_err(Error::Psp)?;
                // `AmdGpu::initialize` cannot serve here: its
                // `load_firmware_multi` dispatches through
                // `psp_dispatch_one`, which fails closed on the shared
                // GPCOM-ring gap. The SMU handshake below is the
                // mailbox path, which needs no GPCOM dispatch.
                let mp1_base = self.gpu.mp1_mailbox_base().ok_or(Error::Invalid)?;
                let expected = self
                    .gpu
                    .expected_smu_driver_if_version()
                    .ok_or(Error::Invalid)?;
                let mut adapter = crate::amdgpu::SmuRegsOwned::new(self.gpu.regs);
                self.smu = Some(
                    smu::bring_up(&mut adapter, mp1_base, expected).map_err(Error::SmuBringUp)?,
                );
            }
            Stage::Gmc => {
                // SAFETY: the owned pool, trained VRAM and accepted firmware
                // persist; automatic gating and all queues are off.
                // `Gmc::initialize` documents "completed PSP/RLC startup":
                // PSP is done above; RLC boot belongs to the parked Cp
                // lane. The stage still runs because `initialize_inner`'s
                // actual register footprint is the two hubs, the NBIO
                // remap and the TLB flush — no RLC register is touched —
                // and the Cp lane re-verifies the pairing when it lands.
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
            // The five parked owners (lanes 4, 6-10) and the DCN executor
            // (lane 5) have no owner to drive yet: fail closed with the
            // stage named, never a silent skip.
            Stage::Ih
            | Stage::Dcn
            | Stage::Cp
            | Stage::Sdma
            | Stage::Submitter
            | Stage::Vcn
            | Stage::Thermal => return Err(Error::StageUnavailable(stage)),
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(Report {
            chip: self.chip,
            stages_completed: STAGES.len() as u8,
            next_stage: None,
            smu: self.smu,
            aperture: self.gmc.as_ref().and_then(gmc::Gmc::aperture),
        })
    }
}

/// The retained Navi31 cold boot: the identity skeleton plus the ordered
/// stage sequence and its hardware backend. `run` drives the sequence
/// once; the owner is retained after success, failure or cancellation,
/// and independent reset is required before reusing quarantined resources.
#[derive(Debug)]
pub struct ColdBoot {
    skeleton: Skeleton,
    sequence: alloc::boxed::Box<Sequence<Hardware>>,
}
impl ColdBoot {
    /// # Safety
    /// Caller owns a physical Navi31 GPU, permanent mappings and a pool made
    /// from its complete boot inventory, excluding every firmware/scanout/client
    /// allocation. Exclude concurrent PSP/SMU/DMUB/index/reset/power access.
    /// This is one cold boot, never attach/resume/reload. VRAM must be trained
    /// when `exchange` is None; otherwise satisfy
    /// `Trainer::new_navi31`'s full quiescence/preimage contract, including
    /// stopping CPU framebuffer writers. Retain this owner after run,
    /// failure or cancellation; independent reset is required before reusing
    /// quarantined resources. No queues may run. `pci` must identify this
    /// GPU's exclusively owned physical PCI function.
    pub unsafe fn new(
        gpu: &AmdGpu,
        pci: narf_bus::BusDevice,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: Firmware,
        exchange: Option<Training>,
        skeleton: Skeleton,
    ) -> Result<Self, Error> {
        if pci.id.vendor != gpu.chip.vid
            || pci.id.device != gpu.chip.did
            || !matches!(pci.kind, narf_bus::BusKind::Pcie { .. })
        {
            return Err(Error::Unsupported);
        }
        // Navi31-first: Navi32/33 keep the platform skeleton (their
        // bring-up is a follow-up lane); only Navi31 executes stages.
        let chip = Rdna3Chip::of(gpu).ok_or(Error::Unsupported)?;
        if chip != Rdna3Chip::Navi31 {
            return Err(Error::Unsupported);
        }
        if !firmware.sos.is_psp13() {
            return Err(Error::Unsupported);
        }
        // PSP layout preflight (MP0/NBIO/GC/HDP banks) before any device
        // access; the trainer re-resolves it when training runs.
        let layout = psp::navi31_layout(gpu).map_err(Error::Psp)?;
        layout
            .validate_pool(gpu, &authority, pool)
            .map_err(Error::Psp)?;
        // SMU bring-up preflight: the MP1 mailbox and the expected
        // driver-IF version must resolve now, not mid-sequence.
        if gpu.mp1_mailbox_base().is_none() || gpu.expected_smu_driver_if_version().is_none() {
            return Err(Error::Unsupported);
        }
        // The controller slot cannot be re-acquired after `claim_navi31`
        // sets DISCRETE_OWNED, so the backend keeps its own copy of the
        // probed handles (Navi48's pattern): register mappings, chip and
        // VRAM identity, discovery blocks and the VBIOS. Mode, backlight
        // and firmware-loaded state start unset, as at probe time.
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
            backlight_percent: None,
            fw_loaded: false,
        };
        let trainer = if let Some(exchange) = exchange {
            // SAFETY: caller reserves exchange and excludes all conflicting clients.
            Some(
                unsafe { training::Trainer::new_navi31(&saved, authority, exchange) }
                    .map_err(Error::Training)?,
            )
        } else {
            None
        };
        Ok(Self {
            skeleton,
            sequence: alloc::boxed::Box::new(Sequence {
                backend: Hardware {
                    chip,
                    gpu: saved,
                    authority,
                    pool: pool.clone(),
                    firmware,
                    trainer,
                    sos: None,
                    psp: None,
                    smu: None,
                    gmc: None,
                },
                state: State::Prepared,
            }),
        })
    }
    /// Drive the retained sequence once, to completion or to the first
    /// failing stage. A second call fails closed (`Busy`).
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.sequence.run().await
    }
    /// The retained identity skeleton (die, IP versions, framebuffer
    /// ownership), for the platform status report.
    pub fn skeleton(&self) -> Skeleton {
        self.skeleton
    }
    /// (stages completed, next stage) for the platform status report.
    pub fn progress(&self) -> (u8, Option<Stage>) {
        match self.sequence.state {
            State::Prepared => (0, STAGES.first().copied()),
            State::Running(stage) | State::Failed(stage, _) => (
                STAGES.iter().position(|s| s == &stage).unwrap_or(0) as u8,
                Some(stage),
            ),
            State::MemoryReady => (STAGES.len() as u8, None),
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi31_boot_tests.rs"]
mod tests;

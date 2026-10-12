//! Ordered, retained Navi48 cold-boot firmware ownership. No automatic probe
//! writes: callers must establish exclusive GPU/VRAM ownership first.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_gddr6 as training,
    amdgpu_navi48_firmware as gfx, amdgpu_psp_boot as sos, amdgpu_psp_ring as psp,
    amdgpu_smu_navi48 as smu, amdgpu_vram::Pool, amdgpu_vram_boot::Training,
};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
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
    PowerSetup,
}
const STAGES: [Stage; 12] = [
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
    Stage::PowerSetup,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    DmubTimeout,
    DmubReadback,
    Training(training::Error),
    Sos(sos::Error),
    Psp(psp::Error),
    Smu(smu::Error),
    Firmware(gfx::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    FirmwareReady,
    Failed(Stage, Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub smu: smu::Versions,
    pub graphics: psp::GfxBootStatus,
    pub power: smu::PowerStatus,
    pub media: psp::MediaFirmware,
}
#[derive(Debug)]
pub struct Firmware {
    sos: sos::Firmware,
    gfx: gfx::Firmware,
}
impl Firmware {
    pub fn open(
        gpu: &AmdGpu,
        registry: &Cap<narf_firmware::FirmwareRegistry, Read>,
        mes: gfx::MesMode,
    ) -> Result<Self, Error> {
        Ok(Self {
            sos: sos::Firmware::open(gpu, registry).map_err(Error::Sos)?,
            gfx: gfx::Firmware::open(gpu, registry, mes).map_err(Error::Firmware)?,
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
            self.state = State::Failed(Stage::PowerSetup, e);
        })?;
        self.state = State::FirmwareReady;
        Ok(report)
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait DisplayIo {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
}
struct DisplayMmio {
    regs: MmioRegion,
    base: u64,
}
impl DisplayIo for DisplayMmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: the constructor bounds DCN4 bank two through 0x200.
        unsafe { self.regs.read32(self.base + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: same bounded bank under live authority and exclusive ownership.
        unsafe { self.regs.write32(self.base + reg as u64 * 4, value) };
    }
}
fn access<T>(
    io: &mut impl DisplayIo,
    cap: &Cap<BusDeviceCap, Write>,
    f: impl FnOnce(&mut dyn DisplayIo) -> Result<T, Error>,
) -> Result<T, Error> {
    cap.invoke(Op(|| f(io))).map_err(|_| Error::Revoked)?
}
fn checked(io: &mut dyn DisplayIo, r: u32) -> Result<u32, Error> {
    match io.read(r) {
        u32::MAX => Err(Error::DeviceGone),
        v => Ok(v),
    }
}
async fn stop_dmub(io: &mut impl DisplayIo, cap: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
    // dmub_dcn401_reset: CNTL2 bit zero, not DCN30's CNTL bit seventeen.
    let (control, reset) = access(io, cap, |io| Ok((checked(io, 0x1f6)?, checked(io, 0x200)?)))?;
    if control & (1 << 16) != 0 && reset & 1 == 0 {
        access(io, cap, |io| {
            io.write(0x1f8, 0x10020000);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            if access(io, cap, |io| {
                Ok(checked(io, 0x1ea)? == 0xdeaddead
                    && checked(io, 0x1f6)? & (1 << 20) != 0
                    && checked(io, 0x1f8)? == 0x00020000)
            })? {
                break;
            }
            if deadline.expired() {
                return Err(Error::DmubTimeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    access(io, cap, |io| {
        let reset = checked(io, 0x200)?;
        io.write(0x200, reset | 1);
        Ok(())
    })?;
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
    access(io, cap, |io| {
        let control = checked(io, 0x1f6)?;
        io.write(0x1f6, control & !(1 << 16));
        if checked(io, 0x200)? & 1 == 0 || checked(io, 0x1f6)? & (1 << 16) != 0 {
            return Err(Error::DmubReadback);
        }
        // No SEC_CNTL/CW0/CW1 writes: authenticated windows belong to PSP.
        for reg in [0x1af, 0x1b0, 0x1b1, 0x1b2, 0x1b3, 0x1b4] {
            let value = checked(io, reg)?;
            io.write(reg, value & !(1 << 31));
        }
        for reg in [0x1d6, 0x1d7, 0x1da, 0x1db, 0x1de, 0x1df, 0x1e3, 0x1f8] {
            io.write(reg, 0);
        }
        Ok(())
    })
}
#[derive(Debug)]
struct Hardware {
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    pool: Pool,
    firmware: Firmware,
    dcn: u64,
    trainer: Option<training::Trainer>,
    sos: Option<sos::Bootloader>,
    psp: Option<psp::Psp>,
    smu: Option<smu::Smu>,
    versions: Option<smu::Versions>,
    graphics: Option<psp::GfxBootStatus>,
    power: Option<smu::PowerStatus>,
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
            Stage::StopDmub => {
                stop_dmub(
                    &mut DisplayMmio {
                        regs: self.gpu.regs,
                        base: self.dcn,
                    },
                    &self.authority,
                )
                .await?
            }
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
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(Report {
            smu: self.versions.ok_or(Error::Invalid)?,
            graphics: self.graphics.ok_or(Error::Invalid)?,
            power: self.power.ok_or(Error::Invalid)?,
            media: self.psp.as_ref().ok_or(Error::Invalid)?.media_firmware(),
        })
    }
}
#[derive(Debug)]
pub struct ColdBoot {
    sequence: Sequence<Hardware>,
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
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: Firmware,
        exchange: Option<Training>,
    ) -> Result<Self, Error> {
        let layout = psp::navi48_layout(gpu).map_err(Error::Psp)?;
        layout
            .validate_pool(gpu, &authority, pool)
            .map_err(Error::Psp)?;
        let target = gfx::Target::resolve(gpu).map_err(Error::Firmware)?;
        let mp0 = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_MP0, 0).ok_or(Error::Unsupported)?;
        if target != firmware.gfx.target() || !firmware.sos.is_psp14(mp0.revision) {
            return Err(Error::Unsupported);
        }
        psp::bank(gpu, ip::HW_ID_MP1, &[(14, 0, 2), (14, 0, 3)], 1, 0x9a).map_err(Error::Psp)?;
        let dcn =
            psp::bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 2, 0x200).map_err(Error::Psp)?;
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
            gc_info: None,
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
        Ok(Self {
            sequence: Sequence {
                backend: Hardware {
                    gpu: saved,
                    authority,
                    pool: pool.clone(),
                    firmware,
                    dcn,
                    trainer,
                    sos: None,
                    psp: None,
                    smu: None,
                    versions: None,
                    graphics: None,
                    power: None,
                },
                state: State::Prepared,
            },
        })
    }
    pub fn state(&self) -> State {
        self.sequence.state
    }
    /// FirmwareReady proves accepted firmware, RLC readiness and SMU power.
    /// It does not prove GMC/SDMA/queue readiness or a native display mode.
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.sequence.run().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_boot_tests.rs"]
mod tests;

//! DCN314 DIO link encoder and DMUB PHY commands for SST DisplayPort.
//! Register fields follow Linux dcn10_link_encoder.c/dcn31_dio_link_encoder.c;
//! firmware payloads follow dmub_cmd.h and atomfirmware.h.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dmub::Channel,
    amdgpu_dmub_boot::Loader,
    amdgpu_dp_training::{self as training, Error, Limits, LinkIo, Settings},
};
use core::future::Future;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub channel: Channel,
    pub aux: u8,
    /// Physical transmitter for native DP, assigned DIG backend for DPIA.
    pub backend: u8,
    pub frontend: u8,
    /// ATOM HPD selector (1..6, zero when not assigned).
    pub hpd: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Disabled,
    Training,
    Trained,
    Failed,
}
/// A sink-side AUX DEFER/timeout is retryable; every other transport or
/// firmware failure aborts, so a poisoned mailbox never looks like a NACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuxError {
    Defer,
    Failed,
}
/// The DMUB-owned PHY and AUX transport. Only a booted loader can implement
/// this: a command sink alone never proves firmware owns the link.
pub trait Phy: Send {
    fn command(&mut self, command: [u8; 64]) -> impl Future<Output = Result<(), Error>> + Send;
    /// `(type_c, disabled, four_lanes)` for a physical transmitter.
    fn typec(&mut self, phy: u8) -> impl Future<Output = Result<(bool, bool, bool), Error>> + Send;
    fn aux(
        &mut self,
        channel: Channel,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), AuxError>> + Send;
}
impl Phy for Loader {
    async fn command(&mut self, command: [u8; 64]) -> Result<(), Error> {
        Loader::command(self, command)
            .await
            .map(|_| ())
            .map_err(|_| Error::Source)
    }
    async fn typec(&mut self, phy: u8) -> Result<(bool, bool, bool), Error> {
        self.typec_phy(phy).await.map_err(|_| Error::Source)
    }
    async fn aux(
        &mut self,
        channel: Channel,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), AuxError> {
        match Loader::aux(self, channel, instance, action, address, data).await {
            Ok(()) => Ok(()),
            Err(crate::amdgpu_dmub_boot::Error::Transport(crate::amdgpu_dmub::Error::Aux(
                2 | 8,
            ))) => Err(AuxError::Defer),
            Err(_) => Err(AuxError::Failed),
        }
    }
}
trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds this DIO bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded, exclusively owned link encoder.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
#[derive(Debug)]
struct Encoder<I: Io> {
    io: I,
    cap: Cap<BusDeviceCap, Write>,
    route: Route,
    state: State,
    settings: Option<Settings>,
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn valid(route: Route) -> bool {
    route.backend < 5
        && route.frontend < 5
        && route.hpd <= 6
        && route.aux < if route.channel == Channel::Dpia { 4 } else { 6 }
}
fn phy_command(route: Route, settings: Settings, action: u8, level: u8) -> [u8; 64] {
    let mut cmd = [0u8; 64];
    let dpia = route.channel == Channel::Dpia;
    cmd[0] = if dpia { 77 } else { 128 };
    cmd[1] = if dpia { 0 } else { 1 };
    cmd[3] = if dpia { 16 } else { 60 };
    cmd[4] = route.backend;
    cmd[5] = action;
    cmd[6] = if action == 11 { level } else { 0 };
    cmd[7] = settings.lanes;
    cmd[8..12].copy_from_slice(&(settings.rate as u32 * 2700).to_le_bytes());
    cmd[12] = route.hpd;
    cmd[13] = 1 << route.frontend;
    cmd[14] = if dpia { route.aux } else { 0x13 };
    cmd
}
impl Encoder<Mmio> {
    /// # Safety
    /// Same contract as `Source::new`, which is the only caller.
    unsafe fn new(
        gpu: &AmdGpu,
        cap: Cap<BusDeviceCap, Write>,
        route: Route,
    ) -> Result<Self, Error> {
        if !valid(route) {
            return Err(Error::Invalid);
        }
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            crate::amdgpu_discovery::HW_ID_DCN,
            &[(3, 1, 4)],
            2,
            0x251e,
        )
        .map_err(|_| Error::Source)?;
        let mut source = Self {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            cap,
            route,
            state: State::Disabled,
            settings: None,
        };
        if source.read(0x20b2)? & 1 != 0 {
            return Err(Error::Source);
        }
        Ok(source)
    }
}
impl<I: Io> Encoder<I> {
    fn state(&self) -> State {
        self.state
    }
    fn route(&self) -> Route {
        self.route
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.cap.invoke(Op(|| f(io))).map_err(|_| Error::Source)
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let reg = reg + self.route.backend as u64 * 0x100;
        self.access(|io| io.read(reg))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = reg + self.route.backend as u64 * 0x100;
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::Source);
            }
            io.write(reg, (old & !mask) | (value & mask));
            if io.read(reg) & mask != value & mask {
                return Err(Error::Source);
            }
            Ok(())
        })?
    }
    fn pattern(&mut self, pattern: u8) -> Result<(), Error> {
        if pattern == 0 {
            self.update(0x210f, u32::MAX, 0)?; // ordinary DP, not embedded panel mode
            let enhanced = self.settings.ok_or(Error::Source)?.enhanced;
            self.update(
                0x2113,
                0x1103ffff,
                0x2000 | if enhanced { 1 << 28 } else { 0 },
            )?;
            self.update(0x211e, 0x3ff00, 0x1ff00)?;
            self.update(0x2108, 0x10, 0x10)?;
        } else {
            let index = match pattern {
                1 => 0,
                2 => 1,
                3 => 2,
                7 => 3,
                _ => return Err(Error::Invalid),
            };
            self.update(0x2118, 3, index)?;
            self.update(0x2108, 0x10, 0)?;
        }
        self.update(0x2117, 1 << 16, 0)?;
        self.update(0x211d, 1, 0)
    }
    async fn train(
        &mut self,
        phy: &mut impl Phy,
        caps: [u8; 16],
        mut limits: Limits,
    ) -> Result<Settings, Error> {
        if self.state != State::Disabled {
            return Err(Error::Source);
        }
        limits.dpia = self.route.channel == Channel::Dpia;
        if !limits.dpia {
            let (typec, disabled, four) = phy.typec(self.route.backend).await?;
            if typec {
                if disabled {
                    return Err(Error::Source);
                }
                limits.lanes = limits.lanes.min(if four { 4 } else { 2 });
            }
        }
        self.state = State::Training;
        let result = training::train(&mut Adapter { source: self, phy }, caps, limits).await;
        self.state = if result.is_ok() {
            State::Trained
        } else {
            State::Failed
        };
        result
    }
    async fn disable(&mut self, phy: &mut impl Phy) -> Result<(), Error> {
        self.state = State::Failed;
        let settings = self.settings.unwrap_or(Settings {
            rate: 6,
            lanes: 1,
            enhanced: false,
        });
        phy.command(phy_command(self.route, settings, 0, 0)).await?;
        if self.read(0x20b2)? & 1 != 0 {
            return Err(Error::Source);
        }
        self.update(0x20b1, 0x7f00, 0)?;
        self.settings = None;
        self.state = State::Disabled;
        Ok(())
    }
}
/// The one owned DCN314 link encoder. Construction proves nothing about the
/// sink: only a completed `train` establishes a link.
#[derive(Debug)]
pub struct Source(Encoder<Mmio>);
impl Source {
    /// # Safety
    /// Caller owns this idle frontend/backend and its physical route exclusively
    /// across hotplug, power transitions and modesets. `route` must be derived
    /// from this GPU's VBIOS or the DPIA allocator, never a UCSI port number.
    /// The matching PCI authority and permanent MMIO mapping must outlive Self.
    pub unsafe fn new(
        gpu: &AmdGpu,
        cap: Cap<BusDeviceCap, Write>,
        route: Route,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded unchanged from this constructor's contract.
        unsafe { Encoder::new(gpu, cap, route) }.map(Self)
    }
    pub fn state(&self) -> State {
        self.0.state()
    }
    pub fn route(&self) -> Route {
        self.0.route()
    }
    pub async fn train(
        &mut self,
        phy: &mut impl Phy,
        caps: [u8; 16],
        limits: Limits,
    ) -> Result<Settings, Error> {
        self.0.train(phy, caps, limits).await
    }
    /// Disable the PHY and detach its stream frontend. A caller must also stop
    /// the timing generator/HUBP before releasing scanout memory.
    pub async fn disable(&mut self, phy: &mut impl Phy) -> Result<(), Error> {
        self.0.disable(phy).await
    }
}

struct Adapter<'a, I: Io, P: Phy> {
    source: &'a mut Encoder<I>,
    phy: &'a mut P,
}
impl<I: Io, P: Phy> Adapter<'_, I, P> {
    async fn aux(&mut self, address: u32, data: &mut [u8], action: u8) -> Result<(), Error> {
        for _ in 0..7 {
            match self
                .phy
                .aux(
                    self.source.route.channel,
                    self.source.route.aux,
                    action,
                    address,
                    data,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(AuxError::Defer) => self.delay_us(1000).await,
                Err(AuxError::Failed) => return Err(Error::Aux),
            }
        }
        Err(Error::Aux)
    }
}
impl<I: Io, P: Phy> LinkIo for Adapter<'_, I, P> {
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        self.aux(address, data, 0x90).await
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        if data.len() > 16 {
            return Err(Error::Invalid);
        }
        let mut copy = [0; 16];
        copy[..data.len()].copy_from_slice(data);
        self.aux(address, &mut copy[..data.len()], 0x80).await
    }
    async fn configure(&mut self, settings: Settings) -> Result<(), Error> {
        let source = &mut *self.source;
        source.settings = Some(settings);
        source.update(0x20b1, 0x77f00, (1u32 << source.route.frontend) << 8)?;
        source.update(0x210b, 3, settings.lanes as u32 - 1)?;
        source.update(0x211e, 0x10, 0x10)?;
        // FEC is not negotiated for this uncompressed 8b/10b SST path.
        source.update(0x2117, 0x30, 0)?;
        self.phy
            .command(phy_command(source.route, settings, 1, 0))
            .await?;
        if source.read(0x20b2)? & 1 == 0 {
            return Err(Error::Source);
        }
        Ok(())
    }
    async fn pattern(&mut self, pattern: u8) -> Result<(), Error> {
        self.source.pattern(pattern)
    }
    async fn tune(&mut self, lanes: &[u8]) -> Result<(), Error> {
        let level = *lanes.first().ok_or(Error::Invalid)?;
        if lanes.iter().any(|n| *n != level) {
            return Err(Error::Invalid);
        }
        let command = phy_command(
            self.source.route,
            self.source.settings.ok_or(Error::Source)?,
            11,
            level,
        );
        self.phy.command(command).await
    }
    async fn disable(&mut self) -> Result<(), Error> {
        self.source.disable(self.phy).await
    }
    async fn delay_us(&mut self, microseconds: u32) {
        narf_time::SleepUntil::new(
            narf_time::Deadline::after_ms((microseconds as u64).div_ceil(1000)).as_instant(),
        )
        .await;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dio_tests.rs"]
mod tests;

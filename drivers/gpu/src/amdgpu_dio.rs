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

/// The DCN versions the register ids in this module describe. The DIG and DP
/// link blocks move wholesale on DCN 3.5 (`dcn_3_5_0_offset.h`):
/// `regDIG0_DIG_BE_CNTL` 0x20b1→0x20bc, `regDIG0_DIG_BE_EN_CNTL`
/// 0x20b2→0x20bd, `regDP0_DP_LINK_CNTL` 0x2108→0x211e — the same +0x16 shift
/// `amdgpu_dcn_stream` sees on the stream half. Another generation needs its
/// own ids, selected per version the way `amdgpu_platform::SURFACE_WINDOWS`
/// does it.
const DCN_VERSIONS: &[(u8, u8, u8)] = &[(3, 1, 4)];

// ── The DIG / DP link window ──────────────────────────────────────
//
// Every id is `dcn/dcn_3_1_4_offset.h` at DCN base index 2, and every mask is
// the one `dcn_3_1_4_sh_mask.h` gives for the named field. Instance N is
// `+ N * DIG_STRIDE`, which is why the bank bound is `DP4_DP_DPHY_SCRAM_CNTL`.

/// `regDIG0_DIG_BE_CNTL`.
const DIG_BE_CNTL: u64 = 0x20b1;
/// `regDIG0_DIG_BE_EN_CNTL`.
const DIG_BE_EN_CNTL: u64 = 0x20b2;
/// `regDP0_DP_LINK_CNTL`.
const DP_LINK_CNTL: u64 = 0x2108;
/// `regDP0_DP_CONFIG`.
const DP_CONFIG: u64 = 0x210b;
/// `regDP0_DP_DPHY_INTERNAL_CTRL` — the eDP alternate-scrambler-reset pair,
/// which `setup_panel_mode` writes whole: 0 for `DP_PANEL_MODE_DEFAULT`, 0x1
/// for eDP, 0x11 for the special panel mode.
const DP_DPHY_INTERNAL_CTRL: u64 = 0x210f;
/// `regDP0_DP_LINK_FRAMING_CNTL`.
const DP_LINK_FRAMING_CNTL: u64 = 0x2113;
/// `regDP0_DP_DPHY_CNTL`.
const DP_DPHY_CNTL: u64 = 0x2117;
/// `regDP0_DP_DPHY_TRAINING_PATTERN_SEL`.
const DP_DPHY_TRAINING_PATTERN_SEL: u64 = 0x2118;
/// `regDP0_DP_DPHY_PRBS_CNTL`.
const DP_DPHY_PRBS_CNTL: u64 = 0x211d;
/// `regDP0_DP_DPHY_SCRAM_CNTL`.
const DP_DPHY_SCRAM_CNTL: u64 = 0x211e;
/// Dword distance between DIG instances. `regDIG1_DIG_BE_CNTL` is 0x21b1
/// against DIG0's 0x20b1.
const DIG_STRIDE: u64 = 0x100;
/// `regDP4_DP_DPHY_SCRAM_CNTL` 0x251e — the highest dword this module touches,
/// and so the bank bound: `DP_DPHY_SCRAM_CNTL` + 4 × `DIG_STRIDE`.
const LAST_REG: u32 = (DP_DPHY_SCRAM_CNTL + 4 * DIG_STRIDE) as u32;

/// `DIG_BE_EN_CNTL__DIG_ENABLE`.
const DIG_ENABLE: u32 = 0x0000_0001;
/// `DIG_BE_CNTL__DIG_FE_SOURCE_SELECT` — a ONE-HOT over the front ends, not an
/// index: `DCN10_DIG_FE_SOURCE_SELECT_DIGA` is 0x1, DIGB 0x2, DIGC 0x4.
const DIG_FE_SOURCE_SELECT: u32 = 0x0000_7F00;
const DIG_FE_SOURCE_SELECT_SHIFT: u32 = 8;
/// `DIG_BE_CNTL__DIG_MODE`. `dcn10_link_encoder_setup` writes 0 for DP SST, 1
/// LVDS, 2 TMDS-DVI, 3 TMDS-HDMI, 5 DP MST — so DP SST is this field cleared.
const DIG_MODE: u32 = 0x0007_0000;
/// `DP_LINK_CNTL__DP_LINK_TRAINING_COMPLETE`.
const DP_LINK_TRAINING_COMPLETE: u32 = 0x0000_0010;
/// `DP_CONFIG__DP_UDI_LANES` — lane count minus one.
const DP_UDI_LANES: u32 = 0x0000_0003;
/// `DP_LINK_FRAMING_CNTL__DP_IDLE_BS_INTERVAL` (0x0003FFFF) |
/// `DP_VBID_DISABLE` (0x01000000) | `DP_VID_ENHANCED_FRAME_MODE` (0x10000000).
const DP_LINK_FRAMING_FIELDS: u32 = 0x1103_FFFF;
/// `DP_IDLE_BS_INTERVAL` for ordinary operation, per
/// `set_dp_phy_pattern_passthrough_mode`. (The HBR2 compliance path uses 0xFC.)
const DP_IDLE_BS_INTERVAL_NORMAL: u32 = 0x2000;
/// `DP_LINK_FRAMING_CNTL__DP_VID_ENHANCED_FRAME_MODE`.
///
/// LINUX-GAP: Linux writes this field only in its two test-pattern paths and
/// forces it to 1 there. We drive it from the sink's own
/// `MAX_LANE_COUNT.ENHANCED_FRAME_CAP` (DPCD 0x0002 bit 7), the same flag
/// `amdgpu_dp_training` puts in `LANE_COUNT_SET.ENHANCED_FRAME_EN` (DPCD 0x0101
/// bit 7). The two ends must agree, so deriving both from one capability bit is
/// deliberate rather than a transcription of Linux's constant.
const DP_VID_ENHANCED_FRAME_MODE: u32 = 0x1000_0000;
/// `DP_DPHY_SCRAM_CNTL__DPHY_SCRAMBLER_BS_COUNT`, and the 0x1FF ordinary
/// operation uses (`set_dp_phy_pattern_passthrough_mode`; the HBR2 compliance
/// path uses 0, "swap every BS with SR").
const DPHY_SCRAMBLER_BS_COUNT: u32 = 0x0003_FF00;
const DPHY_SCRAMBLER_BS_COUNT_NORMAL: u32 = 0x1FF << 8;
/// `DP_DPHY_SCRAM_CNTL__DPHY_SCRAMBLER_ADVANCE`.
const DPHY_SCRAMBLER_ADVANCE: u32 = 0x0000_0010;
/// `DP_DPHY_TRAINING_PATTERN_SEL__DPHY_TRAINING_PATTERN_SEL`.
const DPHY_TRAINING_PATTERN_SEL: u32 = 0x0000_0003;
/// `DP_DPHY_CNTL__DPHY_BYPASS`.
const DPHY_BYPASS: u32 = 0x0001_0000;
/// `DP_DPHY_CNTL__DPHY_FEC_EN` | `DPHY_FEC_READY_SHADOW`. An 8b/10b SST link
/// runs without forward error correction.
const DPHY_FEC_FIELDS: u32 = 0x0000_0030;
/// `DP_DPHY_PRBS_CNTL__DPHY_PRBS_EN`.
const DPHY_PRBS_EN: u32 = 0x0000_0001;

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
            DCN_VERSIONS,
            2,
            LAST_REG,
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
        if source.read(DIG_BE_EN_CNTL)? & DIG_ENABLE != 0 {
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
        let reg = reg + self.route.backend as u64 * DIG_STRIDE;
        self.access(|io| io.read(reg))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = reg + self.route.backend as u64 * DIG_STRIDE;
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
            // `setup_panel_mode(DP_PANEL_MODE_DEFAULT)`: the whole register,
            // not a field update, and 0 is ordinary DP rather than eDP.
            self.update(DP_DPHY_INTERNAL_CTRL, u32::MAX, 0)?;
            let enhanced = self.settings.ok_or(Error::Source)?.enhanced;
            // `DP_IDLE_BS_INTERVAL` 0x2000 with `DP_VBID_DISABLE` cleared,
            // per `set_dp_phy_pattern_passthrough_mode`.
            self.update(
                DP_LINK_FRAMING_CNTL,
                DP_LINK_FRAMING_FIELDS,
                DP_IDLE_BS_INTERVAL_NORMAL
                    | if enhanced {
                        DP_VID_ENHANCED_FRAME_MODE
                    } else {
                        0
                    },
            )?;
            self.update(
                DP_DPHY_SCRAM_CNTL,
                DPHY_SCRAMBLER_BS_COUNT,
                DPHY_SCRAMBLER_BS_COUNT_NORMAL,
            )?;
            self.update(
                DP_LINK_CNTL,
                DP_LINK_TRAINING_COMPLETE,
                DP_LINK_TRAINING_COMPLETE,
            )?;
        } else {
            let index = match pattern {
                1 => 0,
                2 => 1,
                3 => 2,
                7 => 3,
                _ => return Err(Error::Invalid),
            };
            self.update(
                DP_DPHY_TRAINING_PATTERN_SEL,
                DPHY_TRAINING_PATTERN_SEL,
                index,
            )?;
            self.update(DP_LINK_CNTL, DP_LINK_TRAINING_COMPLETE, 0)?;
        }
        // `enable_phy_bypass_mode(false)` then `disable_prbs_mode`.
        self.update(DP_DPHY_CNTL, DPHY_BYPASS, 0)?;
        self.update(DP_DPHY_PRBS_CNTL, DPHY_PRBS_EN, 0)
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
        if self.read(DIG_BE_EN_CNTL)? & DIG_ENABLE != 0 {
            return Err(Error::Source);
        }
        self.update(DIG_BE_CNTL, DIG_FE_SOURCE_SELECT, 0)?;
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
        // One-hot front end plus `DIG_MODE` cleared, which is DP SST.
        source.update(
            DIG_BE_CNTL,
            DIG_FE_SOURCE_SELECT | DIG_MODE,
            (1u32 << source.route.frontend) << DIG_FE_SOURCE_SELECT_SHIFT,
        )?;
        source.update(DP_CONFIG, DP_UDI_LANES, settings.lanes as u32 - 1)?;
        source.update(
            DP_DPHY_SCRAM_CNTL,
            DPHY_SCRAMBLER_ADVANCE,
            DPHY_SCRAMBLER_ADVANCE,
        )?;
        // FEC is not negotiated for this uncompressed 8b/10b SST path.
        source.update(DP_DPHY_CNTL, DPHY_FEC_FIELDS, 0)?;
        self.phy
            .command(phy_command(source.route, settings, 1, 0))
            .await?;
        if source.read(DIG_BE_EN_CNTL)? & DIG_ENABLE == 0 {
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

//! GuC main-GT frequency limits and acknowledged SLPC controls.
//!
//! Source: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe_guc_pc.c, regs/xe_regs.h, abi/guc_actions_slpc_abi.h,
//! xe_wa_oob.rules, xe_device_wa_oob.rules and intel/pciids.h.
//! Media GTs and dynamic MERT/L2-flush cap removal are not owned here.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_gt::{GraphicsIp, GtPlatform},
    intel_gpu_guc::{GuCError, GuCMessage},
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_rcs::GpuBacking,
};
use alloc::{vec, vec::Vec};
use core::sync::atomic::{fence, Ordering};

pub(crate) const RESET_FENCE: u16 = 0xfffe;
const FIRST_FENCE: u16 = 0x8000;
const TIMEOUT: u64 = 1_005_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlpcState {
    Off,
    Resetting { deadline: u64 },
    Running,
    Updating,
    Unavailable,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlpcError {
    State,
    Busy,
    Unavailable,
    FrequencyRange,
    Timeout,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerProfile {
    Base = 0,
    PowerSaving = 1,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrequencyRange {
    pub min_mhz: u32,
    pub max_mhz: u32,
}

/// Fused limits plus source-qualified conservative workaround constraints.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub rpn_mhz: u32,
    pub rpe_mhz: u32,
    pub rp0_mhz: u32,
    pub min_mhz: u32,
    pub max_mhz: u32,
}

fn decode(raw: u32) -> u32 {
    (raw * 50 + 1) / 3
}
fn rounded(mhz: u32) -> u32 {
    decode((mhz * 3 + 25) / 50)
}
fn stable(mmio: &impl MmioWindow, register: u64) -> Result<u32, SlpcError> {
    let a = mmio.read32(register);
    if a == u32::MAX || a != mmio.read32(register) {
        return Err(SlpcError::Unavailable);
    }
    Ok(a)
}

impl Limits {
    /// Main graphics GT only, with current GT forcewake and physical-function
    /// authority. Never uses unavailable fuse reads as usable clock values.
    pub(crate) fn read(
        mmio: &impl MmioWindow,
        platform: GtPlatform,
        device: u16,
    ) -> Result<Self, SlpcError> {
        let ip = GraphicsIp::read(mmio, platform).map_err(|_| SlpcError::Unavailable)?;
        let (rpn_mhz, rpe_mhz, rp0_mhz) = if platform == GtPlatform::Alchemist {
            let cap = stable(mmio, 0x145998)?;
            let efficient = stable(mmio, 0x145ef0)?;
            (
                ((cap >> 16) & 255) * 50,
                ((efficient >> 8) & 255) * 50,
                (cap & 255) * 50,
            )
        } else {
            let cap = stable(mmio, 0x138000)?;
            let efficient = stable(mmio, 0x13800c)?;
            (
                decode((cap >> 16) & 511),
                decode(efficient & 511),
                decode(cap & 511),
            )
        };
        // xe_device_wa_oob.rules: Wa_14022085890, exactly BMG G21.
        let g21 = platform == GtPlatform::Battlemage
            && matches!(
                device,
                0xe202 | 0xe209 | 0xe20b | 0xe20c | 0xe20d | 0xe210 | 0xe211 | 0xe212 | 0xe216
            );
        let min_mhz = if g21 { rpn_mhz.max(1200) } else { rpn_mhz };
        // xe_wa_oob.rules: Wa_22019338487 on graphics 20.01, all steps.
        // Retain the boot MERT cap for this owner's entire lifetime: raising it
        // needs the source's separate flush/actual-frequency protocol.
        let max_mhz = if ip.version == 2001 {
            rp0_mhz.min(2133)
        } else {
            rp0_mhz
        };
        if rpn_mhz == 0 || rpn_mhz > rpe_mhz || rpe_mhz > rp0_mhz || min_mhz > max_mhz {
            return Err(SlpcError::Unavailable);
        }
        Ok(Self {
            rpn_mhz,
            rpe_mhz,
            rp0_mhz,
            min_mhz,
            max_mhz,
        })
    }

    fn validate(self, range: FrequencyRange) -> Result<(), SlpcError> {
        if range.min_mhz < self.min_mhz
            || range.max_mhz > self.max_mhz
            || range.min_mhz > range.max_mhz
            || rounded(range.min_mhz) < self.min_mhz
            || rounded(range.max_mhz) > self.max_mhz
        {
            return Err(SlpcError::FrequencyRange);
        }
        Ok(())
    }
}

/// Confirmed values; absent while an update may be partially applied.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub limits: Limits,
    pub range: FrequencyRange,
    pub profile: PowerProfile,
}

#[derive(Copy, Clone)]
enum Command {
    QueryInitial,
    IgnoreEfficient(bool),
    Min(u32),
    Max(u32),
    Profile(PowerProfile),
    QueryFinal,
    Gucrc,
}

pub(crate) struct Slpc {
    state: SlpcState,
    limits: Option<Limits>,
    range: Option<FrequencyRange>,
    profile: PowerProfile,
    target_range: Option<FrequencyRange>,
    target_profile: PowerProfile,
    commands: Vec<Command>,
    index: usize,
    next_fence: u16,
    pending: Option<u16>,
    acked: bool,
    deadline: u64,
}

impl Slpc {
    pub(crate) fn new() -> Self {
        Self {
            state: SlpcState::Off,
            limits: None,
            range: None,
            profile: PowerProfile::Base,
            target_range: None,
            target_profile: PowerProfile::Base,
            commands: Vec::new(),
            index: 0,
            next_fence: FIRST_FENCE,
            pending: None,
            acked: false,
            deadline: 0,
        }
    }
    pub(crate) fn state(&self) -> SlpcState {
        self.state
    }
    pub(crate) fn status(&self) -> Option<Status> {
        (self.state == SlpcState::Running).then(|| Status {
            limits: self.limits.expect("started SLPC"),
            range: self.range.expect("queried SLPC"),
            profile: self.profile,
        })
    }
    pub(crate) fn start(&mut self, limits: Limits, now: u64) -> Result<(), SlpcError> {
        self.deadline = now.checked_add(TIMEOUT).ok_or(SlpcError::Timeout)?;
        self.limits = Some(limits);
        self.state = SlpcState::Resetting {
            deadline: self.deadline,
        };
        Ok(())
    }
    fn begin(&mut self, now: u64) -> Result<(), SlpcError> {
        if matches!(
            self.state,
            SlpcState::Updating | SlpcState::Resetting { .. }
        ) {
            return Err(SlpcError::Busy);
        }
        if self.state != SlpcState::Running {
            return Err(SlpcError::State);
        }
        self.deadline = now.checked_add(TIMEOUT).ok_or(SlpcError::Timeout)?;
        self.commands.clear();
        self.index = 0;
        self.pending = None;
        self.acked = false;
        self.state = SlpcState::Updating;
        Ok(())
    }
    fn range_commands(&mut self, range: FrequencyRange) {
        self.commands.extend([
            Command::IgnoreEfficient(range.min_mhz < self.limits.expect("limits").rpe_mhz),
            Command::Min(range.min_mhz),
            Command::Max(range.max_mhz),
            Command::QueryFinal,
        ]);
        self.target_range = Some(range);
    }
    pub(crate) fn set_range(&mut self, range: FrequencyRange, now: u64) -> Result<(), SlpcError> {
        self.limits.ok_or(SlpcError::State)?.validate(range)?;
        self.begin(now)?;
        self.target_profile = self.profile;
        self.range_commands(range);
        Ok(())
    }
    pub(crate) fn set_profile(&mut self, profile: PowerProfile, now: u64) -> Result<(), SlpcError> {
        self.begin(now)?;
        self.target_range = self.range;
        self.target_profile = profile;
        self.commands.push(Command::Profile(profile));
        Ok(())
    }
    fn unavailable(&mut self) {
        self.state = SlpcState::Unavailable;
        self.range = None;
        self.pending = None;
        self.commands.clear();
    }
    /// Only this owner consumes the reserved high CT fence namespace. Never
    /// recycle a control fence before full reset, even after RETRY or timeout.
    pub(crate) fn event(&mut self, message: &GuCMessage) -> bool {
        if message.fence < FIRST_FENCE
            || message.fence > RESET_FENCE
            || self.state == SlpcState::Off
        {
            return false;
        }
        if self.state == SlpcState::Unavailable {
            return true;
        }
        if message.fence == RESET_FENCE {
            // RESET/GUCRC are fast requests: no success reply is expected.
            self.unavailable();
            return true;
        }
        if self.pending != Some(message.fence) || self.acked || !message.payload.is_empty() {
            self.unavailable();
            return true;
        }
        match message.kind {
            7 if message.auxiliary == 0 => self.acked = true,
            3 => {} // BUSY is progress, not completion and not a new deadline.
            5 => self.pending = None, // RETRY the same command with a fresh fence.
            _ => self.unavailable(),
        }
        true
    }
    fn query<B: GpuBacking>(&self, shared: &B) -> Option<FrequencyRange> {
        let word = shared.read32(132);
        let range = FrequencyRange {
            min_mhz: decode((word >> 8) & 255),
            max_mhz: decode(word & 255),
        };
        (range.min_mhz != 0 && range.max_mhz != 0).then_some(range)
    }
    pub(crate) fn progress<M: MmioWindow, A: BootAllocator>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        allocator: &mut A,
        shared: &A::Backing,
        now: u64,
    ) -> Result<(), TransportError> {
        if matches!(self.state, SlpcState::Off | SlpcState::Unavailable) {
            return Ok(());
        }
        if allocator.sync_for_cpu(shared).is_err() {
            self.unavailable();
            return Ok(());
        }
        fence(Ordering::Acquire);
        let global = shared.read32(4);
        if global >= 5 {
            self.unavailable();
            return Ok(());
        }
        if self.state == SlpcState::Running {
            if global != 3 {
                self.unavailable();
            }
            return Ok(());
        }
        if now >= self.deadline {
            self.unavailable();
            return Ok(());
        }
        if global != 3 {
            return Ok(());
        }
        if self.commands.is_empty() {
            self.commands.push(Command::QueryInitial);
        }
        if self.acked {
            self.acked = false;
            self.pending = None;
            match self.commands[self.index] {
                Command::QueryInitial => {
                    let Some(current) = self.query(shared) else {
                        self.unavailable();
                        return Ok(());
                    };
                    let limits = self.limits.expect("limits");
                    let max_mhz = current.max_mhz.clamp(limits.min_mhz, limits.max_mhz);
                    let range = FrequencyRange {
                        min_mhz: current.min_mhz.clamp(limits.min_mhz, max_mhz),
                        max_mhz,
                    };
                    self.range_commands(range);
                    self.commands
                        .extend([Command::Profile(PowerProfile::Base), Command::Gucrc]);
                }
                Command::QueryFinal => {
                    let Some(observed) = self.query(shared) else {
                        self.unavailable();
                        return Ok(());
                    };
                    let target = self.target_range.expect("range command");
                    if observed.min_mhz != rounded(target.min_mhz)
                        || observed.max_mhz != rounded(target.max_mhz)
                        || self.limits.expect("limits").validate(observed).is_err()
                    {
                        self.unavailable();
                        return Ok(());
                    }
                    self.target_range = Some(observed);
                }
                _ => {}
            }
            self.index += 1;
        }
        if self.index == self.commands.len() {
            self.range = self.target_range;
            self.profile = self.target_profile;
            self.state = SlpcState::Running;
            return Ok(());
        }
        if self.pending.is_some() {
            return Ok(());
        }
        let command = self.commands[self.index];
        if matches!(command, Command::Gucrc) {
            match ct.send(RESET_FENCE, 0x3004, 0, &[1], true) {
                Ok(()) => {
                    self.index += 1;
                    self.range = self.target_range;
                    self.profile = self.target_profile;
                    self.state = SlpcState::Running;
                }
                Err(TransportError::Ct(GuCError::Full)) => {}
                Err(error) => return Err(error),
            }
            return Ok(());
        }
        if self.next_fence == RESET_FENCE {
            self.unavailable();
            return Ok(());
        }
        let payload = match command {
            Command::QueryInitial | Command::QueryFinal => vec![0x502, shared.ggtt_offset(), 0],
            Command::IgnoreEfficient(value) => vec![0x602, 28, u32::from(value)],
            Command::Min(value) => vec![0x602, 6, value],
            Command::Max(value) => vec![0x602, 7, value],
            Command::Profile(value) => vec![0x602, 27, value as u32],
            Command::Gucrc => unreachable!(),
        };
        match ct.send(self.next_fence, 0x3003, 0, &payload, false) {
            Ok(()) => {
                self.pending = Some(self.next_fence);
                self.next_fence += 1;
            }
            Err(TransportError::Ct(GuCError::Full)) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

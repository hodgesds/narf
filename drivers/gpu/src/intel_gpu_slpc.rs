//! GuC frequency limits and acknowledged SLPC controls, per GuC.
//!
//! Source: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe_guc_pc.c, regs/xe_regs.h, abi/guc_actions_slpc_abi.h,
//! xe_wa_oob.rules, xe_device_wa_oob.rules and intel/pciids.h.
//! xe_guc_pc.c runs one PC instance per GT. The main GT keeps its existing
//! start sequence. The MTL/Arrow standalone media GuC (`Slpc::start` with
//! `media`) reads the media fuses (`Limits::read_media`) and follows
//! xe_guc_pc_start's per-GT tail: pc_adjust_freq_bounds, GUCRC firmware
//! control, the compute strategy and the cached power profile. Qualified BMG
//! MERT promotion requires the separate retained host-L2 owner and its
//! startup/stop/flush proofs.

#[path = "intel_gpu_slpc_mert.rs"]
pub(crate) mod mert;

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

pub(crate) fn decode(raw: u32) -> u32 {
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
        let (rpn_mhz, rpe_mhz, rp0_mhz) =
            if platform == GtPlatform::Alchemist || platform.is_gen12() {
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
        // Bootstrap at the MERT cap. Only GuCGt's independently prepared
        // host-L2/flush owner may lift it after verified execution startup.
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

    /// Standalone media GT (MTL/Arrow GT1, media 13.00), with GT1 forcewake
    /// held: xe_guc_pc.c::mtl_init_fused_rp_values reads RP0 [8:0] and RPn
    /// [24:16] of MTL_MEDIAP_STATE_CAP (0x138020) and mtl_get_rpe_freq reads
    /// RPe [8:0] of MTL_MPE_FREQUENCY (0x13802c) for xe_gt_is_media_type.
    /// Both lie above MEDIA_GT_GSI_LENGTH, so xe_mmio_adjusted_addr leaves
    /// them absolute through GT1's window. No conservative bound applies:
    /// Wa_22019338487 is MEDIA_VERSION(2000) (pc_max_freq_cap) and
    /// Wa_14022085890 is BMG G21 only.
    pub(crate) fn read_media(mmio: &impl MmioWindow) -> Result<Self, SlpcError> {
        let cap = stable(mmio, 0x138020)?;
        let efficient = stable(mmio, 0x13802c)?;
        let (rpn_mhz, rpe_mhz, rp0_mhz) = (
            decode((cap >> 16) & 511),
            decode(efficient & 511),
            decode(cap & 511),
        );
        if rpn_mhz == 0 || rpn_mhz > rpe_mhz || rpe_mhz > rp0_mhz {
            return Err(SlpcError::Unavailable);
        }
        Ok(Self {
            rpn_mhz,
            rpe_mhz,
            rp0_mhz,
            min_mhz: rpn_mhz,
            max_mhz: rp0_mhz,
        })
    }

    pub(crate) fn validate(self, range: FrequencyRange) -> Result<(), SlpcError> {
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
    EnableDcc(bool),
    DisableDcc(bool),
    /// SLPC_PARAM_STRATEGIES (media GuC start only).
    Strategy(u32),
}

/// abi/guc_actions_slpc_abi.h SLPC_OPTIMIZED_STRATEGY_COMPUTE.
const STRATEGY_COMPUTE: u32 = 1;

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
    mert_range: Option<FrequencyRange>,
    disable_dcc: bool,
    /// The standalone media GuC's start sequence (xe_guc_pc_start per GT).
    media: bool,
    /// SETUP_PC_GUCRC(GUCRC_FIRMWARE_CONTROL) was sent: firmware may own RC6.
    gucrc: bool,
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
            mert_range: None,
            disable_dcc: false,
            media: false,
            gucrc: false,
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
    /// `media` selects the standalone media GuC's start sequence; the main
    /// GT's sequence is unchanged.
    pub(crate) fn start(
        &mut self,
        limits: Limits,
        now: u64,
        platform: GtPlatform,
        media: bool,
    ) -> Result<(), SlpcError> {
        self.deadline = now.checked_add(TIMEOUT).ok_or(SlpcError::Timeout)?;
        self.limits = Some(limits);
        self.media = media;
        // pc_modify_defaults is XE_PANTHERLAKE only.
        self.disable_dcc = platform.is_ptl() && !media;
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
    /// Only GuCGt's qualified, prepared host-L2 owner may call this. The
    /// limits remain unpublished until the ordinary ACK/query transaction.
    pub(crate) fn lift_mert_cap(&mut self, now: u64) -> Result<(), SlpcError> {
        let range = self.mert_range.ok_or(SlpcError::State)?;
        self.begin(now)?;
        self.limits.as_mut().ok_or(SlpcError::State)?.max_mhz =
            self.limits.ok_or(SlpcError::State)?.rp0_mhz;
        self.target_profile = self.profile;
        self.range_commands(range);
        self.mert_range = None;
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
            // xe_guc_pc_start overwrites pc_action_set_strategy's result with
            // the power profile's: a refused strategy does not fail the start.
            6 if matches!(self.commands.get(self.index), Some(Command::Strategy(_))) => {
                self.acked = true
            }
            3 => {} // BUSY is progress, not completion and not a new deadline.
            5 => self.pending = None, // RETRY the same command with a fresh fence.
            _ => self.unavailable(),
        }
        true
    }
    /// The media GuC's start after its first task-state query, as
    /// xe_guc_pc_start runs for a media GT on MTL/Arrow:
    /// - pc_init_freqs -> pc_adjust_freq_bounds lowers only a firmware
    ///   default above RP0: the max first, then the min through
    ///   pc_set_min_freq (IGNORE_EFFICIENT_FREQUENCY, then the min).
    ///   pc_adjust_requested_freq has no user request on a fresh GuC, and
    ///   pc_init_pcode_freq returns early without has_llc (mtl_desc).
    /// - SETUP_PC_GUCRC(GUCRC_FIRMWARE_CONTROL), SLPC_PARAM_STRATEGIES =
    ///   SLPC_OPTIMIZED_STRATEGY_COMPUTE and the cached Base power profile.
    ///
    /// A programmed bound is acknowledged by a final readback. Bounds left
    /// as firmware set them are confirmed by this query and the fused limits.
    fn media_bounds(&mut self, current: FrequencyRange) -> bool {
        let limits = self.limits.expect("limits");
        let mut range = current;
        if current.max_mhz > limits.rp0_mhz {
            self.commands.push(Command::Max(limits.rp0_mhz));
            range.max_mhz = limits.rp0_mhz;
        }
        if current.min_mhz > limits.rp0_mhz {
            self.commands.extend([
                Command::IgnoreEfficient(limits.rp0_mhz < limits.rpe_mhz),
                Command::Min(limits.rp0_mhz),
            ]);
            range.min_mhz = limits.rp0_mhz;
        }
        if range != current {
            self.commands.push(Command::QueryFinal);
        } else if limits.validate(current).is_err() {
            return false;
        }
        self.target_range = Some(range);
        self.commands.extend([
            Command::Gucrc,
            Command::Strategy(STRATEGY_COMPUTE),
            Command::Profile(PowerProfile::Base),
        ]);
        true
    }

    /// xe_guc_pc.c::xe_guc_pc_gucrc_disable's H2G before a stop:
    /// SETUP_PC_GUCRC(GUCRC_HOST_CONTROL), only after this owner handed RC6
    /// to firmware. As xe_uc_gucrc_disable (XE_WARN_ON) a refused send is
    /// not an error: the GuC reset that follows ends firmware control.
    pub(crate) fn release_gucrc<M: MmioWindow, A: BootAllocator>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
    ) -> bool {
        core::mem::take(&mut self.gucrc) && ct.send(RESET_FENCE, 0x3004, 0, &[0], true).is_ok()
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
        // wait_for_pc_state's poll_timeout_us evaluates the state once more
        // after expiry, and a reply drained through event() before this poll
        // is consumed: a late poll that finds either progresses. The bound is
        // enforced on what is still unsatisfied, and before any new command.
        let expired = now >= self.deadline;
        if global != 3 {
            if expired {
                self.unavailable();
            }
            return Ok(());
        }
        if self.commands.is_empty() {
            if self.disable_dcc {
                self.commands
                    .extend([Command::EnableDcc(false), Command::DisableDcc(true)]);
            }
            self.commands.push(Command::QueryInitial);
        }
        if self.acked {
            self.acked = false;
            self.pending = None;
            match self.commands[self.index] {
                Command::QueryInitial if self.media => {
                    let Some(current) = self.query(shared) else {
                        self.unavailable();
                        return Ok(());
                    };
                    if !self.media_bounds(current) {
                        self.unavailable();
                        return Ok(());
                    }
                }
                Command::QueryInitial => {
                    let Some(current) = self.query(shared) else {
                        self.unavailable();
                        return Ok(());
                    };
                    let limits = self.limits.expect("limits");
                    if limits.max_mhz < limits.rp0_mhz {
                        let max_mhz = current.max_mhz.clamp(limits.min_mhz, limits.rp0_mhz);
                        self.mert_range = Some(FrequencyRange {
                            min_mhz: current.min_mhz.clamp(limits.min_mhz, max_mhz),
                            max_mhz,
                        });
                    }
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
        // A reply still owed, or a command not yet issued, past the bound.
        if expired {
            self.unavailable();
            return Ok(());
        }
        if self.pending.is_some() {
            return Ok(());
        }
        let command = self.commands[self.index];
        if matches!(command, Command::Gucrc) {
            match ct.send(RESET_FENCE, 0x3004, 0, &[1], true) {
                Ok(()) => {
                    self.gucrc = true;
                    self.index += 1;
                    // The main GT ends here; the media start continues with
                    // its strategy and power profile (xe_guc_pc_start).
                    if self.index == self.commands.len() {
                        self.range = self.target_range;
                        self.profile = self.target_profile;
                        self.state = SlpcState::Running;
                    }
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
            Command::EnableDcc(value) => vec![0x602, 4, u32::from(value)],
            Command::DisableDcc(value) => vec![0x602, 5, u32::from(value)],
            Command::Strategy(value) => vec![0x602, 26, value],
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

//! Intel GPU power management: suspend/resume sequencing and
//! honest PCI D-state transitions (Q9, #1015).
//!
//! Before this module the Intel GPU had no power management at
//! all: the DRM card's `power_state()` was a hardcoded `"D0"`
//! (drm_devfs_bridge.rs) and nothing quiesced the device for
//! system suspend. This module owns the whole conversation:
//!
//! - **Quiesce.** Submissions are gated off in
//!   [`crate::intel_gpu_rcs`] and completions drained until the
//!   engine is idle. A drain that does not converge refuses the
//!   suspend with [`PmError::Busy`] and leaves the device fully
//!   live — no power register has been touched at that point.
//! - **Snapshot.** The display configuration (the active
//!   [`Mode`] + scanout), RC6 posture, DMC posture and the
//!   pre-suspend D-state are captured into a [`PmSnapshot`].
//! - **D-state.** The device enters D3hot through the PCI
//!   Power-Management capability (`narf_bus::pci::set_power_state`,
//!   PCI Bus PM Interface Spec rev 1.2 §3.2.4 / §5.4), with the
//!   mandated 10 ms settle after each transition.
//! - **Resume.** D0 is restored and *verified by PMCSR
//!   readback*; forcewake is sanitized; DMC firmware is
//!   reloaded and verified; RC6 is re-enabled if the snapshot
//!   says it was on; the display is re-lit by re-running the
//!   real modeset at a freshly allocated scanout (GGTT PTEs do
//!   not survive D3, so the surface is re-established exactly
//!   the way probe establishes it). The submission gate opens
//!   last.
//! - **Failure naming.** Any step that fails leaves the device
//!   in a *named* state ([`PmPhase::Degraded`] with a
//!   [`DegradedReason`]), never in a silently half-programmed
//!   one. A snapshot whose framing or CRC fails is rejected
//!   whole: nothing from it is applied.
//!
//! ## Composition with the power service
//!
//! Two registrations, both made at probe (see
//! [`register_pm`]), both under the name `"intel-gpu"`:
//!
//! - `narf_power::device_pm` — the S3 device fan-out pair
//!   ([`IntelGpuPmOps`]). Suspend here is the quiesce/D3 path
//!   above; resume is the restore path. Handlers run with
//!   interrupts gated: all waits in this module are bounded
//!   poll counts, never wall-clock sleeps — the one exception
//!   is the PCI-mandated D3 settle, which uses the same
//!   `responsive_spin_until` the bus layer's own D3hot cycle
//!   uses.
//! - `narf_power::suspend_service` — a [`SuspendStateHook`]
//!   ([`IntelGpuSuspendHook`]) for S4. `seal` serializes the
//!   snapshot taken by the device suspend (the seal fan-out
//!   runs after device quiesce by the service's contract);
//!   `unseal` records the verified outcome, and
//!   [`PmCore::reconcile_after_unseal`] acts on it. The hook is
//!   deliberately **not critical**: every byte of GPU state is
//!   reconstructible from driver-owned state, so a missing or
//!   invalid blob means "re-establish", never "abort the
//!   resume" — the alternative (a dark screen because a blob
//!   failed AEAD) is strictly worse, and the design reserves
//!   criticality for state that cannot be rebuilt (key
//!   custodians, §5.2 rule 4).
//!
//! ## Composition with Q8 (#1014) and Q1 (#1013)
//!
//! The core owns one [`Rc6`] and one [`Forcewake`]. RC6 park
//! is attempted only after the submission drain: forcewake
//! holds are scoped to a single submission, so a closed gate
//! plus a drained engine proves zero holds exist and park's
//! own `DomainsHeld` refusal cannot fire spuriously. The PM
//! forcewake instance is separate from the RCS instance on
//! purpose — after the drain there are no concurrent register
//! users for it to disagree with, and resume sanitizes through
//! it before anything else touches GT registers.
//!
//! Lock order (never inverted): `PM_CORE` → `CONTROLLER` /
//! RCS statics / ACTIVE_MODE. Probe registration takes the PM
//! statics without holding `CONTROLLER`.
//!
//! Spec: `drivers/gpu/specification/intel_gpu.md` §13.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bus::pci::PciPowerState;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::device_pm::{DevicePmOps, DeviceSuspendError};
use narf_power::suspend_service::{
    register_suspend_state_hook, BlobOutcome, SealCtx, SealError, SuspendStateHook, UnsealCtx,
};

use crate::intel_gpu::ActiveScanout;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dmc::{
    load_program, parse_dmc_firmware, set_dc_target, verify_loaded, DcTarget, DmcId, DC_STATE_EN,
    DC_STATE_EN_UPTO_MASK, DMC_MAX_FW_SIZE_GEN12,
};
use crate::intel_gpu_forcewake::{Forcewake, FwError};
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_rc6::{Rc6, Rc6Error, GEN6_GT_GFX_RC6};
use crate::intel_gpu_rcs::RCS_BASE;

/// Registration name in both power registries. The device-PM
/// fan-out attributes outcomes to it; the hook registry uses
/// it as the HKDF label. Fixtures pin the literal.
pub const PM_NAME: &str = "intel-gpu";

/// Poll budget for the submission drain at suspend. Poll
/// *count*, not wall-clock (the #879 determinism rule: a
/// deadline means different things under TCG and silicon).
pub const DRAIN_POLL_BUDGET: u32 = 100_000;

// ── Errors and phases ───────────────────────────────────────

/// Why a power-management operation failed. Mapped onto
/// `narf_power`'s `DeviceSuspendError` at the registry
/// boundary; the variants here stay precise for the driver
/// log and the fixtures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmError {
    /// No probed controller, or probe never retained the PCI
    /// authority this module transitions.
    NotProbed,
    /// The operation does not apply in the current phase
    /// (suspend while suspended, resume while live).
    WrongPhase,
    /// The submission drain did not converge within
    /// [`DRAIN_POLL_BUDGET`] polls. The device was left fully
    /// live: gate reopened, no snapshot, no power writes.
    Busy,
    /// A PCI PMCSR read/write failed (no PM capability, cap
    /// revoked, device gone) or the D0 readback disagreed.
    PciFailed,
    /// A forcewake acquire/release underneath the operation
    /// failed (Q1's error, carried whole).
    Forcewake(FwError),
    /// An RC6 operation failed (Q8's error, carried whole).
    Rc6(Rc6Error),
    /// DMC firmware bytes failed to parse, at registration.
    DmcParse,
    /// DMC reload verification failed at resume.
    DmcVerify,
    /// The DC-state handoff was refused at resume.
    DcRefused,
    /// The display re-light (modeset over a fresh scanout)
    /// failed at resume.
    Relight,
    /// A serialized snapshot failed framing, bounds, field
    /// sanity, or CRC validation. Nothing from it is applied.
    SnapshotCorrupt,
    /// The operation completed but the device was left in the
    /// named degraded state carried here.
    Degraded(DegradedReason),
}

impl From<FwError> for PmError {
    fn from(e: FwError) -> Self {
        PmError::Forcewake(e)
    }
}

impl From<Rc6Error> for PmError {
    fn from(e: Rc6Error) -> Self {
        PmError::Rc6(e)
    }
}

/// The device's power phase, as this module tracks it. This
/// — not a constant — is what the DRM card's `power_state()`
/// reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmPhase {
    /// Fully live in D0 with the pre-suspend posture.
    Live,
    /// Quiesced, snapshotted, and in D3hot.
    Suspended,
    /// Live in D0, but the restore was partial or unverified
    /// in the named way. Submissions run (the engine is
    /// usable); the name says what is not whole.
    Degraded(DegradedReason),
}

/// The named ways a resume/reconcile can be less than whole.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DegradedReason {
    /// No trustworthy snapshot existed at resume (missing, or
    /// the hook marked it untrusted): state was re-established
    /// from driver-owned state instead.
    SnapshotInvalid,
    /// Unseal reported the blob missing or invalid after the
    /// device had already been restored from an unverified
    /// source; the display was re-established from
    /// driver-owned state.
    UnverifiedRestore,
    /// A hardware step of the resume failed: PMCSR readback
    /// disagreed, or RC6 re-enable failed.
    HardwareRestore,
    /// The display re-light failed.
    DisplayRelight,
    /// The DMC reload / verify / DC-target restore failed.
    DmcRestore,
}

// ── CRC-32 (IEEE 802.3, as catalogued in the CRC RevEng
//    catalogue: poly 0x04C11DB7 reflected, init/xorout
//    0xFFFFFFFF; check value for "123456789" is 0xCBF43926) ──

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ── Snapshot ────────────────────────────────────────────────

/// The must-survive configuration captured at suspend. This
/// is configuration, not register state: resume re-runs the
/// real programming sequences (modeset, RC6 enable, DMC load)
/// from it, so nothing here needs to be trusted at register
/// granularity — and its serialized form is what the suspend
/// hook seals.
#[derive(Clone, Debug)]
pub struct PmSnapshot {
    /// Sequence number, minted fresh per suspend. Lets the
    /// unseal reconcile tell "the blob for the restore that
    /// already ran" from "a different suspend's blob".
    pub seq: u64,
    /// The mode to re-light. `None` on a headless device.
    pub mode: Option<Mode>,
    /// The scanout live at suspend. Its width/height size the
    /// resumed allocation; its GGTT offset is *not* reused
    /// (PTEs do not survive D3).
    pub scanout: Option<ActiveScanout>,
    /// Whether RC6 was enabled at suspend.
    pub rc6_enabled: bool,
    /// Bitmask over [`DmcId::ALL`] of the DMC programs the
    /// registered firmware carries; 0 when no firmware is
    /// registered.
    pub dmc_programs: u8,
    /// Raw `DC_STATE_EN` up-to field bits at suspend
    /// ([`DC_STATE_EN_UPTO_MASK`]-masked).
    pub dc_target_bits: u8,
    /// The raw RC6 residency counter at suspend, for
    /// continuity reporting across the cycle.
    pub rc6_residency_raw: u32,
    /// The PMCSR PowerState bits the device was in before
    /// suspend (in practice D0).
    pub dstate_before: u8,
}

const SNAP_MAGIC: &[u8; 8] = b"NARFIPM1";
const SNAP_VERSION: u16 = 1;
/// magic(8) + version(2) + total_len(4) + payload_len(4).
const SNAP_HEADER_LEN: usize = 18;
const SNAP_CRC_LEN: usize = 4;

const FLAG_HAS_MODE: u8 = 1 << 0;
const FLAG_HAS_SCANOUT: u8 = 1 << 1;
const FLAG_RC6_ENABLED: u8 = 1 << 2;
const FLAG_DMC_PRESENT: u8 = 1 << 3;

impl PmSnapshot {
    /// Serialize: header ‖ payload ‖ CRC-32 over everything
    /// before it. Layout is specified in spec §13.2; fixtures
    /// pin the byte shape.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.seq.to_le_bytes());
        let mut flags = 0u8;
        if self.mode.is_some() {
            flags |= FLAG_HAS_MODE;
        }
        if self.scanout.is_some() {
            flags |= FLAG_HAS_SCANOUT;
        }
        if self.rc6_enabled {
            flags |= FLAG_RC6_ENABLED;
        }
        if self.dmc_programs != 0 {
            flags |= FLAG_DMC_PRESENT;
        }
        payload.push(flags);
        payload.push(self.dc_target_bits);
        payload.push(self.dstate_before);
        payload.push(self.dmc_programs);
        payload.extend_from_slice(&self.rc6_residency_raw.to_le_bytes());
        if let Some(m) = &self.mode {
            payload.extend_from_slice(&m.pixel_clock_khz.to_le_bytes());
            for v in [
                m.h_active,
                m.h_total,
                m.h_sync_start,
                m.h_sync_end,
                m.v_active,
                m.v_total,
                m.v_sync_start,
                m.v_sync_end,
            ] {
                payload.extend_from_slice(&v.to_le_bytes());
            }
            payload.push((m.h_sync_positive as u8) | ((m.v_sync_positive as u8) << 1));
        }
        if let Some(s) = &self.scanout {
            payload.extend_from_slice(&s.width.to_le_bytes());
            payload.extend_from_slice(&s.height.to_le_bytes());
            payload.extend_from_slice(&s.stride_bytes.to_le_bytes());
            payload.extend_from_slice(&s.gtt_offset.to_le_bytes());
            payload.extend_from_slice(&s.phys_base.to_le_bytes());
        }
        let total = SNAP_HEADER_LEN + payload.len() + SNAP_CRC_LEN;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(SNAP_MAGIC);
        out.extend_from_slice(&SNAP_VERSION.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        let crc = crc32_ieee(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// Parse and validate a serialized snapshot. Every check
    /// is fail-closed: magic, version, exact length agreement,
    /// CRC, per-field sanity, and no trailing payload bytes.
    /// A failure is [`PmError::SnapshotCorrupt`] and no field
    /// of the result may be used — there is no result.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PmError> {
        let corrupt = PmError::SnapshotCorrupt;
        if bytes.len() < SNAP_HEADER_LEN + SNAP_CRC_LEN {
            return Err(corrupt);
        }
        if &bytes[0..8] != SNAP_MAGIC {
            return Err(corrupt);
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        if version != SNAP_VERSION {
            return Err(corrupt);
        }
        let total = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
        if total != bytes.len() || SNAP_HEADER_LEN + payload_len + SNAP_CRC_LEN != total {
            return Err(corrupt);
        }
        let stored_crc = u32::from_le_bytes(bytes[total - SNAP_CRC_LEN..total].try_into().unwrap());
        if crc32_ieee(&bytes[..total - SNAP_CRC_LEN]) != stored_crc {
            return Err(corrupt);
        }
        let payload = &bytes[SNAP_HEADER_LEN..SNAP_HEADER_LEN + payload_len];
        let mut cur = Cursor {
            buf: payload,
            at: 0,
        };
        let seq = cur.u64()?;
        let flags = cur.u8()?;
        let dc_target_bits = cur.u8()?;
        let dstate_before = cur.u8()?;
        let dmc_programs = cur.u8()?;
        let rc6_residency_raw = cur.u32()?;
        if dc_target_bits > 2 || dstate_before > 3 {
            return Err(corrupt);
        }
        let mode = if flags & FLAG_HAS_MODE != 0 {
            let pixel_clock_khz = cur.u32()?;
            let f = [
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
                cur.u16()?,
            ];
            let sync = cur.u8()?;
            let m = Mode {
                pixel_clock_khz,
                h_active: f[0],
                h_total: f[1],
                h_sync_start: f[2],
                h_sync_end: f[3],
                v_active: f[4],
                v_total: f[5],
                v_sync_start: f[6],
                v_sync_end: f[7],
                h_sync_positive: sync & 1 != 0,
                v_sync_positive: sync & 2 != 0,
            };
            if m.h_active == 0
                || m.v_active == 0
                || m.h_total < m.h_active
                || m.v_total < m.v_active
                || m.pixel_clock_khz == 0
            {
                return Err(corrupt);
            }
            Some(m)
        } else {
            None
        };
        let scanout = if flags & FLAG_HAS_SCANOUT != 0 {
            let s = ActiveScanout {
                width: cur.u32()?,
                height: cur.u32()?,
                stride_bytes: cur.u32()?,
                gtt_offset: cur.u32()?,
                phys_base: cur.u64()?,
            };
            if s.width == 0 || s.height == 0 || s.stride_bytes == 0 {
                return Err(corrupt);
            }
            Some(s)
        } else {
            None
        };
        if cur.at != payload.len() {
            return Err(corrupt);
        }
        Ok(Self {
            seq,
            mode,
            scanout,
            rc6_enabled: flags & FLAG_RC6_ENABLED != 0,
            dmc_programs,
            dc_target_bits,
            rc6_residency_raw,
            dstate_before,
        })
    }
}

/// Bounds-checked little-endian cursor over a snapshot
/// payload; every overrun is [`PmError::SnapshotCorrupt`].
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], PmError> {
        let end = self.at.checked_add(n).ok_or(PmError::SnapshotCorrupt)?;
        if end > self.buf.len() {
            return Err(PmError::SnapshotCorrupt);
        }
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, PmError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PmError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, PmError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, PmError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

// ── Hardware seams ──────────────────────────────────────────

/// The PCI power-management conversation, abstracted so the
/// core state machine runs against a fake PMCSR in fixtures.
/// Production is [`BusPciPower`], over `narf_bus::pci`.
pub trait PciPower {
    /// Read the current PMCSR PowerState.
    fn read(&self) -> Result<PciPowerState, PmError>;
    /// Write the PMCSR PowerState (other PMCSR fields
    /// preserved, per `narf_bus::pci::set_power_state`).
    fn write(&self, state: PciPowerState) -> Result<(), PmError>;
    /// The PCI PM §5.4 settle after a D3hot entry or exit
    /// (10 ms). Production spins responsively; fixtures count
    /// the call.
    fn settle(&self);
}

/// The driver-platform services the core needs, abstracted
/// for fixtures. Production is [`ProductionPlatform`].
pub trait PmPlatform {
    /// Close the RCS submission gate (new submissions refuse
    /// with `SubmitError::Suspended`).
    fn close_submission_gate(&self);
    /// Reopen the RCS submission gate.
    fn open_submission_gate(&self);
    /// Poll completions until the production engine is idle;
    /// `false` when `budget` polls pass without convergence.
    fn drain_submissions(&self, budget: u32) -> bool;
    /// The display configuration to snapshot / re-establish
    /// from: the driver's active mode and live scanout.
    fn display_state(&self) -> (Option<Mode>, Option<ActiveScanout>);
    /// Re-light the display at `mode` over a freshly
    /// allocated scanout (GGTT PTEs do not survive D3, so the
    /// surface is re-established, not restored in place).
    fn relight(&self, mode: &Mode) -> Result<(), PmError>;
}

/// What the suspend hook's `unseal` learned from the image,
/// in core terms. Recorded by the hook, acted on by
/// [`PmCore::reconcile_after_unseal`].
#[derive(Clone, Debug)]
enum UnsealOutcome {
    /// The blob verified and parsed: this snapshot is the
    /// trustworthy restore source.
    Verified(PmSnapshot),
    /// No blob for this hook exists in the image.
    Missing,
    /// A blob exists but failed AEAD verification or framing.
    Invalid,
}

// ── The core state machine ──────────────────────────────────

/// Intel GPU power-management state. Owns the phase, the
/// tracked D-state, the snapshot, and the RC6/forcewake
/// instances the power conversations run through.
pub struct PmCore {
    phase: PmPhase,
    dstate: PciPowerState,
    snapshot: Option<PmSnapshot>,
    /// Whether `snapshot` may be trusted as a restore source.
    /// The S3 RAM copy is trusted by construction (it never
    /// left the machine); the hook's unseal can revoke that
    /// for the S4 path when its sealed copy does not verify.
    snapshot_trusted: bool,
    unseal_outcome: Option<UnsealOutcome>,
    /// `seq` of the snapshot the running restore applied.
    last_applied_seq: u64,
    next_seq: u64,
    rc6: Rc6,
    fw: Forcewake,
    dmc_blob: Option<&'static [u8]>,
    dmc_programs: u8,
}

impl core::fmt::Debug for PmCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmCore")
            .field("phase", &self.phase)
            .field("dstate", &self.dstate)
            .field("has_snapshot", &self.snapshot.is_some())
            .field("snapshot_trusted", &self.snapshot_trusted)
            .field("last_applied_seq", &self.last_applied_seq)
            .field("rc6_enabled", &self.rc6.is_enabled())
            .field("dmc_programs", &self.dmc_programs)
            .finish_non_exhaustive()
    }
}

impl Default for PmCore {
    fn default() -> Self {
        Self::new()
    }
}

impl PmCore {
    pub const fn new() -> Self {
        Self {
            phase: PmPhase::Live,
            dstate: PciPowerState::D0,
            snapshot: None,
            snapshot_trusted: true,
            unseal_outcome: None,
            last_applied_seq: 0,
            next_seq: 1,
            rc6: Rc6::new(),
            fw: Forcewake::new(),
            dmc_blob: None,
            dmc_programs: 0,
        }
    }

    /// The tracked phase.
    pub fn phase(&self) -> PmPhase {
        self.phase
    }

    /// The tracked PCI D-state (updated on every transition
    /// this module performs and refreshed from PMCSR at
    /// registration).
    pub fn dstate(&self) -> PciPowerState {
        self.dstate
    }

    /// The DRM `power_state()` string for the tracked state —
    /// the honest replacement for the hardcoded `"D0"`.
    pub fn power_state_str(&self) -> &'static str {
        match self.dstate {
            PciPowerState::D0 => "D0",
            PciPowerState::D1 => "D1",
            PciPowerState::D2 => "D2",
            PciPowerState::D3Hot => "D3hot",
        }
    }

    /// Register DMC firmware bytes for the resume reload.
    /// The blob is parsed eagerly: a malformed blob is
    /// refused here ([`PmError::DmcParse`]) and the previous
    /// registration stands. Returns the program bitmask.
    /// Nothing in production calls this yet — Q8 landed the
    /// loader without a probe-time firmware fetch; this is
    /// the named seam that wiring uses when it lands.
    /// Stepping selection is wildcard: the core owns no
    /// silicon-stepping readout (probe's `ChipInfo` does not
    /// carry one in this tree), and the registrant fetched
    /// the blob for this platform.
    pub fn register_dmc_firmware(&mut self, blob: &'static [u8]) -> Result<u8, PmError> {
        let fw = parse_dmc_firmware(blob, b'*', b'*', DMC_MAX_FW_SIZE_GEN12)
            .map_err(|_| PmError::DmcParse)?;
        let mut mask = 0u8;
        for (i, id) in DmcId::ALL.iter().enumerate() {
            if fw.program(*id).is_some() {
                mask |= 1 << i;
            }
        }
        self.dmc_blob = Some(blob);
        self.dmc_programs = mask;
        Ok(mask)
    }

    /// The full suspend conversation. On any refusal the
    /// device is left exactly as live as it was found; the
    /// steps are ordered so that the first irreversible act
    /// (the D3 write) is also the last.
    pub fn suspend<M: MmioWindow>(
        &mut self,
        regs: &M,
        pci: &dyn PciPower,
        platform: &dyn PmPlatform,
    ) -> Result<(), PmError> {
        if self.phase != PmPhase::Live {
            return Err(PmError::WrongPhase);
        }
        // 1. Gate + drain. Nothing else has happened yet, so
        //    a drain refusal is a clean Busy: reopen and leave.
        platform.close_submission_gate();
        if !platform.drain_submissions(DRAIN_POLL_BUDGET) {
            platform.open_submission_gate();
            return Err(PmError::Busy);
        }
        // 2. Snapshot the configuration. From here to the D3
        //    write, every failure rolls back to Live.
        let (mode, scanout) = platform.display_state();
        self.fw.sanitize(regs);
        let dc_target_bits = (regs.read32(DC_STATE_EN) & DC_STATE_EN_UPTO_MASK) as u8;
        let snapshot = PmSnapshot {
            seq: self.next_seq,
            mode,
            scanout,
            rc6_enabled: self.rc6.is_enabled(),
            dmc_programs: self.dmc_programs,
            dc_target_bits,
            rc6_residency_raw: regs.read32(GEN6_GT_GFX_RC6),
            dstate_before: self.dstate as u8,
        };
        self.snapshot = Some(snapshot);
        self.snapshot_trusted = true;
        // 3. Arm RC6 for the suspend duration. The drain
        //    proved zero forcewake holds exist (holds are
        //    submission-scoped), so park's own refusal cannot
        //    fire; handle it as a rollback anyway.
        if self.rc6.is_enabled() {
            if let Err(e) = self.rc6.park(&mut self.fw, regs) {
                self.snapshot = None;
                platform.open_submission_gate();
                return Err(e.into());
            }
        }
        // 4. D3hot + the mandated settle.
        if let Err(e) = pci.write(PciPowerState::D3Hot) {
            // Roll back: unarm RC6 (best effort — the suspend
            // error is the one that matters), drop the
            // snapshot, reopen the gate.
            let _ = self.rc6.unpark(&mut self.fw, regs);
            self.snapshot = None;
            platform.open_submission_gate();
            return Err(e);
        }
        pci.settle();
        self.dstate = PciPowerState::D3Hot;
        self.phase = PmPhase::Suspended;
        self.next_seq += 1;
        Ok(())
    }

    /// The full resume conversation. Restores from the
    /// snapshot when one is trusted; otherwise re-establishes
    /// from driver-owned state and says so in the phase.
    /// Every subsystem restore is attempted even when an
    /// earlier one degrades — each applied piece is applied
    /// whole; the phase names what is missing.
    pub fn resume<M: MmioWindow>(
        &mut self,
        regs: &M,
        pci: &dyn PciPower,
        platform: &dyn PmPlatform,
    ) -> Result<(), PmError> {
        match self.phase {
            PmPhase::Live => return Err(PmError::WrongPhase),
            PmPhase::Suspended | PmPhase::Degraded(_) => {}
        }
        // 1. D0, settle, and *verify* by readback. A device
        //    that does not report D0 is not trusted with the
        //    rest of the sequence: named degraded, gate stays
        //    closed so a retry remains possible.
        pci.write(PciPowerState::D0)?;
        pci.settle();
        match pci.read() {
            Ok(PciPowerState::D0) => {}
            Ok(other) => {
                self.dstate = other;
                self.phase = PmPhase::Degraded(DegradedReason::HardwareRestore);
                return Err(PmError::PciFailed);
            }
            Err(e) => {
                self.phase = PmPhase::Degraded(DegradedReason::HardwareRestore);
                return Err(e);
            }
        }
        self.dstate = PciPowerState::D0;
        let mut degraded: Option<DegradedReason> = None;
        // 2. Forcewake sanitize before any GT register is
        //    trusted (mirrors the probe-time fw_domain_reset).
        self.fw.sanitize(regs);
        // 3. Pick the restore source.
        let snapshot = if self.snapshot_trusted {
            self.snapshot.take()
        } else {
            self.snapshot = None;
            None
        };
        let reestablish = snapshot.is_none();
        if reestablish {
            degraded = Some(DegradedReason::SnapshotInvalid);
            // The hardware came back at reset state, so the
            // software RC6 flag may claim an enable that no
            // longer exists (suspend parked an enabled RC6,
            // then D3 wiped the registers). Reconcile it with
            // the disable conversation; a failure here only
            // deepens an already-named degradation.
            let _ = self.rc6.sanitize(&mut self.fw, regs);
        }
        // 4. DMC reload + verify + DC target (snapshot path
        //    only: without a snapshot the posture is unknown,
        //    and programming a guessed DC target would be
        //    exactly the half-programming this module refuses).
        if let Some(snap) = &snapshot {
            if snap.dmc_programs != 0 {
                match self.restore_dmc(regs, snap.dc_target_bits) {
                    Ok(()) => {}
                    Err(_) if degraded.is_none() => degraded = Some(DegradedReason::DmcRestore),
                    Err(_) => {}
                }
            }
            // 5. RC6 re-enable, if it was on.
            if snap.rc6_enabled {
                match self.rc6.enable(&mut self.fw, regs, &[RCS_BASE], 0) {
                    Ok(()) => {}
                    Err(_) if degraded.is_none() => {
                        degraded = Some(DegradedReason::HardwareRestore)
                    }
                    Err(_) => {}
                }
            }
        }
        // 6. Display re-light: from the snapshot's mode, or
        //    (re-establish) from the driver's current state.
        let relight_mode = match &snapshot {
            Some(snap) => snap.mode,
            None => platform.display_state().0,
        };
        if let Some(mode) = relight_mode {
            match platform.relight(&mode) {
                Ok(()) => {}
                Err(_) if degraded.is_none() => degraded = Some(DegradedReason::DisplayRelight),
                Err(_) => {}
            }
        }
        // 7. Bookkeeping, gate last.
        if let Some(snap) = &snapshot {
            self.last_applied_seq = snap.seq;
        }
        self.snapshot = None;
        self.snapshot_trusted = true;
        self.unseal_outcome = None;
        platform.open_submission_gate();
        match degraded {
            None => {
                self.phase = PmPhase::Live;
                Ok(())
            }
            Some(reason) => {
                self.phase = PmPhase::Degraded(reason);
                Err(PmError::Degraded(reason))
            }
        }
    }

    /// Reload the registered DMC firmware and restore the DC
    /// target. The blob was parse-validated at registration;
    /// it is re-parsed here because the firmware object
    /// borrows the bytes and this is its natural lifetime.
    fn restore_dmc<M: MmioWindow>(&mut self, regs: &M, dc_target_bits: u8) -> Result<(), PmError> {
        let blob = self.dmc_blob.ok_or(PmError::DmcVerify)?;
        // Stepping selection is wildcard (see the registration
        // seam): the blob was fetched for this platform by its
        // registrant; the reload re-selects the same entries.
        let fw = parse_dmc_firmware(blob, b'*', b'*', DMC_MAX_FW_SIZE_GEN12)
            .map_err(|_| PmError::DmcVerify)?;
        if !fw.has_main() {
            return Err(PmError::DmcVerify);
        }
        load_program(regs, &fw);
        verify_loaded(regs, &fw).map_err(|_| PmError::DmcVerify)?;
        let target = match dc_target_bits {
            1 => DcTarget::Dc5,
            2 => DcTarget::Dc6,
            _ => DcTarget::Off,
        };
        set_dc_target(regs, &fw, target).map_err(|_| PmError::DcRefused)?;
        Ok(())
    }

    /// Act on the unseal outcome the hook recorded. Called by
    /// the resume coordinator after the unseal fan-out; a
    /// no-op when no unseal ran (the S3 path).
    pub fn reconcile_after_unseal<M: MmioWindow>(
        &mut self,
        _regs: &M,
        platform: &dyn PmPlatform,
    ) -> Result<(), PmError> {
        let outcome = match self.unseal_outcome.take() {
            Some(o) => o,
            None => return Ok(()),
        };
        match outcome {
            UnsealOutcome::Verified(snap) => {
                match self.phase {
                    PmPhase::Suspended => {
                        // The device resume has not run yet:
                        // the verified snapshot replaces the RAM
                        // copy as the restore source.
                        self.snapshot = Some(snap);
                        self.snapshot_trusted = true;
                        Ok(())
                    }
                    PmPhase::Live | PmPhase::Degraded(_) => {
                        if snap.seq == self.last_applied_seq {
                            return Ok(());
                        }
                        // The restore that ran used an
                        // unverified source (or a different
                        // suspend's): re-apply the verified
                        // display state.
                        if let Some(mode) = snap.mode {
                            platform.relight(&mode)?;
                        }
                        self.last_applied_seq = snap.seq;
                        if let PmPhase::Degraded(
                            DegradedReason::SnapshotInvalid | DegradedReason::UnverifiedRestore,
                        ) = self.phase
                        {
                            self.phase = PmPhase::Live;
                        }
                        Ok(())
                    }
                }
            }
            UnsealOutcome::Missing | UnsealOutcome::Invalid => match self.phase {
                PmPhase::Suspended => {
                    // The sealed copy does not verify, so the
                    // RAM snapshot loses its trust: resume will
                    // re-establish rather than restore from it.
                    self.snapshot_trusted = false;
                    Ok(())
                }
                PmPhase::Live => {
                    // The running restore was never verified.
                    // Re-establish the display from
                    // driver-owned state and name it.
                    let (mode, _) = platform.display_state();
                    if let Some(mode) = mode {
                        platform.relight(&mode)?;
                    }
                    self.phase = PmPhase::Degraded(DegradedReason::UnverifiedRestore);
                    Ok(())
                }
                PmPhase::Degraded(_) => Ok(()),
            },
        }
    }
}

// ── Production glue ─────────────────────────────────────────

/// The whole PM state. One probed Intel GPU exists (the
/// controller is a singleton), so one core does too.
static PM_CORE: IrqSafeSpinLock<PmCore> = IrqSafeSpinLock::new(PmCore::new());

/// The PCI authority retained at probe for D-state
/// transitions (the `amdgpu.rs` `PCI_AUTHORITY` pattern).
static PCI_AUTHORITY: IrqSafeSpinLock<
    Option<(
        narf_bus::BusDevice,
        narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    )>,
> = IrqSafeSpinLock::new(None);

/// The driver's active display mode, noted at probe (and by
/// any future runtime modeset — Q4/Q11 lanes must call
/// [`note_active_mode`] when they change it, or resume will
/// re-light the stale mode).
static ACTIVE_MODE: IrqSafeSpinLock<Option<Mode>> = IrqSafeSpinLock::new(None);

/// `MmioWindow` over the controller's BAR0 mapping (same
/// adapter shape as the modeset takeover glue).
#[derive(Debug)]
pub struct PmBarWindow(pub narf_bus::bar::MmioRegion);

impl MmioWindow for PmBarWindow {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: BAR0 is mapped for the lifetime of the probed
        // controller; `off` is a GT/display register offset
        // from this module's conversations, and a 32-bit
        // register read has no unwanted side effect.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: same BAR ownership as `read32`; `off` is a
        // programmable GT/display register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.write32(off, val) }
    }
}

/// Production [`PciPower`]: the retained probe authority
/// driving `narf_bus::pci`'s PMCSR helpers.
#[derive(Debug)]
pub struct BusPciPower;

impl PciPower for BusPciPower {
    fn read(&self) -> Result<PciPowerState, PmError> {
        let guard = PCI_AUTHORITY.lock();
        let (device, cap) = guard.as_ref().ok_or(PmError::NotProbed)?;
        narf_bus::pci::power_state(cap, device)
            .map_err(|_| PmError::PciFailed)?
            .ok_or(PmError::PciFailed)
    }

    fn write(&self, state: PciPowerState) -> Result<(), PmError> {
        let guard = PCI_AUTHORITY.lock();
        let (device, cap) = guard.as_ref().ok_or(PmError::NotProbed)?;
        narf_bus::pci::set_power_state(cap, device, state).map_err(|_| PmError::PciFailed)
    }

    fn settle(&self) {
        // PCI PM §5.4: 10 ms before the next config access
        // after a D3hot entry or exit. The bus layer's own
        // D3hot cycle waits exactly this way.
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ms(narf_bus::pci::PM_D3HOT_DELAY_MS),
        );
    }
}

/// Production [`PmPlatform`]: the RCS production glue, the
/// noted active mode, and probe's display establishment path.
#[derive(Debug)]
pub struct ProductionPlatform;

impl PmPlatform for ProductionPlatform {
    fn close_submission_gate(&self) {
        crate::intel_gpu_rcs::set_submission_gate(true);
    }

    fn open_submission_gate(&self) {
        crate::intel_gpu_rcs::set_submission_gate(false);
    }

    fn drain_submissions(&self, budget: u32) -> bool {
        for _ in 0..budget {
            crate::intel_gpu_rcs::poll_default_completions();
            if crate::intel_gpu_rcs::production_idle() {
                return true;
            }
        }
        crate::intel_gpu_rcs::production_idle()
    }

    fn display_state(&self) -> (Option<Mode>, Option<ActiveScanout>) {
        let mode = *ACTIVE_MODE.lock();
        let scanout = crate::intel_gpu::with_controller(|gpu| gpu.current_mode()).flatten();
        (mode, scanout)
    }

    fn relight(&self, mode: &Mode) -> Result<(), PmError> {
        crate::intel_gpu::relight_display(mode)
            .map(|_| ())
            .ok_or(PmError::Relight)
    }
}

fn production_window() -> Option<PmBarWindow> {
    crate::intel_gpu::with_controller(|gpu| PmBarWindow(gpu.gtt_mmadr))
}

/// The device-PM suspend entry (registry-facing).
pub fn production_suspend() -> Result<(), PmError> {
    let window = production_window().ok_or(PmError::NotProbed)?;
    let mut core = PM_CORE.lock();
    core.suspend(&window, &BusPciPower, &ProductionPlatform)
}

/// The device-PM resume entry (registry-facing).
pub fn production_resume() -> Result<(), PmError> {
    let window = production_window().ok_or(PmError::NotProbed)?;
    let mut core = PM_CORE.lock();
    core.resume(&window, &BusPciPower, &ProductionPlatform)
}

/// The S4 coordinator entry: act on the recorded unseal
/// outcome (design §5.2 fan-out order: device resume, then
/// unseal, then this reconcile).
pub fn production_reconcile() -> Result<(), PmError> {
    let window = production_window().ok_or(PmError::NotProbed)?;
    let mut core = PM_CORE.lock();
    core.reconcile_after_unseal(&window, &ProductionPlatform)
}

fn pm_to_device_error(e: PmError) -> DeviceSuspendError {
    match e {
        PmError::Busy => DeviceSuspendError::Busy,
        _ => DeviceSuspendError::DriverError,
    }
}

/// The `device_pm` registry pair. A unit struct: the state
/// lives in [`PM_CORE`], the registry holds the vtable.
#[derive(Debug)]
pub struct IntelGpuPmOps;

impl DevicePmOps for IntelGpuPmOps {
    fn suspend(&self) -> Result<(), DeviceSuspendError> {
        production_suspend().map_err(pm_to_device_error)
    }

    fn resume(&self) -> Result<(), DeviceSuspendError> {
        production_resume().map_err(pm_to_device_error)
    }
}

/// The suspend-service hook. See the module docs for why it
/// is not critical: all GPU state is reconstructible, so a
/// failed blob means re-establish, never abort the resume.
#[derive(Debug)]
pub struct IntelGpuSuspendHook;

impl SuspendStateHook for IntelGpuSuspendHook {
    fn name(&self) -> &str {
        PM_NAME
    }

    fn critical(&self) -> bool {
        false
    }

    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError> {
        let core = PM_CORE.lock();
        let snapshot = core.snapshot.as_ref().ok_or(SealError::Refused(
            "intel-gpu: no PM snapshot to seal (device suspend did not run)",
        ))?;
        ctx.seal_image(&snapshot.to_bytes())?;
        Ok(())
    }

    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError> {
        // Never reject: every outcome — verified, missing,
        // garbled — is information the reconcile acts on. A
        // framing failure after AEAD success is recorded as
        // Invalid, same as an AEAD failure: in both cases the
        // bytes are not a trustworthy snapshot.
        let outcome = match ctx.take_image() {
            BlobOutcome::Restored(bytes) => match PmSnapshot::from_bytes(&bytes) {
                Ok(snap) => UnsealOutcome::Verified(snap),
                Err(_) => UnsealOutcome::Invalid,
            },
            BlobOutcome::Missing => UnsealOutcome::Missing,
            BlobOutcome::Invalid => UnsealOutcome::Invalid,
        };
        PM_CORE.lock().unseal_outcome = Some(outcome);
        Ok(())
    }
}

/// Register the Intel GPU with both power registries and
/// retain the PCI authority. Called once at probe success,
/// Gen12-class parts only (the forcewake/RC6 register map
/// this module drives is Gen12's; Xe-LPG gets its PM with
/// #1016's engine). Both registries replace on name, so a
/// re-probe does not double-register. Registration is not
/// an initcall — the census is untouched.
pub fn register_pm(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    probe_mode: Option<Mode>,
) {
    *PCI_AUTHORITY.lock() = Some((device, cap));
    *ACTIVE_MODE.lock() = probe_mode;
    narf_power::device_pm::register_device_pm_ops(PM_NAME, Arc::new(IntelGpuPmOps));
    register_suspend_state_hook(Arc::new(IntelGpuSuspendHook));
    // Track the hardware's actual D-state from PMCSR, not an
    // assumption about how firmware left it.
    if let Ok(state) = BusPciPower.read() {
        PM_CORE.lock().dstate = state;
    }
}

/// Note the driver's active display mode (probe, and any
/// future runtime modeset). Resume re-lights this mode.
pub fn note_active_mode(mode: Option<Mode>) {
    *ACTIVE_MODE.lock() = mode;
}

/// Register DMC firmware bytes for the resume reload (see
/// [`PmCore::register_dmc_firmware`] for the seam's status).
pub fn register_dmc_firmware(blob: &'static [u8]) -> Result<u8, PmError> {
    PM_CORE.lock().register_dmc_firmware(blob)
}

/// The tracked D-state as the DRM `power_state()` string.
pub fn power_state_str() -> &'static str {
    PM_CORE.lock().power_state_str()
}

/// The tracked phase (diagnostics + fixtures).
pub fn phase() -> PmPhase {
    PM_CORE.lock().phase
}

// ── Test support ────────────────────────────────────────────

/// Summary of the recorded unseal outcome, for fixtures.
#[cfg(any(test, feature = "kernel-test"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UnsealSummary {
    None,
    Verified(u64),
    Missing,
    Invalid,
}

#[cfg(any(test, feature = "kernel-test"))]
impl PmCore {
    /// The recorded unseal outcome as a fixture summary.
    pub fn unseal_summary(&self) -> UnsealSummary {
        match &self.unseal_outcome {
            None => UnsealSummary::None,
            Some(UnsealOutcome::Verified(snap)) => UnsealSummary::Verified(snap.seq),
            Some(UnsealOutcome::Missing) => UnsealSummary::Missing,
            Some(UnsealOutcome::Invalid) => UnsealSummary::Invalid,
        }
    }

    /// Whether a snapshot is currently held.
    pub fn has_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }
}

/// Reset every PM static. Fixtures only — production never
/// unregisters.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_pm_for_test() {
    *PM_CORE.lock() = PmCore::new();
    *PCI_AUTHORITY.lock() = None;
    *ACTIVE_MODE.lock() = None;
}

/// Seed the core with a suspended phase + snapshot, as a
/// completed device suspend would leave it. Fixtures only.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __seed_suspended_for_test(snapshot: PmSnapshot) {
    let mut core = PM_CORE.lock();
    core.snapshot = Some(snapshot);
    core.snapshot_trusted = true;
    core.phase = PmPhase::Suspended;
    core.dstate = PciPowerState::D3Hot;
}

/// Read the core's unseal summary. Fixtures only.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __unseal_summary_for_test() -> UnsealSummary {
    PM_CORE.lock().unseal_summary()
}

// ── Fixtures ────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the PM core + hook. The fakes model the
    //! *hardware side* of each conversation: the fake PMCSR
    //! accepts state writes and can lie on readback; the fake
    //! register file converges forcewake acks the way the
    //! hardware does (masked request bit → ack bit); the fake
    //! platform's engine idles only when its script says so.
    //! The DMC blob is built from the format description in
    //! spec §12, not from the parser's expectations.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_power::suspend_service::{
        decode_hook_region, off_policy_sms, unseal_registered, ImageStore, KeyEntropy, PolicyLevel,
        RecordedPolicy, ServiceError, SuspendService, UnsealOutcome as PowerUnsealOutcome,
        __reset_hooks_for_test,
    };

    use crate::intel_gpu_forcewake::{
        FORCEWAKE_ACK_BLITTER, FORCEWAKE_ACK_MEDIA, FORCEWAKE_ACK_RENDER, FORCEWAKE_BLITTER,
        FORCEWAKE_MEDIA, FORCEWAKE_RENDER,
    };
    use crate::intel_gpu_rc6::{GEN6_RC_CONTROL, GEN9_PG_ENABLE, RC6_CTL_HOST, RC_CTL_RC6_ENABLE};

    // ── Shared ordered event log ────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Ev {
        Reg(u64, u32),
        PciWrite(PciPowerState),
        Settle,
        Gate(bool),
        Relight(u16),
    }

    type Log = Rc<RefCell<Vec<Ev>>>;

    fn new_log() -> Log {
        Rc::new(RefCell::new(Vec::new()))
    }

    // ── Fake register file (models forcewake ack hardware) ──

    #[derive(Clone)]
    struct FakeRegs {
        map: Rc<RefCell<BTreeMap<u64, u32>>>,
        log: Log,
    }

    impl FakeRegs {
        fn new(log: Log) -> Self {
            Self {
                map: Rc::new(RefCell::new(BTreeMap::new())),
                log,
            }
        }
        fn set_reg(&self, off: u64, val: u32) {
            self.map.borrow_mut().insert(off, val);
        }
        fn get_reg(&self, off: u64) -> u32 {
            *self.map.borrow().get(&off).unwrap_or(&0)
        }
    }

    impl MmioWindow for FakeRegs {
        fn read32(&self, off: u64) -> u32 {
            *self.map.borrow().get(&off).unwrap_or(&0)
        }
        fn write32(&self, off: u64, val: u32) {
            self.log.borrow_mut().push(Ev::Reg(off, val));
            self.map.borrow_mut().insert(off, val);
            // Model the forcewake ack: a masked write to a
            // request register moves the KERNEL bit (bit 0)
            // of the matching ack register to the data value,
            // exactly the convergence the hardware performs.
            let ack_off = match off {
                FORCEWAKE_RENDER => Some(FORCEWAKE_ACK_RENDER),
                FORCEWAKE_MEDIA => Some(FORCEWAKE_ACK_MEDIA),
                FORCEWAKE_BLITTER => Some(FORCEWAKE_ACK_BLITTER),
                _ => None,
            };
            if let Some(ack_off) = ack_off {
                if val & (1 << 16) != 0 {
                    let mut map = self.map.borrow_mut();
                    let ack = map.entry(ack_off).or_insert(0);
                    if val & 1 != 0 {
                        *ack |= 1;
                    } else {
                        *ack &= !1;
                    }
                }
            }
        }
    }

    // ── Fake PCI PMCSR ──────────────────────────────────────

    struct FakePci {
        log: Log,
        state: Cell<PciPowerState>,
        fail_write: Cell<bool>,
        read_lie: Cell<Option<PciPowerState>>,
    }

    impl FakePci {
        fn new(log: Log) -> Self {
            Self {
                log,
                state: Cell::new(PciPowerState::D0),
                fail_write: Cell::new(false),
                read_lie: Cell::new(None),
            }
        }
    }

    impl PciPower for FakePci {
        fn read(&self) -> Result<PciPowerState, PmError> {
            Ok(self.read_lie.get().unwrap_or_else(|| self.state.get()))
        }
        fn write(&self, state: PciPowerState) -> Result<(), PmError> {
            self.log.borrow_mut().push(Ev::PciWrite(state));
            if self.fail_write.get() {
                return Err(PmError::PciFailed);
            }
            self.state.set(state);
            Ok(())
        }
        fn settle(&self) {
            self.log.borrow_mut().push(Ev::Settle);
        }
    }

    // ── Fake platform ───────────────────────────────────────

    struct FakePlatform {
        log: Log,
        gate_closed: Cell<bool>,
        idle_after: Cell<u32>,
        polls: Cell<u32>,
        mode: Cell<Option<Mode>>,
        scanout: Option<ActiveScanout>,
        relight_args: RefCell<Vec<Mode>>,
        relight_fail: Cell<bool>,
    }

    impl FakePlatform {
        fn new(log: Log, mode: Option<Mode>, scanout: Option<ActiveScanout>) -> Self {
            Self {
                log,
                gate_closed: Cell::new(false),
                idle_after: Cell::new(0),
                polls: Cell::new(0),
                mode: Cell::new(mode),
                scanout,
                relight_args: RefCell::new(Vec::new()),
                relight_fail: Cell::new(false),
            }
        }
    }

    impl PmPlatform for FakePlatform {
        fn close_submission_gate(&self) {
            self.log.borrow_mut().push(Ev::Gate(true));
            self.gate_closed.set(true);
        }
        fn open_submission_gate(&self) {
            self.log.borrow_mut().push(Ev::Gate(false));
            self.gate_closed.set(false);
        }
        fn drain_submissions(&self, budget: u32) -> bool {
            for _ in 0..budget {
                self.polls.set(self.polls.get() + 1);
                if self.polls.get() > self.idle_after.get() {
                    return true;
                }
            }
            false
        }
        fn display_state(&self) -> (Option<Mode>, Option<ActiveScanout>) {
            (self.mode.get(), self.scanout.clone())
        }
        fn relight(&self, mode: &Mode) -> Result<(), PmError> {
            self.log.borrow_mut().push(Ev::Relight(mode.h_active));
            self.relight_args.borrow_mut().push(*mode);
            if self.relight_fail.get() {
                return Err(PmError::Relight);
            }
            Ok(())
        }
    }

    // ── Shared fixture data ─────────────────────────────────

    /// CEA-861 1080p60 timing (148.5 MHz pixel clock).
    fn mode_1080p() -> Mode {
        Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    /// VESA DMT 1280x720@60 timing (74.25 MHz pixel clock).
    fn mode_720p() -> Mode {
        Mode {
            pixel_clock_khz: 74_250,
            h_active: 1280,
            h_total: 1650,
            h_sync_start: 1430,
            h_sync_end: 1430 + 80,
            v_active: 720,
            v_total: 750,
            v_sync_start: 725,
            v_sync_end: 730,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    fn fixture_scanout() -> ActiveScanout {
        ActiveScanout {
            width: 1920,
            height: 1080,
            stride_bytes: 7680,
            gtt_offset: 0x0040_0000,
            phys_base: 0x1_0000_0000,
        }
    }

    fn fixture_snapshot(seq: u64) -> PmSnapshot {
        PmSnapshot {
            seq,
            mode: Some(mode_1080p()),
            scanout: Some(fixture_scanout()),
            rc6_enabled: true,
            dmc_programs: 1,
            dc_target_bits: 2,
            rc6_residency_raw: 0x00AB_CDEF,
            dstate_before: 0,
        }
    }

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A minimal DMC container built from the format
    /// description (spec §12): CSS header, package v2, one
    /// Main program (v3 header, wildcard stepping) with a
    /// 4-dword payload and a one-entry MMIO table.
    fn fixture_dmc_blob() -> Vec<u8> {
        use crate::intel_gpu_dmc::{
            CSS_HEADER_BYTES, CSS_HEADER_VER, CSS_MODULE_TYPE_DMC, CSS_VERSION_OFFSET,
            DMC_HEADER_V3_BYTES, DMC_SIGNATURE, FW_INFO_BYTES, PACKAGE_HEADER_BYTES,
            PACKAGE_V2_MAX_ENTRIES,
        };
        let package_size = PACKAGE_HEADER_BYTES + PACKAGE_V2_MAX_ENTRIES * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0002_000C);
        let pkg = CSS_HEADER_BYTES;
        blob[pkg] = (package_size / 4) as u8;
        blob[pkg + 1] = 2;
        put32(&mut blob, pkg + 12, 1);
        let e = pkg + PACKAGE_HEADER_BYTES;
        blob[e + 1] = 0; // DmcId::Main
        blob[e + 2] = b'*';
        blob[e + 3] = b'*';
        put32(&mut blob, e + 4, 0);
        let payload = [0xAAAA_0001u32, 0xAAAA_0002, 0xAAAA_0003, 0xAAAA_0004];
        let prog_off = blob.len();
        blob.resize(prog_off + DMC_HEADER_V3_BYTES + payload.len() * 4, 0);
        put32(&mut blob, prog_off, DMC_SIGNATURE);
        blob[prog_off + 4] = (DMC_HEADER_V3_BYTES / 4) as u8;
        blob[prog_off + 5] = 3;
        put32(&mut blob, prog_off + 8, 0x12);
        put32(&mut blob, prog_off + 12, payload.len() as u32);
        put32(&mut blob, prog_off + 16, 0x0002_000C);
        put32(&mut blob, prog_off + 20, 0x80000);
        put32(&mut blob, prog_off + 92, 1);
        put32(&mut blob, prog_off + 96, 0x8F074); // DMC_SSP_BASE
        put32(&mut blob, prog_off + 176, 0x0000_2FC0);
        for (j, v) in payload.iter().enumerate() {
            put32(&mut blob, prog_off + DMC_HEADER_V3_BYTES + 4 * j, *v);
        }
        blob
    }

    fn leak_blob(blob: Vec<u8>) -> &'static [u8] {
        alloc::boxed::Box::leak(blob.into_boxed_slice())
    }

    fn reg_writes(log: &Log) -> Vec<(u64, u32)> {
        log.borrow()
            .iter()
            .filter_map(|e| match e {
                Ev::Reg(off, val) => Some((*off, *val)),
                _ => None,
            })
            .collect()
    }

    // ── (1) Full suspend → resume conversation ──────────────

    fn smoke_pm_suspend_resume_conversation() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        regs.set_reg(DC_STATE_EN, 2);
        regs.set_reg(GEN6_GT_GFX_RC6, 0x00AB_CDEF);
        let pci = FakePci::new(log.clone());
        let platform = FakePlatform::new(log.clone(), Some(mode_1080p()), Some(fixture_scanout()));
        let mut core = PmCore::new();
        match core.register_dmc_firmware(leak_blob(fixture_dmc_blob())) {
            Ok(1) => {}
            Ok(_) => return TestResult::Fail("DMC fixture mask is not Main-only"),
            Err(_) => return TestResult::Fail("DMC fixture blob refused at registration"),
        }
        if core
            .rc6
            .enable(&mut core.fw, &regs, &[RCS_BASE], 0)
            .is_err()
        {
            return TestResult::Fail("RC6 enable failed against the fake register file");
        }
        log.borrow_mut().clear();

        // ── Suspend ──
        if core.suspend(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("suspend refused a quiesceable device");
        }
        if core.phase() != PmPhase::Suspended || core.power_state_str() != "D3hot" {
            return TestResult::Fail("phase/D-state after suspend is not Suspended/D3hot");
        }
        if !platform.gate_closed.get() {
            return TestResult::Fail("submission gate not closed at suspend");
        }
        let events = log.borrow().clone();
        let d3_at = events
            .iter()
            .position(|e| *e == Ev::PciWrite(PciPowerState::D3Hot));
        let park_at = events
            .iter()
            .position(|e| *e == Ev::Reg(GEN6_RC_CONTROL, RC_CTL_RC6_ENABLE));
        match (park_at, d3_at) {
            (Some(p), Some(d)) if p < d => {}
            _ => return TestResult::Fail("RC6 park does not precede the D3 write"),
        }
        if events.last() != Some(&Ev::Settle) {
            return TestResult::Fail("no PM settle after the D3 write");
        }
        let snap = match &core.snapshot {
            Some(s) => s.clone(),
            None => return TestResult::Fail("no snapshot after suspend"),
        };
        if snap.seq != 1
            || !snap.rc6_enabled
            || snap.dc_target_bits != 2
            || snap.dmc_programs != 1
            || snap.rc6_residency_raw != 0x00AB_CDEF
            || snap.mode != Some(mode_1080p())
        {
            return TestResult::Fail("snapshot does not carry the suspended configuration");
        }

        // D3 wipes the DC target register; resume must
        // restore it from the snapshot, not find it.
        regs.set_reg(DC_STATE_EN, 0);
        log.borrow_mut().clear();

        // ── Resume ──
        if core.resume(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("resume failed against the fake hardware");
        }
        if core.phase() != PmPhase::Live || core.power_state_str() != "D0" {
            return TestResult::Fail("phase/D-state after resume is not Live/D0");
        }
        if platform.gate_closed.get() {
            return TestResult::Fail("submission gate still closed after resume");
        }
        let events = log.borrow().clone();
        if events.first() != Some(&Ev::PciWrite(PciPowerState::D0))
            || events.get(1) != Some(&Ev::Settle)
        {
            return TestResult::Fail("resume does not open with D0 + settle");
        }
        if platform.relight_args.borrow().as_slice() != [mode_1080p()] {
            return TestResult::Fail("relight did not run at the snapshot mode");
        }
        if !core.rc6.is_enabled() {
            return TestResult::Fail("RC6 not re-enabled at resume");
        }
        if regs.get_reg(DC_STATE_EN) & DC_STATE_EN_UPTO_MASK != 2 {
            return TestResult::Fail("DC target not restored to DC6 at resume");
        }
        if core.has_snapshot() || core.last_applied_seq != 1 {
            return TestResult::Fail("snapshot bookkeeping wrong after resume");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pm",
        smoke_pm_suspend_resume_conversation
    );

    // ── (2) Drain refusal leaves the device fully live ──────

    fn smoke_pm_drain_refusal_leaves_device_live() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let pci = FakePci::new(log.clone());
        let platform = FakePlatform::new(log.clone(), Some(mode_1080p()), None);
        platform.idle_after.set(u32::MAX);
        let mut core = PmCore::new();
        match core.suspend(&regs, &pci, &platform) {
            Err(PmError::Busy) => {}
            other => {
                let _ = other;
                return TestResult::Fail("never-idle drain did not refuse with Busy");
            }
        }
        if core.phase() != PmPhase::Live || core.has_snapshot() {
            return TestResult::Fail("refused suspend still changed phase/snapshot");
        }
        if platform.gate_closed.get() {
            return TestResult::Fail("refused suspend left the gate closed");
        }
        if !reg_writes(&log).is_empty() || log.borrow().iter().any(|e| matches!(e, Ev::PciWrite(_)))
        {
            return TestResult::Fail("refused suspend touched a power register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pm",
        smoke_pm_drain_refusal_leaves_device_live
    );

    // ── (3) Snapshot codec: round-trip + fail-closed ────────

    fn smoke_pm_snapshot_codec() -> TestResult {
        // CRC catalogue check value for CRC-32/ISO-HDLC.
        if crc32_ieee(b"123456789") != 0xCBF4_3926 {
            return TestResult::Fail("CRC-32 check value mismatch");
        }
        let snap = fixture_snapshot(9);
        let bytes = snap.to_bytes();
        let back = match PmSnapshot::from_bytes(&bytes) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("own snapshot does not parse"),
        };
        if back.seq != 9 || back.to_bytes() != bytes {
            return TestResult::Fail("snapshot round-trip is not byte-exact");
        }
        let empty = PmSnapshot {
            mode: None,
            scanout: None,
            rc6_enabled: false,
            dmc_programs: 0,
            ..fixture_snapshot(3)
        };
        if PmSnapshot::from_bytes(&empty.to_bytes()).is_err() {
            return TestResult::Fail("headless snapshot does not round-trip");
        }
        // Any single-byte damage refuses the whole snapshot.
        for at in [0usize, 20, bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0xFF;
            if PmSnapshot::from_bytes(&damaged).is_ok() {
                return TestResult::Fail("damaged snapshot parsed");
            }
        }
        if PmSnapshot::from_bytes(&bytes[..bytes.len() - 1]).is_ok() {
            return TestResult::Fail("truncated snapshot parsed");
        }
        // Field sanity is enforced independently of the CRC:
        // both of these carry a *valid* CRC over bad fields.
        let bad_dc = PmSnapshot {
            dc_target_bits: 3,
            ..fixture_snapshot(4)
        };
        if PmSnapshot::from_bytes(&bad_dc.to_bytes()).is_ok() {
            return TestResult::Fail("snapshot with DC field 3 parsed");
        }
        let bad_mode = PmSnapshot {
            mode: Some(Mode {
                h_total: 100, // < h_active
                ..mode_1080p()
            }),
            ..fixture_snapshot(5)
        };
        if PmSnapshot::from_bytes(&bad_mode.to_bytes()).is_ok() {
            return TestResult::Fail("snapshot with h_total < h_active parsed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pm", smoke_pm_snapshot_codec);

    // ── (4) Untrusted snapshot: resume re-establishes ───────

    fn smoke_pm_untrusted_snapshot_reestablishes() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let pci = FakePci::new(log.clone());
        // The snapshot will carry the 720p mode; the driver's
        // live state says 1080p. An untrusted resume must
        // re-light the *driver's* mode, never the snapshot's.
        let platform = FakePlatform::new(log.clone(), Some(mode_720p()), None);
        let mut core = PmCore::new();
        if core
            .rc6
            .enable(&mut core.fw, &regs, &[RCS_BASE], 0)
            .is_err()
        {
            return TestResult::Fail("RC6 enable failed");
        }
        if core.suspend(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("suspend failed");
        }
        platform.mode.set(Some(mode_1080p()));
        // The hook's verdict on the sealed copy: invalid.
        core.unseal_outcome = Some(UnsealOutcome::Invalid);
        if core.reconcile_after_unseal(&regs, &platform).is_err() {
            return TestResult::Fail("reconcile (suspended/invalid) failed");
        }
        if core.snapshot_trusted {
            return TestResult::Fail("invalid unseal left the snapshot trusted");
        }
        log.borrow_mut().clear();
        match core.resume(&regs, &pci, &platform) {
            Err(PmError::Degraded(DegradedReason::SnapshotInvalid)) => {}
            _ => return TestResult::Fail("untrusted resume not Degraded(SnapshotInvalid)"),
        }
        if platform.relight_args.borrow().as_slice() != [mode_1080p()] {
            return TestResult::Fail("re-establish did not relight the driver's mode");
        }
        if core.rc6.is_enabled() {
            return TestResult::Fail("re-establish left the RC6 flag claiming an enable");
        }
        if !reg_writes(&log).contains(&(GEN9_PG_ENABLE, 0)) {
            return TestResult::Fail("re-establish did not run the RC6 disable conversation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pm",
        smoke_pm_untrusted_snapshot_reestablishes
    );

    // ── (5) Phase discipline + D-state strings ──────────────

    fn smoke_pm_phase_and_dstate_reporting() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let pci = FakePci::new(log.clone());
        let platform = FakePlatform::new(log.clone(), None, None);
        let mut core = PmCore::new();
        if core.power_state_str() != "D0" {
            return TestResult::Fail("fresh core does not report D0");
        }
        if core.resume(&regs, &pci, &platform) != Err(PmError::WrongPhase) {
            return TestResult::Fail("resume while live not refused");
        }
        if core.suspend(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("headless suspend failed");
        }
        if core.power_state_str() != "D3hot" {
            return TestResult::Fail("suspended core does not report D3hot");
        }
        if core.suspend(&regs, &pci, &platform) != Err(PmError::WrongPhase) {
            return TestResult::Fail("double suspend not refused");
        }
        if core.resume(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("headless resume failed");
        }
        // The string mapping itself, over the remaining states
        // (a pure function of the tracked state).
        core.dstate = PciPowerState::D1;
        if core.power_state_str() != "D1" {
            return TestResult::Fail("D1 does not report as D1");
        }
        core.dstate = PciPowerState::D2;
        if core.power_state_str() != "D2" {
            return TestResult::Fail("D2 does not report as D2");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pm",
        smoke_pm_phase_and_dstate_reporting
    );

    // ── (6) PCI write failure rolls the suspend back ────────

    fn smoke_pm_pci_failure_rolls_back() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let pci = FakePci::new(log.clone());
        let platform = FakePlatform::new(log.clone(), Some(mode_1080p()), None);
        let mut core = PmCore::new();
        if core
            .rc6
            .enable(&mut core.fw, &regs, &[RCS_BASE], 0)
            .is_err()
        {
            return TestResult::Fail("RC6 enable failed");
        }
        pci.fail_write.set(true);
        match core.suspend(&regs, &pci, &platform) {
            Err(PmError::PciFailed) => {}
            _ => return TestResult::Fail("failed D3 write not reported as PciFailed"),
        }
        if core.phase() != PmPhase::Live || core.has_snapshot() || platform.gate_closed.get() {
            return TestResult::Fail("failed suspend did not roll back to Live");
        }
        // The rollback unparks: RC6_CTL_HOST lands after the
        // park's RC6-enable write.
        let writes = reg_writes(&log);
        let park_at = writes
            .iter()
            .position(|w| *w == (GEN6_RC_CONTROL, RC_CTL_RC6_ENABLE));
        let unpark_at = writes
            .iter()
            .position(|w| *w == (GEN6_RC_CONTROL, RC6_CTL_HOST));
        match (park_at, unpark_at) {
            (Some(p), Some(u)) if p < u => {}
            _ => return TestResult::Fail("rollback did not unpark after the failed D3 write"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pm", smoke_pm_pci_failure_rolls_back);

    // ── (7) D0 readback disagreement degrades, gate stays ───

    fn smoke_pm_resume_readback_degrades() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let pci = FakePci::new(log.clone());
        let platform = FakePlatform::new(log.clone(), Some(mode_1080p()), None);
        let mut core = PmCore::new();
        if core.suspend(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("suspend failed");
        }
        pci.read_lie.set(Some(PciPowerState::D3Hot));
        match core.resume(&regs, &pci, &platform) {
            Err(PmError::PciFailed) => {}
            _ => return TestResult::Fail("lying readback not reported as PciFailed"),
        }
        if core.phase() != PmPhase::Degraded(DegradedReason::HardwareRestore) {
            return TestResult::Fail("lying readback not Degraded(HardwareRestore)");
        }
        if !platform.gate_closed.get() {
            return TestResult::Fail("gate reopened for an unverified D0");
        }
        // A truthful retry from the degraded phase recovers.
        pci.read_lie.set(None);
        if core.resume(&regs, &pci, &platform).is_err() {
            return TestResult::Fail("resume retry from Degraded failed");
        }
        if core.phase() != PmPhase::Live {
            return TestResult::Fail("resume retry did not return to Live");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pm",
        smoke_pm_resume_readback_degrades
    );

    // ── (8) Reconcile paths at core level ───────────────────

    fn smoke_pm_reconcile_paths() -> TestResult {
        let log = new_log();
        let regs = FakeRegs::new(log.clone());
        let platform = FakePlatform::new(log.clone(), Some(mode_720p()), None);
        let mut core = PmCore::new();
        core.phase = PmPhase::Live;
        core.last_applied_seq = 3;
        // Verified blob for the restore that already ran:
        // no-op.
        core.unseal_outcome = Some(UnsealOutcome::Verified(fixture_snapshot(3)));
        if core.reconcile_after_unseal(&regs, &platform).is_err()
            || !platform.relight_args.borrow().is_empty()
        {
            return TestResult::Fail("matching verified blob was not a no-op");
        }
        // Verified blob for a *different* suspend: re-apply
        // its display state.
        core.unseal_outcome = Some(UnsealOutcome::Verified(fixture_snapshot(9)));
        if core.reconcile_after_unseal(&regs, &platform).is_err() {
            return TestResult::Fail("verified reconcile failed");
        }
        if platform.relight_args.borrow().as_slice() != [mode_1080p()] || core.last_applied_seq != 9
        {
            return TestResult::Fail("verified reconcile did not apply the blob's mode");
        }
        // Missing blob while live: the running restore was
        // never verified — re-establish from driver state and
        // name it.
        platform.relight_args.borrow_mut().clear();
        core.unseal_outcome = Some(UnsealOutcome::Missing);
        if core.reconcile_after_unseal(&regs, &platform).is_err() {
            return TestResult::Fail("missing reconcile failed");
        }
        if core.phase() != PmPhase::Degraded(DegradedReason::UnverifiedRestore)
            || platform.relight_args.borrow().as_slice() != [mode_720p()]
        {
            return TestResult::Fail("missing blob not Degraded(UnverifiedRestore) at driver mode");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pm", smoke_pm_reconcile_paths);

    // ── (9) The hook through the real suspend service ──────

    /// In-memory `ImageStore` (the power crate's fixture
    /// shape, re-derived from the trait).
    struct MemStore {
        data: Rc<RefCell<Vec<u8>>>,
    }

    impl MemStore {
        fn new(len: usize) -> Self {
            Self {
                data: Rc::new(RefCell::new(alloc::vec![0u8; len])),
            }
        }
        fn flip_byte(&self, offset: u64) {
            self.data.borrow_mut()[offset as usize] ^= 0xFF;
        }
        fn bytes(&self, offset: u64, len: usize) -> Vec<u8> {
            self.data.borrow()[offset as usize..offset as usize + len].to_vec()
        }
    }

    impl ImageStore for MemStore {
        fn len_bytes(&self) -> u64 {
            self.data.borrow().len() as u64
        }
        fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
            let start = offset as usize;
            let end = start
                .checked_add(out.len())
                .ok_or(ServiceError::Truncated)?;
            let data = self.data.borrow();
            if end > data.len() {
                return Err(ServiceError::Truncated);
            }
            out.copy_from_slice(&data[start..end]);
            Ok(())
        }
        fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
            let start = offset as usize;
            let end = start.checked_add(data.len()).ok_or(ServiceError::Store)?;
            let mut store = self.data.borrow_mut();
            if end > store.len() {
                return Err(ServiceError::Store);
            }
            store[start..end].copy_from_slice(data);
            Ok(())
        }
        fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }
    }

    /// Deterministic fixture entropy (the suspend service's
    /// scripted-entropy contract: seed-grade, never partial).
    struct FixtureEntropy(Cell<u64>);

    impl KeyEntropy for FixtureEntropy {
        fn has_seed_grade(&self) -> bool {
            true
        }
        fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
            let mut x = self.0.get() | 1;
            for b in out.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x >> 32) as u8;
            }
            self.0.set(x);
            Ok(())
        }
    }

    fn off_policy() -> RecordedPolicy {
        RecordedPolicy {
            level: PolicyLevel::Off,
            policy_epoch: 0,
        }
    }

    /// The hook-region store offset for a 1024-byte image
    /// payload (one chunk): the layout the image writer
    /// produces — header page + one chunk page. Cross-checked
    /// by decoding the region at that offset below: a wrong
    /// offset fails the decode, not silently.
    const HOOK_REGION_OFFSET: u64 = 8192;

    fn smoke_pm_hook_through_service() -> TestResult {
        __reset_hooks_for_test();
        narf_power::device_pm::__reset_for_test();
        __reset_pm_for_test();
        __seed_suspended_for_test(fixture_snapshot(7));
        register_suspend_state_hook(Arc::new(IntelGpuSuspendHook));

        let mut svc = SuspendService::new(FixtureEntropy(Cell::new(0x5EED)));
        let mut store = MemStore::new(1 << 20);
        let image = [0x5Au8; 1024];
        let (_id, report) = match svc.seal_image_registered(&mut store, off_policy(), &image) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("seal_image_registered failed"),
        };
        let snap_len = fixture_snapshot(7).to_bytes().len();
        if report.sealed.len() != 1
            || report.sealed[0].name != PM_NAME
            || report.sealed[0].image_len != Some(snap_len)
        {
            return TestResult::Fail("seal report does not name the intel-gpu blob");
        }
        let opened = match svc.open_off(&store) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("open_off failed"),
        };
        let region_len = opened.hook_region_len() as usize;
        let trusted = match opened.verify_all(&store) {
            Ok(t) => t,
            Err(_) => return TestResult::Fail("verify_all failed"),
        };
        let report = match unseal_registered(&trusted, &store, &off_policy_sms(), &|_| true) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("unseal fan-out failed"),
        };
        if report.entries.len() != 1 || report.entries[0].outcome != PowerUnsealOutcome::Delivered {
            return TestResult::Fail("unseal did not deliver to the intel-gpu hook");
        }
        if __unseal_summary_for_test() != UnsealSummary::Verified(7) {
            return TestResult::Fail("hook did not record the verified snapshot");
        }

        // Tamper one ciphertext byte of the hook's blob: the
        // image still verifies (the blob's own AEAD is the
        // check), the fan-out still delivers, and the hook
        // records Invalid — never the tampered state.
        let region = store.bytes(HOOK_REGION_OFFSET, region_len);
        let blobs = match decode_hook_region(&region) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("hook region does not decode at the pinned offset"),
        };
        let mut at = HOOK_REGION_OFFSET + 4; // u32 count
        let mut sealed_at = None;
        for blob in &blobs {
            let entry_sealed_at = at + 2 + blob.name.len() as u64 + 1 + 4;
            if blob.name == PM_NAME {
                sealed_at = Some(entry_sealed_at);
                break;
            }
            at = entry_sealed_at + blob.sealed.len() as u64;
        }
        let at = match sealed_at {
            Some(a) => a,
            None => return TestResult::Fail("intel-gpu blob not in the hook region"),
        };
        store.flip_byte(at);
        if svc.open_off(&store).is_err() {
            return TestResult::Fail("open_off failed on the tampered image");
        }
        let report = match unseal_registered(&trusted, &store, &off_policy_sms(), &|_| true) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("tampered blob aborted the fan-out"),
        };
        if report.entries.len() != 1 || report.entries[0].outcome != PowerUnsealOutcome::Delivered {
            return TestResult::Fail("tampered blob was not delivered as an outcome");
        }
        if __unseal_summary_for_test() != UnsealSummary::Invalid {
            return TestResult::Fail("tampered blob was not recorded Invalid");
        }

        // Seal with no snapshot refuses, and the service
        // aborts the whole seal (no image committed).
        __reset_pm_for_test();
        let mut store2 = MemStore::new(1 << 20);
        if svc
            .seal_image_registered(&mut store2, off_policy(), &image)
            .is_ok()
        {
            return TestResult::Fail("seal without a snapshot did not abort");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pm", smoke_pm_hook_through_service);
}

//! The TPM lifecycle surface for the suspend service
//! (power-suspend design §8.3/§4.3, lane P6b #1003; the
//! suspend half of #942): what happens to the TPM custody
//! anchor's world across the TPM's *own* lifecycle events —
//! the suspend/resume power sequencing, `TPM2_Clear` and
//! ownership change, and dictionary-attack (DA) lockout.
//!
//! Three contracts, stated once and pinned by fixtures:
//!
//! - **Power sequencing.** A suspend that used the anchor ends
//!   its TPM conversation with `TPM2_Shutdown(TPM_SU_STATE)`
//!   ([`TpmLifecycle::shutdown_for_suspend`] — design §4.3 step
//!   6, issued only after the image is durable). The resume
//!   environment opens with [`TpmLifecycle::startup_for_resume`],
//!   which asks for the saved state and reports what it
//!   actually got: [`StartupOutcome::Restored`] (state saved
//!   and restored — PCRs are continuous with the suspend, so
//!   the anchor's PCR policy can be satisfied),
//!   [`StartupOutcome::Fresh`] (no state to restore — the TPM
//!   was started `TPM_SU_CLEAR`, PCRs are at power-on values,
//!   and a slot sealed against the pre-suspend measurements
//!   will refuse, as it must), or
//!   [`StartupOutcome::AlreadyStarted`] (an earlier boot stage
//!   — firmware, the bootloader — already started the TPM; the
//!   lifecycle never issues a second Startup sequence against
//!   a running TPM and never pretends to know which startup
//!   the earlier stage chose). The classification follows the
//!   response policy `narf_tpm`'s production `startup` folds on
//!   (Part 3 §9.3): a `TPM_RC_VALUE`-class answer to
//!   `Startup(TPM_SU_STATE)` means "no saved state", and to the
//!   `TPM_SU_CLEAR` retry it means "already started". Response
//!   codes are classified by their format-one *base* (Part 2
//!   §6.6), never by exact composite — the number bits a TPM
//!   ORs in for the failing parameter differ by call site.
//! - **Clear / ownership invalidation.** `TPM2_Clear` (Part 3
//!   §24.4) mints a new storage primary seed: every sealed
//!   suspend slot dies at `Load`, whatever its recorded epoch,
//!   and the owner-defined NV epoch counter is flushed with the
//!   rest of the owner hierarchy's indices. The lifecycle's
//!   statement of that event is [`TpmLifecycle::epoch_state`]
//!   reporting [`EpochState::Absent`], and the anchor's
//!   corresponding unwrap is [`super::AnchorError::Failed`]
//!   from its no-oracle bucket — never a refusal an operator
//!   could mistake for PCR drift, and never, under any
//!   circumstances, a silent re-seal or a re-provision that
//!   resurrects the slot: re-advancing the epoch after a Clear
//!   provisions a *new* counter under a *new* seed and the old
//!   slots stay dead even when the new counter reaches the
//!   same number. NV surgery alone (undefine + re-define) is
//!   *not* an invalidation event — it moves the accounting,
//!   not the seed — and this module does not pretend
//!   otherwise; the invalidation event is Clear.
//! - **DA lockout accounting.** The anchor maps both
//!   `TPM_RC_POLICY_FAIL` and `TPM_RC_LOCKOUT` to
//!   [`super::AnchorError::Refused`] — deliberately one bucket.
//!   The lifecycle keeps the causes apart for the *operator*:
//!   [`classify_refusal`] attributes the anchor's recorded
//!   response code ([`super::TpmAnchor::last_response_code`])
//!   as policy, lockout, or auth failure; the lifecycle's
//!   `lockout_state` reads the TPM's own accounting
//!   (`TPM_PT_LOCKOUT_COUNTER` and its companions, Part 2
//!   §6.13); and [`TpmLifecycle::reset_lockout`] is the
//!   recovery act, authorized by the lockout hierarchy. The
//!   resume rule the accounting exists to support: **on a
//!   lockout refusal the TPM factor is not retried within the
//!   attempt** — the TPM counts authValue failures, and a
//!   resume loop that keeps presenting auth turns a transient
//!   refusal into a longer lockout (the accounting also shows
//!   why the anchor's own traffic cannot do this: its policy
//!   failures are not auth failures and are never counted, and
//!   the epoch counter it increments is `TPMA_NV_NO_DA`). Other
//!   factors of the recorded policy proceed unaffected; a TPM
//!   lockout is a property of the TPM factor, not of the
//!   machine's resume.
//!
//! Wiring: this module is the anchor-side lifecycle API. The
//! suspend path calls `shutdown_for_suspend` after its image
//! is durable; the resume environment calls
//! `startup_for_resume` before it touches any slot. Neither
//! caller exists in this tree yet — the boot/resume wiring is
//! the resume environment's lane, the same remainder posture
//! the anchor itself took in #1002 — and nothing in this
//! module registers an initcall or a device-PM handler.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_drivers_tpm::devfs_bridge::{self, TpmTransport};
use narf_drivers_tpm::tpm2::{
    commands as cmds, nv as tpm_nv, TPM_CAP_TPM_PROPERTIES, TPM_PT_LOCKOUT_COUNTER,
    TPM_PT_LOCKOUT_INTERVAL, TPM_PT_LOCKOUT_RECOVERY, TPM_PT_MAX_AUTH_FAIL, TPM_RC_LOCKOUT,
    TPM_RC_NV_UNINITIALIZED, TPM_RC_SUCCESS, TPM_SU_CLEAR, TPM_SU_STATE,
};

/// Lifecycle failure. `Unavailable` is the factor's absence —
/// the transport failed, so the TPM's state is *unknown*, and
/// the caller must treat the TPM factor as missing rather than
/// guess. `Refused` is the TPM answering no to an authorized
/// act (the lockout reset presented an auth the TPM rejects).
/// `Failed` is every other unexpected answer: a malfunction
/// class, deliberately one bucket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmLifecycleError {
    /// No TPM answered (transport failure).
    Unavailable,
    /// The TPM refused the act (authorization class).
    Refused,
    /// The TPM answered unexpectedly.
    Failed,
}

/// What [`TpmLifecycle::shutdown_for_suspend`] achieved.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// `TPM2_Shutdown(TPM_SU_STATE)` landed: the next
    /// `Startup(TPM_SU_STATE)` can restore the saved state.
    StateSaved,
    /// The state-saving shutdown failed and the lifecycle fell
    /// back to `TPM2_Shutdown(TPM_SU_CLEAR)`: the suspend may
    /// proceed, but the resume will find no saved TPM state
    /// and must expect the anchor's slots sealed against the
    /// pre-suspend PCRs to refuse.
    StateContinuityLost,
}

/// What [`TpmLifecycle::startup_for_resume`] found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartupOutcome {
    /// `Startup(TPM_SU_STATE)` succeeded: the state saved by
    /// the suspend's orderly shutdown was restored, PCRs
    /// continuous with the moment of suspend.
    Restored,
    /// No saved state existed (dirty power loss, a CLEAR
    /// shutdown, firmware that discarded it): the TPM was
    /// started fresh with `Startup(TPM_SU_CLEAR)`.
    Fresh,
    /// The TPM was already started by an earlier boot stage:
    /// both Startup attempts were answered as type mismatches.
    /// The lifecycle did not disturb it.
    AlreadyStarted,
}

/// The suspend epoch counter's state, as the lifecycle is
/// willing to certify it. The anchor's `epoch()` collapses all
/// of this into `Option<u64>`; the lifecycle distinguishes the
/// cases because they carry different meanings for resume: a
/// counter that was never provisioned is a machine that has
/// not enrolled, and a counter that vanished is a machine
/// whose TPM was cleared or whose NV was re-provisioned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EpochState {
    /// The counter is defined and has been incremented.
    Present(u64),
    /// The counter is defined but never incremented
    /// (`TPM_RC_NV_UNINITIALIZED`): provisioned, unused.
    Uninitialized,
    /// No counter is defined at that index: never provisioned,
    /// undefined since, or flushed by `TPM2_Clear`.
    Absent,
}

/// The TPM's dictionary-attack accounting, read from its
/// variable properties (Part 2 §6.13). Intervals are seconds;
/// the TPM decays `failed_tries` by one per
/// `lockout_interval_secs` of *powered* time, which is why a
/// lockout's wall-clock duration is not a promise — the
/// accounting is reported, never scheduled against.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LockoutState {
    /// Authorization failures counted since the last reset
    /// (`TPM_PT_LOCKOUT_COUNTER` — the DA `failedTries`).
    pub failed_tries: u32,
    /// The threshold at which the TPM enters lockout
    /// (`TPM_PT_MAX_AUTH_FAIL`).
    pub max_auth_fail: u32,
    /// Seconds of powered time per `failed_tries` decrement
    /// (`TPM_PT_LOCKOUT_INTERVAL`).
    pub lockout_interval_secs: u32,
    /// Seconds after a lockoutAuth failure before it may be
    /// presented again (`TPM_PT_LOCKOUT_RECOVERY`).
    pub lockout_recovery_secs: u32,
}

impl LockoutState {
    /// Whether the TPM is currently in DA lockout:
    /// `failedTries` has reached `maxTries` (Part 1 §19).
    pub fn in_lockout(&self) -> bool {
        self.max_auth_fail > 0 && self.failed_tries >= self.max_auth_fail
    }
}

/// Which refusal an anchor outcome was, for accounting. The
/// anchor's own surface stays deliberately coarse — policy and
/// lockout are its [`super::AnchorError::Refused`], auth
/// failures sit in its no-oracle
/// [`super::AnchorError::Failed`] — so this classification is
/// for the operator-facing lifecycle accounting only, computed
/// from the recorded response code after the fact, and is
/// never fed back into a retry decision within an attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmRefusal {
    /// `TPM_RC_POLICY_FAIL`: the TPM evaluated the slot's
    /// policy (PCR state) and it did not match.
    Policy,
    /// `TPM_RC_LOCKOUT`: DA lockout is active; authValue use
    /// for DA-protected entities is refused wholesale.
    Lockout,
    /// `TPM_RC_AUTH_FAIL` / `TPM_RC_BAD_AUTH`: an auth value
    /// did not match (counted toward lockout only in the
    /// `AUTH_FAIL` case — the distinction is Part 1 §19's, and
    /// the accounting reports both as auth refusals).
    Auth,
}

// Format-one base codes (Part 2 §6.6): the low six bits of a
// format-one response code once the number/severity bits are
// masked off. Classification by base — the same decode
// `narf_tpm::TpmRc::from_rc` performs — is what keeps this
// correct across call sites whose composites differ.
const RC_BASE_VALUE: u32 = 0x04;
const RC_BASE_HANDLE: u32 = 0x0B;
const RC_BASE_AUTH_FAIL: u32 = 0x0E;
const RC_BASE_POLICY_FAIL: u32 = 0x1D;
const RC_BASE_BAD_AUTH: u32 = 0x22;

/// The format-one base of a response code, or `None` for a
/// format-zero (version-one) code.
fn fmt1_base(rc: u32) -> Option<u32> {
    if rc & 0x80 != 0 {
        Some(rc & 0x3F)
    } else {
        None
    }
}

/// Attribute a TPM response code as a refusal cause, or `None`
/// when the code is not a refusal (success, absence-class
/// codes, malfunctions). Feed it
/// [`super::TpmAnchor::last_response_code`] after a failed
/// anchor operation whose cause the accounting must name.
pub fn classify_refusal(rc: u32) -> Option<TpmRefusal> {
    if rc == TPM_RC_LOCKOUT {
        return Some(TpmRefusal::Lockout);
    }
    match fmt1_base(rc) {
        Some(RC_BASE_POLICY_FAIL) => Some(TpmRefusal::Policy),
        Some(RC_BASE_AUTH_FAIL) | Some(RC_BASE_BAD_AUTH) => Some(TpmRefusal::Auth),
        _ => None,
    }
}

/// The TPM lifecycle over the same transport seam the anchor
/// consumes. Holds no state of its own: every answer is read
/// from the TPM at call time, because the TPM's lifecycle state
/// (started? cleared? locked out?) is exactly what can change
/// while this service is not running.
pub struct TpmLifecycle {
    transport: Arc<dyn TpmTransport>,
}

impl fmt::Debug for TpmLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmLifecycle")
    }
}

impl TpmLifecycle {
    /// A lifecycle over an explicit transport (fixtures, and
    /// the resume environment's own injection).
    pub fn with_transport(transport: Arc<dyn TpmTransport>) -> Self {
        Self { transport }
    }

    /// The production lifecycle: the transport the platform
    /// probe registered. `None` on a TPM-less machine — the
    /// lifecycle, like the anchor, simply does not exist there.
    pub fn production() -> Option<Self> {
        devfs_bridge::installed_transport().map(Self::with_transport)
    }

    /// Submit one command, returning the raw response and its
    /// code. A transport failure is `Unavailable`; a malformed
    /// frame (no readable code) is `Failed`.
    fn submit(&self, cmd: &[u8]) -> Result<(Vec<u8>, u32), TpmLifecycleError> {
        let raw = self
            .transport
            .submit(cmd)
            .map_err(|()| TpmLifecycleError::Unavailable)?;
        let rc = cmds::response_rc(&raw).ok_or(TpmLifecycleError::Failed)?;
        Ok((raw, rc))
    }

    /// The last TPM act of a suspend that used the anchor
    /// (design §4.3 step 6): `TPM2_Shutdown(TPM_SU_STATE)`, so
    /// the resume can restore the saved state. Issued only
    /// after the image is durable — a shutdown that saved state
    /// for an image that never landed would offer the resume a
    /// continuity the image does not have.
    ///
    /// If the state-saving shutdown fails, fall back to
    /// `TPM2_Shutdown(TPM_SU_CLEAR)` and report
    /// [`ShutdownOutcome::StateContinuityLost`]: the suspend
    /// proceeds and the resume takes the fresh-start path,
    /// with the anchor's PCR-bound slots refusing there — the
    /// honest outcome, surfaced, never papered over.
    pub fn shutdown_for_suspend(&self) -> Result<ShutdownOutcome, TpmLifecycleError> {
        if let Ok((_, TPM_RC_SUCCESS)) = self.submit(&cmds::shutdown(TPM_SU_STATE)) {
            return Ok(ShutdownOutcome::StateSaved);
        }
        // The state-saving shutdown did not land — the TPM
        // refused it, answered garbage, or the transport
        // dropped it. One fallback: a CLEAR shutdown still
        // leaves the TPM in its cleanest power-down state, and
        // the outcome class tells the caller exactly what was
        // lost. If the fallback itself was refused, that is a
        // malfunction; if it never reached the TPM, the factor
        // is absent.
        match self.submit(&cmds::shutdown(TPM_SU_CLEAR)) {
            Ok((_, TPM_RC_SUCCESS)) => Ok(ShutdownOutcome::StateContinuityLost),
            Ok(_) => Err(TpmLifecycleError::Failed),
            Err(e) => Err(e),
        }
    }

    /// The first TPM act of a resume: ask for the saved state,
    /// and report what the TPM actually did. Mirrors the
    /// response policy of `narf_tpm`'s production `startup`
    /// (Part 3 §9.3), extended to *report* the outcome class
    /// instead of folding it into success — the resume
    /// environment's expectations of the anchor differ by class
    /// (see the module documentation).
    pub fn startup_for_resume(&self) -> Result<StartupOutcome, TpmLifecycleError> {
        let (_, rc) = self.submit(&cmds::startup(TPM_SU_STATE))?;
        match rc {
            TPM_RC_SUCCESS => Ok(StartupOutcome::Restored),
            // No saved state to restore (or saved state the TPM
            // cannot recover): start fresh.
            _ if fmt1_base(rc) == Some(RC_BASE_VALUE) || rc == TPM_RC_NV_UNINITIALIZED => {
                let (_, rc) = self.submit(&cmds::startup(TPM_SU_CLEAR))?;
                match rc {
                    TPM_RC_SUCCESS => Ok(StartupOutcome::Fresh),
                    _ if fmt1_base(rc) == Some(RC_BASE_VALUE) => Ok(StartupOutcome::AlreadyStarted),
                    _ => Err(TpmLifecycleError::Failed),
                }
            }
            _ => Err(TpmLifecycleError::Failed),
        }
    }

    /// Read the suspend epoch counter's state without
    /// collapsing its failure modes: the three `Ok` variants
    /// are the TPM's three answers (value, defined-but-
    /// unwritten, no such index), and `Err` is the lifecycle's
    /// (the TPM is absent, or answered nonsense).
    pub fn epoch_state(&self) -> Result<EpochState, TpmLifecycleError> {
        let (raw, rc) = self.submit(&cmds::nv_read(tpm_nv::NV_IDX_SUSPEND_EPOCH, 8, 0))?;
        match rc {
            TPM_RC_SUCCESS => {
                let data =
                    cmds::parse_nv_read_response(&raw).map_err(|_| TpmLifecycleError::Failed)?;
                if data.len() != 8 {
                    return Err(TpmLifecycleError::Failed);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data);
                Ok(EpochState::Present(u64::from_be_bytes(buf)))
            }
            TPM_RC_NV_UNINITIALIZED => Ok(EpochState::Uninitialized),
            _ if fmt1_base(rc) == Some(RC_BASE_HANDLE) => Ok(EpochState::Absent),
            _ => Err(TpmLifecycleError::Failed),
        }
    }

    /// Read the TPM's DA accounting (Part 1 §19) from its
    /// variable properties.
    pub fn lockout_state(&self) -> Result<LockoutState, TpmLifecycleError> {
        Ok(LockoutState {
            failed_tries: self.property(TPM_PT_LOCKOUT_COUNTER)?,
            max_auth_fail: self.property(TPM_PT_MAX_AUTH_FAIL)?,
            lockout_interval_secs: self.property(TPM_PT_LOCKOUT_INTERVAL)?,
            lockout_recovery_secs: self.property(TPM_PT_LOCKOUT_RECOVERY)?,
        })
    }

    /// One tagged TPM property, read on its own so a TPM that
    /// pages its properties differently still answers.
    fn property(&self, tag: u32) -> Result<u32, TpmLifecycleError> {
        let (raw, rc) = self.submit(&cmds::get_capability(TPM_CAP_TPM_PROPERTIES, tag, 1))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmLifecycleError::Failed);
        }
        let envelope =
            cmds::parse_get_capability_response(&raw).map_err(|_| TpmLifecycleError::Failed)?;
        let props =
            cmds::parse_tagged_properties(&envelope.data).map_err(|_| TpmLifecycleError::Failed)?;
        props
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| *v)
            .ok_or(TpmLifecycleError::Failed)
    }

    /// Cancel an active DA lockout:
    /// `TPM2_DictionaryAttackLockReset` under the lockout
    /// hierarchy's authorization, which sets `failedTries` to
    /// zero. This is an operator act (enrollment / recovery
    /// ceremonies), not something a resume path does on its
    /// own — a resume that could clear the counter could also
    /// be an attacker clearing it between guesses.
    pub fn reset_lockout(&self) -> Result<(), TpmLifecycleError> {
        let (_, rc) = self.submit(&cmds::dictionary_attack_lock_reset())?;
        match rc {
            TPM_RC_SUCCESS => Ok(()),
            _ if classify_refusal(rc).is_some() => Err(TpmLifecycleError::Refused),
            _ => Err(TpmLifecycleError::Failed),
        }
    }
}

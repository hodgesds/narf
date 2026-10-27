//! The suspend policy engine (power-suspend design §10, lane P8
//! #1006): policy levels, the admin floor, enrollment and
//! re-enrollment flows, and recorded-policy enforcement at resume.
//!
//! Everything here is built on the seams the earlier lanes left:
//! P1's [`KeyCustodyAnchor`] trait and slot machinery (the policy
//! layer names anchor *kinds*, never implementations — the token
//! (P3/P5), TPM (P6), and passphrase (P7) anchors register into
//! these rules by kind as they land), P1's authenticated
//! [`RecordedPolicy`] (the governing policy of an image, enforced
//! here at resume), and the service's composition primitive
//! ([`SuspendService::enroll_composition`] /
//! [`SuspendService::rotate_epoch_composition`], the §8.5 XOR split
//! whose storage P6a deferred to this lane: one slot per factor,
//! composition meaning carried by the recorded level).
//!
//! The decided shape (Daniel, 2026-10-26, decision sheet) is
//! implemented as written, not relitigated:
//!
//! 1. Touch+PIN is the default token verification when the token
//!    is the sole factor; touch-only is an explicit choice, and a
//!    reasonable default under token+TPM composition
//!    ([`default_token_verification`]).
//! 2. A passphrase recovery slot is offered at enrollment and
//!    defaults ON for the first epoch
//!    ([`PolicyStore::provision_fresh_install`]).
//! 3. OFF is never a default and never a fallback: it is reachable
//!    only through the explicit [`OffConfirmation`] path, an admin
//!    floor can exclude it (and anything below the floor), and at
//!    resume the *recorded* policy governs — never the machine's
//!    current configuration ([`open_with_policy`]).
//! 4. The fresh-install default is TOKEN when ≥2 tokens enroll,
//!    else PASSPHRASE ([`fresh_install_default`]).
//! 5. S3 / s2idle are permitted at every level
//!    ([`ram_suspend_permitted`]); the RAM exposure is documented
//!    ([`S3_RAM_EXPOSURE_NOTE`]) and the restrict toggle is
//!    deferred to #1008, deliberately not built here.

use alloc::vec::Vec;

use super::anchor::{AnchorError, AnchorKind, KeyCustodyAnchor, UnwrapCtx};
use super::custody::Secret32;
use super::format::{ImageClaims, ImageStore, PolicyLevel, RecordedPolicy};
use super::image::{open_with_sms, parse_claims, OpenedImage};
use super::slots::{Cursor, SlotRecord};
use super::{off_policy_sms, KeyEntropy, ServiceError, SuspendService};

/// The words the OFF confirmation shows, verbatim from design
/// §10.1. OFF is a legitimate choice; it is never a softened one.
pub const OFF_POLICY_WARNING: &str = "No protection. Anyone with the drive can read the \
    suspended machine's memory. This is the Linux behaviour.";

/// The S3/s2idle exposure note of design §7, surfaced by the
/// policy UI: RAM suspend states write nothing to disk, so no
/// image policy can protect them — the exposure is stated, not
/// hidden, and (decision 5) does not restrict the states.
pub const S3_RAM_EXPOSURE_NOTE: &str = "Suspend-to-RAM (S3) and s2idle write nothing to \
    disk: everything in RAM — session keys included — stays in powered RAM, exposed to \
    cold-boot and DMA attacks against the sleeping machine. Only hibernate (S4) images \
    are protected by the suspend policy.";

/// Whether a token factor requires user verification (its PIN) in
/// addition to user presence (the touch). The PIN protocol itself
/// lives in the token anchor (P5); this is the policy record of
/// which mode enrollment requested.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenVerification {
    /// Presence only: an enrolled token, touched.
    TouchOnly,
    /// Presence + PIN: the token's hardware retry limit guards
    /// the knowledge factor (design §4.5).
    TouchAndPin,
}

impl TokenVerification {
    fn code(self) -> u8 {
        match self {
            TokenVerification::TouchOnly => 0,
            TokenVerification::TouchAndPin => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(TokenVerification::TouchOnly),
            1 => Some(TokenVerification::TouchAndPin),
            _ => None,
        }
    }
}

/// What the resume environment does when the recorded policy's
/// token factor is absent at resume time (design §4.9): wait for
/// it, or abandon the image to a cold boot. Configured in advance
/// by the admin; "absent" never means "skip the factor".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenAbsent {
    /// The resume prompt stays up; the machine stays asleep until
    /// a token arrives. The default: a token left at home is not
    /// data loss.
    Defer,
    /// Abandon the image and cold-boot. The image's contents are
    /// lost; the machine is not weakened.
    AbandonImage,
}

impl TokenAbsent {
    fn code(self) -> u8 {
        match self {
            TokenAbsent::Defer => 0,
            TokenAbsent::AbandonImage => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(TokenAbsent::Defer),
            1 => Some(TokenAbsent::AbandonImage),
            _ => None,
        }
    }
}

/// The running system's policy record (design §10.2): the level in
/// force for future suspends, the admin floor beneath it, and the
/// standing enrollment defaults. Non-secret throughout — it
/// persists alongside the slot area, and the authoritative copy
/// for any written image is the [`RecordedPolicy`] sealed into
/// that image's header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    /// The level future suspends are written under.
    pub level: PolicyLevel,
    /// The admin floor: no flow may set a level below this
    /// (design §10.4). `PolicyLevel::Off` as a floor is no floor.
    pub floor: PolicyLevel,
    /// Bumped on every level change; stamped into each image's
    /// [`RecordedPolicy`] as provenance. (The cryptographic gate
    /// is the SMS epoch; this counter never gates a resume.)
    pub policy_epoch: u64,
    /// Verification requested of token factors (decision 1).
    pub token_verification: TokenVerification,
    /// Standing default: include a passphrase recovery slot in
    /// enrollment flows (decision 2 sets this at fresh install).
    pub recovery_slot_default: bool,
    /// Resume behaviour when a token factor is absent.
    pub token_absent: TokenAbsent,
}

const POLICY_MAGIC: &[u8; 8] = b"NARFPOL1";
const POLICY_CODEC_VERSION: u32 = 1;
/// magic(8) ‖ version(4) ‖ level(1) ‖ floor(1) ‖ policy_epoch(8)
/// ‖ token_verification(1) ‖ token_absent(1) ‖ recovery_default(1).
const POLICY_CODEC_LEN: usize = 8 + 4 + 1 + 1 + 8 + 1 + 1 + 1;

impl PolicyConfig {
    /// The record stamped into an image sealed under this config.
    pub fn recorded(&self) -> RecordedPolicy {
        RecordedPolicy {
            level: self.level,
            policy_epoch: self.policy_epoch,
        }
    }

    /// Serialize for the policy store's persistence (mirrored,
    /// non-secret, beside the slot area — design §10.2).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(POLICY_CODEC_LEN);
        out.extend_from_slice(POLICY_MAGIC);
        out.extend_from_slice(&POLICY_CODEC_VERSION.to_le_bytes());
        out.push(self.level.code());
        out.push(self.floor.code());
        out.extend_from_slice(&self.policy_epoch.to_le_bytes());
        out.push(self.token_verification.code());
        out.push(self.token_absent.code());
        out.push(u8::from(self.recovery_slot_default));
        out
    }

    /// Parse a serialized config. Strict and total, like the slot
    /// codec: exact length, known codes only, anything else is
    /// `Malformed` — a policy record this build cannot read is a
    /// policy it must not guess at.
    pub fn parse(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.len() != POLICY_CODEC_LEN {
            return Err(ServiceError::Malformed);
        }
        let mut cur = Cursor::new(bytes);
        if cur.take(8)? != POLICY_MAGIC {
            return Err(ServiceError::Malformed);
        }
        if cur.u32()? != POLICY_CODEC_VERSION {
            return Err(ServiceError::Malformed);
        }
        let level = PolicyLevel::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
        let floor = PolicyLevel::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
        let policy_epoch = cur.u64()?;
        let token_verification =
            TokenVerification::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
        let token_absent = TokenAbsent::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
        let recovery_slot_default = match cur.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ServiceError::Malformed),
        };
        Ok(PolicyConfig {
            level,
            floor,
            policy_epoch,
            token_verification,
            recovery_slot_default,
            token_absent,
        })
    }
}

/// Policy-layer failure. The variants are typed so an admin tool
/// can show *why* a flow refused; custody failures pass through as
/// [`ServiceError`] unchanged (its no-oracle discipline included).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The store holds no policy (nothing provisioned yet).
    NoPolicy,
    /// Fresh install was attempted over an existing policy/epoch.
    AlreadyProvisioned,
    /// The requested level is the one already in force; a fresh
    /// SMS epoch under the same level is `reenroll`, not a change.
    Unchanged,
    /// The requested level sits below the admin floor.
    BelowFloor {
        level: PolicyLevel,
        floor: PolicyLevel,
    },
    /// A transition into OFF was requested without the explicit
    /// confirmation token (decision 3).
    OffNotConfirmed,
    /// The factor set cannot realize the level: wrong kinds, or
    /// too few distinct factors (a token level needs two tokens;
    /// composition needs both groups).
    Unsatisfiable,
    /// A custody/service failure from the layer below.
    Service(ServiceError),
}

impl From<ServiceError> for PolicyError {
    fn from(e: ServiceError) -> Self {
        PolicyError::Service(e)
    }
}

/// The explicit opt-in to policy OFF (decision 3, design §10.4).
/// Constructing one *is* the deliberate act — the running UI
/// shows [`OFF_POLICY_WARNING`] verbatim before it hands one to a
/// flow, and the type's presence in a [`PolicyChange`] is the
/// greppable record that the act happened. There is no other path
/// into OFF: defaults never produce it and no fallback reaches it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OffConfirmation(());

impl OffConfirmation {
    /// Record an explicit, confirmed choice of policy OFF.
    pub fn explicit() -> Self {
        Self(())
    }
}

/// Standing rank of a level for floor comparisons. Token and TPM
/// are *peer* single-hardware-factor levels — presence on a
/// carried token vs binding to the machine's measured boot chain
/// — so they share a rank: a floor names a minimum standing, and
/// either satisfies a floor set at the other. TokenTpm strictly
/// dominates both (it requires both factors). Passphrase stands
/// below every hardware factor (its only brake is KDF cost,
/// design §9.2); OFF is the absence of protection.
pub fn level_rank(level: PolicyLevel) -> u8 {
    match level {
        PolicyLevel::Off => 0,
        PolicyLevel::Passphrase => 1,
        PolicyLevel::Token => 2,
        PolicyLevel::Tpm => 2,
        PolicyLevel::TokenTpm => 3,
    }
}

/// Whether `level` may be in force under an admin `floor`.
pub fn floor_satisfied(level: PolicyLevel, floor: PolicyLevel) -> bool {
    level_rank(level) >= level_rank(floor)
}

/// The default token verification for a level (decision 1):
/// touch+PIN whenever the token is the sole factor — the PIN is
/// the only thing standing in threat 3 (token stolen with the
/// laptop) and the token's hardware retry limit makes it strong.
/// Under token+TPM the machine anchor is the second factor, so
/// touch-only is the reasonable default there. Either way an
/// explicit [`PolicyConfig::token_verification`] choice overrides.
pub fn default_token_verification(level: PolicyLevel) -> TokenVerification {
    match level {
        PolicyLevel::Token => TokenVerification::TouchAndPin,
        _ => TokenVerification::TouchOnly,
    }
}

/// The fresh-install default level (decision 4): TOKEN when at
/// least two tokens enroll (the backup-token mandate of design
/// §4.2 is what makes the level honest), otherwise PASSPHRASE.
/// OFF is never a default — this function cannot return it.
pub fn fresh_install_default(enrolled_tokens: usize) -> PolicyLevel {
    if enrolled_tokens >= 2 {
        PolicyLevel::Token
    } else {
        PolicyLevel::Passphrase
    }
}

/// Whether suspend-to-RAM / s2idle is permitted under `level`
/// (decision 5): yes at every level — those states write nothing
/// to disk, so there is no image for a policy to protect, and
/// pretending otherwise would be theatre (design §7). The RAM
/// exposure is documented ([`S3_RAM_EXPOSURE_NOTE`]) rather than
/// restricted; the deferred restrict toggle is #1008's, not built
/// here.
pub fn ram_suspend_permitted(_level: PolicyLevel) -> bool {
    true
}

/// Validate that a slot set realizes `level` — the composition
/// rules of the policy layer, applied identically to an epoch's
/// enrolled slots before sealing and to an image's recorded slots
/// before any resume unwrap is attempted:
///
/// - OFF carries no slots at all.
/// - Each level's primary factor kinds must be present with the
///   required distinct counts: a token factor means **two**
///   distinct tokens (design §4.2's backup mandate — distinctness
///   is judged on slot params, in which every anchor embeds its
///   credential identity), a TPM factor at least one slot, a
///   passphrase factor at least one slot.
/// - A passphrase slot is the one permitted addition to any
///   hardware-factor level: the any-of recovery slot of §10.1.
///   Any other foreign kind — a token slot under PASSPHRASE, a
///   TPM slot under TOKEN, a test-kind slot anywhere — is a
///   shape violation: silently ignoring it would let a slot set
///   claim a level it does not realize.
/// - Duplicate (kind, params) records are a shape violation: a
///   second copy of a factor is not a second factor.
pub fn validate_slot_set(level: PolicyLevel, slots: &[SlotRecord]) -> Result<(), PolicyError> {
    for (i, a) in slots.iter().enumerate() {
        for b in &slots[i + 1..] {
            if a.kind == b.kind && a.params == b.params {
                return Err(PolicyError::Unsatisfiable);
            }
        }
    }
    let count = |kind: AnchorKind| slots.iter().filter(|s| s.kind == kind).count();
    let allowed = |kind: AnchorKind| match level {
        PolicyLevel::Off => false,
        PolicyLevel::Passphrase => kind == AnchorKind::Passphrase,
        PolicyLevel::Token => matches!(kind, AnchorKind::Token | AnchorKind::Passphrase),
        PolicyLevel::Tpm => matches!(kind, AnchorKind::Tpm | AnchorKind::Passphrase),
        PolicyLevel::TokenTpm => {
            matches!(
                kind,
                AnchorKind::Token | AnchorKind::Tpm | AnchorKind::Passphrase
            )
        }
    };
    if slots.iter().any(|s| !allowed(s.kind)) {
        return Err(PolicyError::Unsatisfiable);
    }
    let token_ok = count(AnchorKind::Token) >= 2;
    let tpm_ok = count(AnchorKind::Tpm) >= 1;
    let pass_ok = count(AnchorKind::Passphrase) >= 1;
    let ok = match level {
        PolicyLevel::Off => slots.is_empty(),
        PolicyLevel::Passphrase => pass_ok,
        PolicyLevel::Token => token_ok,
        PolicyLevel::Tpm => tpm_ok,
        PolicyLevel::TokenTpm => token_ok && tpm_ok,
    };
    if ok {
        Ok(())
    } else {
        Err(PolicyError::Unsatisfiable)
    }
}

/// The factor plan a recorded policy resolves to at resume: what
/// must be satisfied before the image may open. Derived from the
/// recorded level and the image's own slot records (already
/// shape-validated) — never from the machine's current config.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FactorPlan {
    /// OFF: the published derivation; no factor interaction.
    PublishedOff,
    /// Any one slot of `kind` unwraps the SMS (primary and backup
    /// factors of a kind are alternatives).
    AnyOf {
        kind: AnchorKind,
        /// A passphrase recovery slot is also enrolled and may
        /// open the image on its own (a deliberate slot, enrolled
        /// and recorded at seal time — not a runtime fallback,
        /// design §10.3).
        recovery: bool,
    },
    /// Token+TPM composition: one share from each factor group,
    /// XOR-recombined; either group alone yields nothing
    /// (design §8.5).
    Composition {
        /// A passphrase recovery slot is also enrolled (as above).
        recovery: bool,
    },
}

/// Resolve the resume plan for an image. The caller is expected
/// to have run [`validate_slot_set`] over the image's slots
/// first ([`open_with_policy`] does); the plan is then a pure
/// function of the recorded level plus the presence of a recovery
/// slot.
pub fn factor_plan(recorded: &RecordedPolicy, slots: &[SlotRecord]) -> FactorPlan {
    let has_recovery = slots.iter().any(|s| s.kind == AnchorKind::Passphrase);
    match recorded.level {
        PolicyLevel::Off => FactorPlan::PublishedOff,
        PolicyLevel::Passphrase => FactorPlan::AnyOf {
            kind: AnchorKind::Passphrase,
            recovery: false,
        },
        PolicyLevel::Token => FactorPlan::AnyOf {
            kind: AnchorKind::Token,
            recovery: has_recovery,
        },
        PolicyLevel::Tpm => FactorPlan::AnyOf {
            kind: AnchorKind::Tpm,
            recovery: has_recovery,
        },
        PolicyLevel::TokenTpm => FactorPlan::Composition {
            recovery: has_recovery,
        },
    }
}

/// Outcome of trying every (slot, anchor) pair of one kind.
enum UnwrapOutcome {
    /// An unwrap succeeded; this is the recovered secret/share.
    Secret(Secret32),
    /// No anchor of the kind was presented at all.
    NoAnchor,
    /// Anchors were presented and every unwrap refused.
    Refused,
    /// Anchors were presented and every unwrap reported the
    /// factor absent.
    Unavailable,
    /// Anchors were presented and at least one unwrap failed
    /// cryptographically (wrong factor for the slot, tampered
    /// blob — indistinguishable by design).
    Failed,
}

/// Failure classes observed across a resume attempt, for the
/// terminal error's precedence: a cryptographic failure outranks
/// a refusal, which outranks absence — the most informative class
/// wins, and all of them are coarse (no oracle about *which* slot
/// or check, per the discipline of design §6.2).
#[derive(Default)]
struct AttemptLog {
    failed: bool,
    refused: bool,
    unavailable: bool,
}

impl AttemptLog {
    fn record(&mut self, outcome: &UnwrapOutcome) {
        match outcome {
            UnwrapOutcome::Failed => self.failed = true,
            UnwrapOutcome::Refused => self.refused = true,
            UnwrapOutcome::Unavailable => self.unavailable = true,
            UnwrapOutcome::Secret(_) | UnwrapOutcome::NoAnchor => {}
        }
    }

    fn error(&self) -> ServiceError {
        if self.failed {
            ServiceError::Anchor(AnchorError::Failed)
        } else if self.refused {
            ServiceError::Anchor(AnchorError::Refused)
        } else if self.unavailable {
            ServiceError::Anchor(AnchorError::Unavailable)
        } else {
            ServiceError::SlotNotFound
        }
    }
}

/// Try every slot of `kind` in the image against every presented
/// anchor of that kind until one unwraps. Backup factors share a
/// kind, so a presented factor legitimately fails the slots that
/// are not its own — iteration continues past individual failures
/// and only the aggregate class is reported.
fn unwrap_any_of_kind(
    claims: &ImageClaims,
    anchors: &[&dyn KeyCustodyAnchor],
    kind: AnchorKind,
) -> UnwrapOutcome {
    let mut log = AttemptLog::default();
    for record in claims.slots.iter().filter(|r| r.kind == kind) {
        for anchor in anchors.iter().filter(|a| a.kind() == kind) {
            match anchor.unwrap(
                &UnwrapCtx {
                    sms_epoch: claims.sms_epoch,
                },
                &record.wrapped(),
            ) {
                Ok(secret) => return UnwrapOutcome::Secret(secret),
                Err(AnchorError::Refused) => log.refused = true,
                Err(AnchorError::Unavailable) => log.unavailable = true,
                Err(AnchorError::Failed) => log.failed = true,
            }
        }
    }
    if log.failed {
        UnwrapOutcome::Failed
    } else if log.refused {
        UnwrapOutcome::Refused
    } else if log.unavailable {
        UnwrapOutcome::Unavailable
    } else {
        // No (slot, anchor) pair of this kind existed at all.
        UnwrapOutcome::NoAnchor
    }
}

/// Open an image under its **recorded** policy (design §10.3),
/// driving whichever anchors the resume environment presents.
/// This is the policy layer above P4's image-level enforcement:
/// the image's slot set must first *realize* its recorded level
/// under [`validate_slot_set`] — an image whose only satisfiable
/// path is weaker than its recorded level refuses here, before
/// any anchor is invoked — and then the level's factor plan must
/// be satisfied in full (composition needs both shares; recovery
/// slots are the only alternates, and only because they were
/// enrolled and recorded at seal time).
///
/// Error discipline mirrors the service's: once any unwrap
/// succeeds, the outcome is decided by the header seal alone
/// (`AuthenticationFailed` on tamper — no shopping across factors
/// for a better answer); if no path yields a secret, the reported
/// class is the aggregate of the anchor failures, with
/// [`ServiceError::PolicyMismatch`] for a slot set that does not
/// realize its recorded level and [`ServiceError::SlotNotFound`]
/// when a required factor kind was never presented.
pub fn open_with_policy(
    store: &dyn ImageStore,
    anchors: &[&dyn KeyCustodyAnchor],
) -> Result<OpenedImage, ServiceError> {
    let claims = parse_claims(store)?;
    if claims.policy.level == PolicyLevel::Off {
        // Recorded OFF governs: the published derivation opens it,
        // whatever the machine's current configuration says.
        return open_with_sms(store, claims, &off_policy_sms());
    }
    validate_slot_set(claims.policy.level, &claims.slots)
        .map_err(|_| ServiceError::PolicyMismatch)?;
    let plan = factor_plan(&claims.policy, &claims.slots);
    let mut log = AttemptLog::default();

    // Primary path.
    let primary = match plan {
        FactorPlan::PublishedOff => unreachable!("OFF returned above"),
        FactorPlan::AnyOf { kind, .. } => {
            let outcome = unwrap_any_of_kind(&claims, anchors, kind);
            match outcome {
                UnwrapOutcome::Secret(sms) => Some(sms),
                other => {
                    log.record(&other);
                    None
                }
            }
        }
        FactorPlan::Composition { .. } => {
            let token = unwrap_any_of_kind(&claims, anchors, AnchorKind::Token);
            let tpm = unwrap_any_of_kind(&claims, anchors, AnchorKind::Tpm);
            match (token, tpm) {
                (UnwrapOutcome::Secret(a), UnwrapOutcome::Secret(b)) => Some(a.with_bytes(|x| {
                    b.with_bytes(|y| {
                        let mut out = [0u8; 32];
                        for i in 0..32 {
                            out[i] = x[i] ^ y[i];
                        }
                        Secret32::mint(out)
                    })
                })),
                (a, b) => {
                    log.record(&a);
                    log.record(&b);
                    None
                }
            }
        }
    };
    if let Some(sms) = primary {
        return open_with_sms(store, claims, &sms);
    }

    // Recovery path: an enrolled passphrase slot, when the plan
    // carries one. Deliberate at enrollment, recorded in the
    // image — the only alternate path the design contains.
    let recovery = match plan {
        FactorPlan::AnyOf { recovery, .. } | FactorPlan::Composition { recovery } => recovery,
        FactorPlan::PublishedOff => false,
    };
    if recovery {
        match unwrap_any_of_kind(&claims, anchors, AnchorKind::Passphrase) {
            UnwrapOutcome::Secret(sms) => return open_with_sms(store, claims, &sms),
            other => log.record(&other),
        }
    }
    Err(log.error())
}

/// A set of custody factors offered to an enrollment flow, bucketed
/// by the kind each bucket must contain (a bucket member whose
/// `kind()` disagrees is a caller error — [`PolicyError::
/// Unsatisfiable`] — not a slot the flow will silently misfile).
pub struct FactorSet<'a> {
    pub tokens: Vec<&'a dyn KeyCustodyAnchor>,
    pub tpms: Vec<&'a dyn KeyCustodyAnchor>,
    pub passphrases: Vec<&'a dyn KeyCustodyAnchor>,
}

impl FactorSet<'_> {
    fn check_kinds(&self) -> Result<(), PolicyError> {
        let ok = self.tokens.iter().all(|a| a.kind() == AnchorKind::Token)
            && self.tpms.iter().all(|a| a.kind() == AnchorKind::Tpm)
            && self
                .passphrases
                .iter()
                .all(|a| a.kind() == AnchorKind::Passphrase);
        if ok {
            Ok(())
        } else {
            Err(PolicyError::Unsatisfiable)
        }
    }
}

/// Fresh-install provisioning (decision 4 + decision 2): the
/// factors in hand, the floor to provision, and the recovery
/// opt-out (the default is ON for this first epoch — opting out
/// is the explicit act, never the silent one).
pub struct FreshInstall<'a> {
    pub factors: FactorSet<'a>,
    pub floor: PolicyLevel,
    pub recovery_opt_out: bool,
    /// Explicit token-verification choice; `None` takes the
    /// decided default for the computed level.
    pub token_verification: Option<TokenVerification>,
}

/// A level change (design §10.4: changing levels = re-enrollment,
/// a fresh SMS epoch under the new factor set; existing images
/// keep their recorded policy and their epoch's retained slots).
pub struct PolicyChange<'a> {
    pub level: PolicyLevel,
    pub factors: FactorSet<'a>,
    /// Required iff `level` is OFF (decision 3).
    pub off_confirmation: Option<OffConfirmation>,
    /// Include the change's passphrase factors as recovery slots;
    /// `None` takes the standing [`PolicyConfig::
    /// recovery_slot_default`].
    pub include_recovery: Option<bool>,
    /// Explicit token-verification choice; `None` takes the
    /// decided default when the new level involves tokens, else
    /// keeps the current setting.
    pub token_verification: Option<TokenVerification>,
}

/// Rotate the service to a fresh SMS epoch realizing `level` over
/// `factors` — the shared core of level changes and same-level
/// re-enrollment. OFF rotates nothing (OFF images are written
/// under the published derivation; the retained epochs keep
/// serving their recorded images).
fn rotate_for_level<E: KeyEntropy>(
    svc: &mut SuspendService<E>,
    level: PolicyLevel,
    factors: &FactorSet<'_>,
    include_recovery: bool,
) -> Result<(), PolicyError> {
    factors.check_kinds()?;
    match level {
        PolicyLevel::Off => Ok(()),
        PolicyLevel::Passphrase => {
            if factors.passphrases.is_empty() {
                return Err(PolicyError::Unsatisfiable);
            }
            svc.rotate_epoch(&factors.passphrases)?;
            Ok(())
        }
        PolicyLevel::Token => {
            if factors.tokens.len() < 2 {
                return Err(PolicyError::Unsatisfiable);
            }
            let mut all: Vec<&dyn KeyCustodyAnchor> = factors.tokens.clone();
            if include_recovery {
                all.extend(factors.passphrases.iter().copied());
            }
            svc.rotate_epoch(&all)?;
            Ok(())
        }
        PolicyLevel::Tpm => {
            if factors.tpms.is_empty() {
                return Err(PolicyError::Unsatisfiable);
            }
            let mut all: Vec<&dyn KeyCustodyAnchor> = factors.tpms.clone();
            if include_recovery {
                all.extend(factors.passphrases.iter().copied());
            }
            svc.rotate_epoch(&all)?;
            Ok(())
        }
        PolicyLevel::TokenTpm => {
            if factors.tokens.len() < 2 || factors.tpms.is_empty() {
                return Err(PolicyError::Unsatisfiable);
            }
            svc.rotate_epoch_composition(&factors.tokens, &factors.tpms)?;
            if include_recovery {
                for anchor in &factors.passphrases {
                    svc.enroll(anchor)?;
                }
            }
            Ok(())
        }
    }
}

/// The policy store: the running system's [`PolicyConfig`] plus
/// the flows that administer it (design §10.2 — policy changes
/// happen only here, in a running authenticated system, and take
/// effect for future suspends). The store itself holds no secret;
/// SMS custody never leaves the [`SuspendService`] it drives.
#[derive(Debug, Default)]
pub struct PolicyStore {
    config: Option<PolicyConfig>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self { config: None }
    }

    /// The current config, if the machine is provisioned.
    pub fn config(&self) -> Option<&PolicyConfig> {
        self.config.as_ref()
    }

    /// The policy record an image sealed now would carry.
    pub fn recorded_policy(&self) -> Result<RecordedPolicy, PolicyError> {
        self.config
            .as_ref()
            .map(PolicyConfig::recorded)
            .ok_or(PolicyError::NoPolicy)
    }

    /// Provision a fresh install (decisions 2 + 4): compute the
    /// default level from the tokens in hand, enroll the factors
    /// into the service's first SMS epoch, and record the config.
    /// If an anchor fails mid-enrollment the error propagates and
    /// no config is recorded (the partially enrolled epoch stays
    /// in the service, holding wraps under the factors that did
    /// enroll — a reboot or epoch retirement is the remedy, and no
    /// image can have been sealed under an unrecorded policy).
    /// With fewer than two tokens the level is PASSPHRASE and the
    /// tokens are *not* enrolled — a sub-mandate token set cannot
    /// realize any token level, and dead slots under a passphrase
    /// image would only confuse the shape rules; the tokens enroll
    /// later, when a second arrives, via [`Self::change_level`].
    pub fn provision_fresh_install<E: KeyEntropy>(
        &mut self,
        svc: &mut SuspendService<E>,
        install: FreshInstall<'_>,
    ) -> Result<RecordedPolicy, PolicyError> {
        if self.config.is_some() || svc.current_epoch().is_some() {
            return Err(PolicyError::AlreadyProvisioned);
        }
        install.factors.check_kinds()?;
        let level = fresh_install_default(install.factors.tokens.len());
        if !floor_satisfied(level, install.floor) {
            return Err(PolicyError::BelowFloor {
                level,
                floor: install.floor,
            });
        }
        match level {
            PolicyLevel::Token => {
                svc.create_epoch()?;
                for anchor in &install.factors.tokens {
                    svc.enroll(anchor)?;
                }
                // Decision 2: the recovery slot defaults ON for
                // the first epoch; opting out is the explicit act.
                if !install.recovery_opt_out {
                    for anchor in &install.factors.passphrases {
                        svc.enroll(anchor)?;
                    }
                }
            }
            PolicyLevel::Passphrase => {
                if install.factors.passphrases.is_empty() {
                    return Err(PolicyError::Unsatisfiable);
                }
                svc.create_epoch()?;
                for anchor in &install.factors.passphrases {
                    svc.enroll(anchor)?;
                }
            }
            _ => unreachable!("fresh-install default is Token or Passphrase"),
        }
        self.validate_current_against(svc, level)?;
        let config = PolicyConfig {
            level,
            floor: install.floor,
            policy_epoch: 1,
            token_verification: install
                .token_verification
                .unwrap_or_else(|| default_token_verification(level)),
            recovery_slot_default: !install.recovery_opt_out,
            token_absent: TokenAbsent::Defer,
        };
        self.config = Some(config);
        Ok(config.recorded())
    }

    /// Change the policy level (design §10.4): floor and OFF
    /// rules first, then re-enrollment under the new factor set,
    /// then the config advances (policy epoch +1). Existing images
    /// are untouched: their epochs' slots stay retained and their
    /// recorded policies keep governing them.
    pub fn change_level<E: KeyEntropy>(
        &mut self,
        svc: &mut SuspendService<E>,
        change: PolicyChange<'_>,
    ) -> Result<RecordedPolicy, PolicyError> {
        let current = self.config.ok_or(PolicyError::NoPolicy)?;
        if change.level == current.level {
            return Err(PolicyError::Unchanged);
        }
        if !floor_satisfied(change.level, current.floor) {
            return Err(PolicyError::BelowFloor {
                level: change.level,
                floor: current.floor,
            });
        }
        if change.level == PolicyLevel::Off && change.off_confirmation.is_none() {
            return Err(PolicyError::OffNotConfirmed);
        }
        let include_recovery = change
            .include_recovery
            .unwrap_or(current.recovery_slot_default);
        if change.level != PolicyLevel::Off {
            rotate_for_level(svc, change.level, &change.factors, include_recovery)?;
            self.validate_current_against(svc, change.level)?;
        }
        let config = PolicyConfig {
            level: change.level,
            floor: current.floor,
            policy_epoch: current.policy_epoch + 1,
            token_verification: match change.token_verification {
                Some(v) => v,
                None => match change.level {
                    PolicyLevel::Token | PolicyLevel::TokenTpm => {
                        default_token_verification(change.level)
                    }
                    _ => current.token_verification,
                },
            },
            recovery_slot_default: current.recovery_slot_default,
            token_absent: current.token_absent,
        };
        self.config = Some(config);
        Ok(config.recorded())
    }

    /// Re-enroll the *current* level under a fresh SMS epoch
    /// (design §8.3's documented remedy after a firmware update
    /// changes the PCRs, and the general token-churn path of
    /// §4.9): the level and policy epoch do not move; the factor
    /// set is re-wrapped whole. The factors provided are the
    /// admin's intent — recovery passphrases provided here enroll
    /// as recovery slots.
    pub fn reenroll<E: KeyEntropy>(
        &mut self,
        svc: &mut SuspendService<E>,
        factors: FactorSet<'_>,
    ) -> Result<RecordedPolicy, PolicyError> {
        let current = self.config.ok_or(PolicyError::NoPolicy)?;
        if current.level != PolicyLevel::Off {
            rotate_for_level(svc, current.level, &factors, true)?;
            self.validate_current(svc)?;
        }
        Ok(current.recorded())
    }

    /// Enroll (or replace) the passphrase recovery slot on the
    /// current epoch (decision 2 beyond the first epoch, design
    /// §4.9's recovery path). Meaningless — and refused — under
    /// OFF (no slots exist) and PASSPHRASE (passphrases there are
    /// the primary factor, enrolled by the level flows).
    pub fn enroll_recovery<E: KeyEntropy>(
        &mut self,
        svc: &mut SuspendService<E>,
        anchor: &dyn KeyCustodyAnchor,
    ) -> Result<SlotRecord, PolicyError> {
        let current = self.config.ok_or(PolicyError::NoPolicy)?;
        if matches!(current.level, PolicyLevel::Off | PolicyLevel::Passphrase)
            || anchor.kind() != AnchorKind::Passphrase
        {
            return Err(PolicyError::Unsatisfiable);
        }
        Ok(svc.enroll(anchor)?)
    }

    /// Raise or lower the admin floor. A floor the *current* level
    /// would violate is refused — the floor constrains the future,
    /// it does not retroactively criminalize the present config.
    pub fn set_floor(&mut self, floor: PolicyLevel) -> Result<(), PolicyError> {
        let config = self.config.as_mut().ok_or(PolicyError::NoPolicy)?;
        if !floor_satisfied(config.level, floor) {
            return Err(PolicyError::BelowFloor {
                level: config.level,
                floor,
            });
        }
        config.floor = floor;
        Ok(())
    }

    /// Set the resume behaviour for an absent token factor
    /// (design §4.9's advance-configured choice).
    pub fn set_token_absent(&mut self, behaviour: TokenAbsent) -> Result<(), PolicyError> {
        let config = self.config.as_mut().ok_or(PolicyError::NoPolicy)?;
        config.token_absent = behaviour;
        Ok(())
    }

    /// Check the service's current epoch realizes the configured
    /// level — the enrollment-side composition rule, and the
    /// diagnostic an admin tool runs after manual slot surgery
    /// (revoke a token and a TOKEN level stops validating until a
    /// replacement enrolls; sealing refuses until it does).
    pub fn validate_current<E: KeyEntropy>(
        &self,
        svc: &SuspendService<E>,
    ) -> Result<(), PolicyError> {
        let current = self.config.ok_or(PolicyError::NoPolicy)?;
        self.validate_current_against(svc, current.level)
    }

    fn validate_current_against<E: KeyEntropy>(
        &self,
        svc: &SuspendService<E>,
        level: PolicyLevel,
    ) -> Result<(), PolicyError> {
        if level == PolicyLevel::Off {
            // OFF has no slot requirements (and any retained slots
            // belong to earlier epochs' images, not to OFF).
            return Ok(());
        }
        let epoch = svc
            .current_epoch()
            .ok_or(PolicyError::Service(ServiceError::NoEpoch))?;
        let area = svc.slot_area();
        let slots = area
            .records_for(epoch)
            .ok_or(PolicyError::Service(ServiceError::UnknownEpoch))?;
        validate_slot_set(level, slots)
    }

    /// Seal an image under the current policy — the only seal
    /// entry the running system should use: the current epoch's
    /// slot set is validated against the configured level first,
    /// so a machine can never write an image whose recorded level
    /// its own slots do not realize.
    pub fn seal<E: KeyEntropy>(
        &self,
        svc: &mut SuspendService<E>,
        store: &mut dyn ImageStore,
        image: &[u8],
    ) -> Result<[u8; 16], PolicyError> {
        let current = self.config.ok_or(PolicyError::NoPolicy)?;
        if current.level != PolicyLevel::Off {
            self.validate_current(svc)?;
        }
        Ok(svc.seal_image(store, current.recorded(), image)?)
    }
}

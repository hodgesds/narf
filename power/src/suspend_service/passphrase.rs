//! The Argon2id passphrase anchor — the suspend floor
//! (power-suspend design §9, lane P7, issue #1004).
//!
//! The floor is the factor path that must work with **no token
//! and no machine anchor**: identical image, identical service,
//! only the SMS unwrap differs (design §3.1). The passphrase is
//! also a first-class enrolled factor at every other level: any
//! policy may carry a passphrase *recovery slot* (design §10.1),
//! and per the DECIDED enrollment policy (2026-10-26) that slot
//! is offered at enrollment and defaults ON for the first epoch
//! — the enrollment *offer* is policy-layer UX (P8, #1006); this
//! module is the mechanism it offers: enroll, change, unwrap.
//!
//! Construction (design §9.1):
//!
//! ```text
//! salt        = 32B random per passphrase slot, stored in the slot record
//! KEK_pass    = Argon2id(passphrase, salt, params)          // 32B output
//! slot record = { salt, argon2 params, AEAD-wrap_KEK_pass(SMS) }
//! ```
//!
//! The KDF is Argon2id (version 0x13) via the `argon2` crate the
//! workspace already depends on for LUKS2 (`block/src/luks2.rs`),
//! with the parameter policy below. The wrap AEAD is the tree's
//! ChaCha20-Poly1305, with the epoch and the slot's full public
//! parameter block bound as AAD — tampering with the recorded
//! parameters therefore fails the AEAD even when the tamper
//! stays inside the accepted parameter window.
//!
//! Parameter discipline (design §9.1 + the LUKS2 cap pattern):
//! the operating point targets ~2 s of wall time at resume with
//! memory fixed at 512 MiB and 4 lanes; the time cost is what
//! enrollment calibration adjusts ([`calibrate_time_cost`]).
//! Recorded parameters are the derivation input at unwrap — a
//! slot enrolled on one machine unwraps on another (design
//! §9.2: the floor has no hardware binding) — but only inside
//! the anchor's [`PassphrasePolicy`] window. A slot whose
//! recorded parameters fall outside the window (above the caps:
//! a memory/CPU exhaustion attack on the resume environment;
//! below the floors: a KDF downgrade) is refused *before* the
//! passphrase is even requested and before any KDF work runs.
//! The caps mirror `Luks2UnlockPolicy`'s defaults in
//! `block/src/luks2.rs` (1 GiB / 16 passes / 64 lanes).
//!
//! Failure discipline: a wrong passphrase and a tampered blob
//! are the same error (`AnchorError::Failed` from the AEAD);
//! the resume environment collapses that into its single
//! `AuthenticationFailed` class (design §6.2, P4), so neither
//! layer is an oracle for *which* check failed. Secret material
//! (the passphrase, the derived KEK) lives in `Zeroizing`
//! custody for exactly the derivation's duration; no secret is
//! ever compared by hand in this module — the only equality that
//! decides anything is the AEAD tag check inside `narf-crypto`.
//!
//! Prompt discipline (design §9.4): the passphrase is obtained
//! through the [`PassphraseSource`] seam inside `unwrap`, i.e.
//! inside the resume attempt P4's `attempt_resume` drives, so
//! the `ResumePrompt` lines keep their order — the claimed
//! policy announced as an attempt first, facts only after
//! verification. [`resume_with_passphrase`] adds the floor's
//! retry discipline around the attempt: exponential backoff
//! (1 s, 2 s, 4 s, … capped at 60 s), the attempt count held in
//! RAM only (it dies with the attempt loop; persisting it would
//! let an attacker reset it, and the design does not pretend
//! otherwise), and after 10 refusals the environment announces
//! the cold-boot offer — image retained — instead of looping.
//!
//! The §9.3 UEFI-variable combiner is implemented as an anchor
//! option, default off: when enabled, the wrap/unwrap KEK is
//! `HKDF(KEK_pass ‖ machine_secret)`, the slot record carries a
//! combiner flag, and a combiner slot refuses on a machine that
//! does not present the secret. Provisioning and reading the
//! UEFI variable itself is platform integration (the running
//! system reads it and hands the secret to the anchor's
//! constructor, exactly as it will at resume); the design's
//! labelling stands — it binds the image to this machine's
//! firmware flash, not to its boot chain.

use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroizing;

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};

use super::anchor::{AnchorError, AnchorKind, KeyCustodyAnchor, UnwrapCtx, WrapCtx, WrappedSlot};
use super::custody::Secret32;
use super::entropy::KeyEntropy;
use super::format::ImageStore;
use super::resume::{attempt_resume, ResumePrompt};
use super::slots::SlotRecord;
use super::{ResumeRefusal, ServiceError, SuspendService, VerifiedResume};

/// Longest passphrase the anchor accepts, in bytes. The console
/// source enforces the same cap while reading; the anchor
/// enforces it for every source, so a broken or hostile source
/// cannot hand the KDF an unbounded input.
pub const MAX_PASSPHRASE_LEN: usize = 1024;

/// Salt length per slot (design §9.1: 32B random per slot).
pub const PASSPHRASE_SALT_LEN: usize = 32;

/// Failed passphrase attempts the resume driver tolerates before
/// offering cold boot (design §9.4). The count is RAM-only by
/// design; see [`resume_with_passphrase`].
pub const MAX_RESUME_PASSPHRASE_FAILURES: u32 = 10;

/// Argon2id cost parameters for one slot. The version is not a
/// field: this build implements Argon2 version 0x13 only
/// (RFC 9106), and a slot record carries no version negotiation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost, in KiB (Argon2 `m_cost`).
    pub memory_kib: u32,
    /// Passes over memory (Argon2 `t_cost`).
    pub time_cost: u32,
    /// Parallel lanes (Argon2 `p_cost`).
    pub lanes: u32,
}

impl Argon2idParams {
    /// The design §9.1 operating point before calibration:
    /// memory fixed at 512 MiB, 4 lanes, time cost 3 as the
    /// starting value enrollment calibration adjusts toward the
    /// ~2 s target ([`calibrate_time_cost`]).
    pub const DESIGN_DEFAULT: Self = Self {
        memory_kib: 512 * 1024,
        time_cost: 3,
        lanes: 4,
    };
}

/// The accepted parameter window for slots this anchor will
/// unwrap (and the bounds its own operating point must satisfy
/// at enrollment). Recorded parameters outside the window are
/// refused before any KDF work — see the module docs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PassphrasePolicy {
    pub min_memory_kib: u32,
    pub max_memory_kib: u32,
    pub min_time_cost: u32,
    pub max_time_cost: u32,
    pub min_lanes: u32,
    pub max_lanes: u32,
}

impl PassphrasePolicy {
    /// The production window. Caps mirror the LUKS2 unlock
    /// policy defaults (`Luks2UnlockPolicy` in
    /// `block/src/luks2.rs`): 1 GiB of Argon2 memory, 16 passes,
    /// 64 lanes — the most KDF work one resume attempt may be
    /// made to do by untrusted slot bytes. Floors are the
    /// anti-downgrade side: 16 MiB / 1 pass / 1 lane is already
    /// far below the design operating point; anything weaker is
    /// not a slot this build honours.
    pub fn production() -> Self {
        Self {
            min_memory_kib: 16 * 1024,
            max_memory_kib: 1024 * 1024,
            min_time_cost: 1,
            max_time_cost: 16,
            min_lanes: 1,
            max_lanes: 64,
        }
    }

    /// Whether `params` lies inside the window (all bounds
    /// inclusive; parameters are public data — this check is
    /// not a secret comparison).
    pub fn accepts(&self, params: &Argon2idParams) -> bool {
        params.memory_kib >= self.min_memory_kib
            && params.memory_kib <= self.max_memory_kib
            && params.time_cost >= self.min_time_cost
            && params.time_cost <= self.max_time_cost
            && params.lanes >= self.min_lanes
            && params.lanes <= self.max_lanes
    }
}

// ── The KDF ──────────────────────────────────────────────────────

/// Argon2id (version 0x13, RFC 9106) as a 32-byte key
/// derivation: the one KDF entry point both the anchor and the
/// RFC-vector fixture use, so the fixture validates the exact
/// code production runs. `secret` and `associated_data` are the
/// RFC's optional K/X inputs — production slot derivation
/// passes `None` for both (the LUKS2-shaped construction of
/// design §9.1 has neither); they exist so the RFC 9106 §5.3
/// vector, which exercises both, runs through this function
/// unchanged.
pub fn argon2id_kdf(
    password: &[u8],
    salt: &[u8],
    params: Argon2idParams,
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, AnchorError> {
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.time_cost)
        .p_cost(params.lanes)
        .output_len(32);
    if let Some(ad) = associated_data {
        let ad = argon2::AssociatedData::new(ad).map_err(|_| AnchorError::Failed)?;
        builder.data(ad);
    }
    let argon_params = builder.build().map_err(|_| AnchorError::Failed)?;
    let argon = match secret {
        Some(secret) => argon2::Argon2::new_with_secret(
            secret,
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        )
        .map_err(|_| AnchorError::Failed)?,
        None => argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        ),
    };
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut *out)
        .map_err(|_| AnchorError::Failed)?;
    Ok(out)
}

/// Choose the time cost for `base` so one derivation lands at
/// the design §9.1 target (~2 s) on this machine: probe one
/// derivation at `time_cost = 1` through `measure` (returns the
/// measured wall time in milliseconds for the given params),
/// then scale linearly, clamped to the policy window.
/// Calibration runs at enrollment, in the running system;
/// the result is what gets recorded in the slot record.
pub fn calibrate_time_cost(
    base: Argon2idParams,
    policy: &PassphrasePolicy,
    target_millis: u64,
    measure: &mut dyn FnMut(Argon2idParams) -> u64,
) -> Argon2idParams {
    let mut probe = base;
    probe.time_cost = 1;
    let one_pass = measure(probe);
    let time_cost = if one_pass == 0 || one_pass >= target_millis {
        1
    } else {
        (target_millis / one_pass) as u32
    };
    let mut out = base;
    out.time_cost = time_cost.clamp(policy.min_time_cost.max(1), policy.max_time_cost);
    out
}

// ── Slot parameter block (the anchor's `params` payload) ────────

/// Version byte of the parameter-block framing below. A future
/// framing change bumps it; this build parses version 1 only
/// and refuses anything else (a slot this build cannot read is
/// a slot it must not use).
const PARAMS_VERSION: u8 = 1;
/// Flag bit: the §9.3 UEFI combiner was applied to this slot.
const PARAMS_FLAG_COMBINER: u8 = 0x01;
/// version ‖ flags ‖ memory ‖ time ‖ lanes ‖ salt.
const PARAMS_LEN: usize = 1 + 1 + 4 + 4 + 4 + PASSPHRASE_SALT_LEN;

struct SlotParams {
    params: Argon2idParams,
    combiner: bool,
    salt: [u8; PASSPHRASE_SALT_LEN],
}

impl SlotParams {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARAMS_LEN);
        out.push(PARAMS_VERSION);
        out.push(if self.combiner {
            PARAMS_FLAG_COMBINER
        } else {
            0
        });
        out.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.params.time_cost.to_le_bytes());
        out.extend_from_slice(&self.params.lanes.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// Strict parse: exact length, known version, no unknown
    /// flag bits. Anything else is `Failed` — at the anchor
    /// boundary a malformed slot and a hostile slot are the
    /// same class.
    fn decode(bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() != PARAMS_LEN || bytes[0] != PARAMS_VERSION {
            return Err(AnchorError::Failed);
        }
        let flags = bytes[1];
        if flags & !PARAMS_FLAG_COMBINER != 0 {
            return Err(AnchorError::Failed);
        }
        let u32_at = |off: usize| {
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
        };
        let mut salt = [0u8; PASSPHRASE_SALT_LEN];
        salt.copy_from_slice(&bytes[14..PARAMS_LEN]);
        Ok(Self {
            params: Argon2idParams {
                memory_kib: u32_at(2),
                time_cost: u32_at(6),
                lanes: u32_at(10),
            },
            combiner: flags & PARAMS_FLAG_COMBINER != 0,
            salt,
        })
    }
}

/// The wrap AAD: binds the slot to its SMS epoch and to its
/// full recorded parameter block, so any post-hoc edit of the
/// public parameters fails the AEAD open.
fn wrap_aad(sms_epoch: u64, params_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + params_bytes.len());
    aad.extend_from_slice(b"narf-suspend/passphrase-slot");
    aad.extend_from_slice(&sms_epoch.to_le_bytes());
    aad.extend_from_slice(params_bytes);
    aad
}

// ── Passphrase entry seam ───────────────────────────────────────

/// Where the anchor gets the passphrase for one wrap/unwrap.
/// Called once per operation; the returned bytes are held in
/// `Zeroizing` custody by the anchor and wiped when the
/// derivation completes. Implementations are the enrollment
/// prompt (running system) and the resume prompt (early
/// environment) — the seam is what lets fixtures script both.
pub trait PassphraseSource: Send + Sync {
    /// Obtain the passphrase for one attempt. `Err(Refused)`
    /// is "no passphrase was entered" (abort, empty entry);
    /// it is deliberately the same class the resume layer
    /// already collapses.
    fn obtain(&self) -> Result<Zeroizing<Vec<u8>>, AnchorError>;
}

/// Production source for the resume environment: the early
/// console (design §9.4). Emits the prompt with no newline,
/// reads bytes via `narf_console::try_read_byte` until CR/LF,
/// echoes nothing, and caps the entry at
/// [`MAX_PASSPHRASE_LEN`] (an overlong entry is consumed to
/// end-of-line, then refused, so the console state stays
/// sane). Polling is unbounded by design — a human at a
/// console may take minutes; the §4.9 "defer" outcome is the
/// operator's cold boot, not a timeout here.
#[derive(Debug)]
pub struct ConsolePassphraseSource;

impl PassphraseSource for ConsolePassphraseSource {
    fn obtain(&self) -> Result<Zeroizing<Vec<u8>>, AnchorError> {
        narf_console::write_str("power: enter the suspend passphrase: ");
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut overlong = false;
        loop {
            let Some(byte) = narf_console::try_read_byte() else {
                core::hint::spin_loop();
                continue;
            };
            match byte {
                b'\r' | b'\n' => break,
                0x03 => return Err(AnchorError::Refused), // Ctrl-C: abort
                0x7f | 0x08 => {
                    buf.pop();
                }
                0x20..=0x7e => {
                    if buf.len() < MAX_PASSPHRASE_LEN {
                        buf.push(byte);
                    } else {
                        overlong = true;
                    }
                }
                _ => {} // other control bytes are ignored, never echoed
            }
        }
        narf_console::write_str("\n");
        if overlong || buf.is_empty() {
            return Err(AnchorError::Refused);
        }
        Ok(buf)
    }
}

// ── The anchor ──────────────────────────────────────────────────

/// The passphrase custody anchor (design §9). Generic over
/// the entropy seam (salt generation — the same fail-closed
/// surface the service draws key material from) and the
/// passphrase source (enrollment prompt / resume prompt /
/// fixture script).
///
/// The §9.3 combiner is a constructor decision: with
/// `combiner_secret` present, wraps apply the combiner and
/// record the flag; unwraps of combiner slots require the
/// same secret present again. Default off — construct with
/// [`PassphraseAnchor::new`] for the plain floor.
pub struct PassphraseAnchor<E: KeyEntropy, S: PassphraseSource> {
    entropy: E,
    source: S,
    policy: PassphrasePolicy,
    params: Argon2idParams,
    combiner_secret: Option<Zeroizing<[u8; 32]>>,
}

impl<E: KeyEntropy, S: PassphraseSource> fmt::Debug for PassphraseAnchor<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The combiner secret is custody material: its
        // presence is state, its bytes are never printed.
        f.debug_struct("PassphraseAnchor")
            .field("params", &self.params)
            .field("policy", &self.policy)
            .field("combiner", &self.combiner_secret.is_some())
            .finish_non_exhaustive()
    }
}

impl<E: KeyEntropy, S: PassphraseSource> PassphraseAnchor<E, S> {
    /// A plain passphrase anchor (combiner off) with the
    /// given operating point. The operating point must lie
    /// inside `policy` — enrollment with out-of-window
    /// parameters refuses rather than minting a slot no
    /// resume environment would honour.
    pub fn new(entropy: E, source: S, policy: PassphrasePolicy, params: Argon2idParams) -> Self {
        Self {
            entropy,
            source,
            policy,
            params,
            combiner_secret: None,
        }
    }

    /// Enable the §9.3 UEFI combiner with the machine secret
    /// the platform provisioned/read. The secret itself never
    /// enters the slot record — only the flag does.
    pub fn with_combiner(mut self, machine_secret: [u8; 32]) -> Self {
        self.combiner_secret = Some(Zeroizing::new(machine_secret));
        self
    }

    /// The anchor's operating point (what `wrap` records).
    pub fn params(&self) -> Argon2idParams {
        self.params
    }

    fn draw(&self, out: &mut [u8]) -> Result<(), AnchorError> {
        if !self.entropy.has_seed_grade() {
            return Err(AnchorError::Unavailable);
        }
        self.entropy
            .fill_key_material(out)
            .map_err(|_| AnchorError::Unavailable)
    }

    /// Derive the slot KEK: Argon2id over the recorded (at
    /// unwrap) or operating (at wrap) parameters, then the
    /// §9.3 combiner where it applies —
    /// `HKDF(KEK_pass ‖ machine_secret)`.
    fn derive_kek(
        &self,
        passphrase: &[u8],
        slot: &SlotParams,
        combiner_secret: Option<&[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, AnchorError> {
        let kek_pass = argon2id_kdf(passphrase, &slot.salt, slot.params, None, None)?;
        match (slot.combiner, combiner_secret) {
            (false, _) => Ok(kek_pass),
            (true, Some(secret)) => {
                let mut ikm = Zeroizing::new(Vec::with_capacity(64));
                ikm.extend_from_slice(&*kek_pass);
                ikm.extend_from_slice(secret);
                let prk = hkdf_extract(None, &ikm);
                let okm = hkdf_expand(&prk, b"narf-suspend/passphrase-combiner", 32);
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&okm);
                Ok(out)
            }
            (true, None) => Err(AnchorError::Refused),
        }
    }
}

impl<E: KeyEntropy + Send + Sync, S: PassphraseSource> KeyCustodyAnchor for PassphraseAnchor<E, S> {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Passphrase
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        if !self.policy.accepts(&self.params) {
            return Err(AnchorError::Refused);
        }
        let combiner = self.combiner_secret.is_some();
        let passphrase = self.source.obtain()?;
        if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_LEN {
            return Err(AnchorError::Refused);
        }
        let mut salt = [0u8; PASSPHRASE_SALT_LEN];
        self.draw(&mut salt)?;
        let mut nonce = [0u8; 12];
        self.draw(&mut nonce)?;
        let slot = SlotParams {
            params: self.params,
            combiner,
            salt,
        };
        let params_bytes = slot.encode();
        let kek = self.derive_kek(&passphrase, &slot, self.combiner_secret.as_deref())?;
        let aad = wrap_aad(ctx.sms_epoch, &params_bytes);
        let mut ct = [0u8; 32];
        secret.with_bytes(|s| ct.copy_from_slice(s));
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::with_capacity(12 + 32 + 16);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        Ok(WrappedSlot {
            params: params_bytes,
            blob,
        })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        let parsed = SlotParams::decode(&slot.params)?;
        // The window check runs before the passphrase is
        // requested and before any KDF work: out-of-window
        // recorded parameters are refused, never re-derived
        // at (module docs: exhaustion attack above the caps,
        // downgrade below the floors).
        if !self.policy.accepts(&parsed.params) {
            return Err(AnchorError::Refused);
        }
        if parsed.combiner && self.combiner_secret.is_none() {
            return Err(AnchorError::Refused);
        }
        if slot.blob.len() != 12 + 32 + 16 {
            return Err(AnchorError::Failed);
        }
        let passphrase = self.source.obtain()?;
        if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_LEN {
            return Err(AnchorError::Refused);
        }
        let kek = self.derive_kek(&passphrase, &parsed, self.combiner_secret.as_deref())?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&slot.blob[..12]);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&slot.blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&slot.blob[44..]);
        let aad = wrap_aad(ctx.sms_epoch, &slot.params);
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            // Wrong passphrase, wrong combiner secret, or a
            // tampered blob/parameter block: one class, by
            // design (no oracle).
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

// ── Passphrase change (running system) ──────────────────────────

/// Change the passphrase on an enrolled slot (design §10.4:
/// changing a factor re-wraps under the same SMS epoch — no
/// rotation, the SMS does not change when a factor's secret
/// does). The flow proves knowledge of the *current*
/// passphrase first (the old anchor must unwrap the existing
/// record), then enrolls the replacement slot, and only then
/// revokes the old record — a failure anywhere leaves the old
/// slot in place, never zero passphrase slots mid-change.
///
/// `old_params` identifies the record to replace (slot
/// identity is (epoch, kind, params), per the service's
/// revoke semantics — two passphrase slots in one epoch, e.g.
/// a floor slot and a recovery slot, differ by their params).
pub fn change_passphrase<E: KeyEntropy>(
    service: &mut SuspendService<E>,
    old_anchor: &dyn KeyCustodyAnchor,
    old_params: &[u8],
    new_anchor: &dyn KeyCustodyAnchor,
) -> Result<SlotRecord, ServiceError> {
    let epoch = service.current_epoch().ok_or(ServiceError::NoEpoch)?;
    let area = service.slot_area();
    let old_record = area
        .records_for(epoch)
        .and_then(|records| {
            records
                .iter()
                .find(|r| r.kind == AnchorKind::Passphrase && r.params == old_params)
        })
        .ok_or(ServiceError::SlotNotFound)?;
    // Proof of the current passphrase: the old anchor must
    // unwrap the existing record. The unwrapped SMS is the
    // service's own epoch secret coming back through custody —
    // it is dropped (zeroized) immediately; the check is the
    // successful unwrap, not the value.
    let proven = old_anchor.unwrap(&UnwrapCtx { sms_epoch: epoch }, &old_record.wrapped())?;
    drop(proven);
    let new_record = service.enroll(new_anchor)?;
    service.revoke_slot(epoch, AnchorKind::Passphrase, old_params)?;
    Ok(new_record)
}

// ── Resume retry discipline (design §9.4) ───────────────────────

/// The delay between resume attempts. The production
/// implementation spins on the monotonic clock; fixtures
/// record the schedule instead of sleeping.
pub trait ResumeDelay {
    /// Wait `millis` milliseconds.
    fn delay(&mut self, millis: u64);
}

/// Production delay: busy-wait on `narf_time`'s monotonic
/// nanosecond clock (the resume environment has no scheduler
/// to sleep on; the backoff totals at most ~2 minutes across
/// the whole attempt budget). The clock's cycles→ns
/// calibration is boot bring-up state that precedes the
/// resume environment in the boot path.
#[derive(Debug)]
pub struct MonotonicDelay;

impl ResumeDelay for MonotonicDelay {
    fn delay(&mut self, millis: u64) {
        let start = narf_time::monotonic_ns();
        let target = start.saturating_add(millis.saturating_mul(1_000_000));
        while narf_time::monotonic_ns() < target {
            core::hint::spin_loop();
        }
    }
}

/// Backoff after `failures` consecutive refusals: 1 s, 2 s,
/// 4 s, … capped at 60 s (design §9.4).
pub fn backoff_millis(failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(6);
    (1000u64 << shift).min(60_000)
}

/// Drive resume attempts for a passphrase-carrying image
/// under the §9.4 discipline: retry only the factor-refusal
/// class (a wrong passphrase is retryable by a human; a
/// tampered image, a missing slot, and a store failure are
/// not — and the authentication class must never be turned
/// into a retry oracle), back off exponentially between
/// attempts, and after [`MAX_RESUME_PASSPHRASE_FAILURES`]
/// refusals announce the cold-boot offer (image retained)
/// and return the refusal. The attempt count is a local —
/// RAM only, exactly as designed.
pub fn resume_with_passphrase(
    store: &dyn ImageStore,
    anchors: &[&dyn KeyCustodyAnchor],
    prompt: &mut dyn ResumePrompt,
    delay: &mut dyn ResumeDelay,
) -> Result<VerifiedResume, ResumeRefusal> {
    // The retry budget exists to guard passphrase guessing.
    // With no passphrase anchor presented there is nothing to
    // retry — a single attempt, so a token-only image is
    // never stalled behind a pointless backoff ladder.
    if !anchors.iter().any(|a| a.kind() == AnchorKind::Passphrase) {
        return attempt_resume(store, anchors, prompt);
    }
    let mut failures = 0u32;
    loop {
        match attempt_resume(store, anchors, prompt) {
            Ok(verified) => return Ok(verified),
            Err(ResumeRefusal::FactorRefused) => {
                failures += 1;
                if failures >= MAX_RESUME_PASSPHRASE_FAILURES {
                    prompt.say(
                        "power: passphrase attempts exhausted; image retained — cold boot available",
                    );
                    return Err(ResumeRefusal::FactorRefused);
                }
                delay.delay(backoff_millis(failures));
            }
            Err(other) => return Err(other),
        }
    }
}

//! The resume environment (power-suspend design §6): the early
//! context that stands up before any restored state is trusted,
//! locates the suspend image, drives its factors through the
//! custody seam, and verifies the image end to end before — and
//! only before — handing control to restored state.
//!
//! The trust order of design §6.2 is normative and is the whole
//! shape of [`attempt_resume`]:
//!
//! 1. Parse the header *claims* ([`parse_claims`]). Claims are
//!    untrusted: they say where the slots are and what policy the
//!    image *claims*, nothing more.
//! 2. Prompt with the claimed policy **as an attempt**, never as
//!    a fact — the prompt discipline below exists because a
//!    tampered claim byte must not be able to put words in the
//!    console's mouth.
//! 3. Satisfy the recorded policy through the
//!    [`KeyCustodyAnchor`] seam: an OFF image opens under its
//!    published derivation; a wrapped image opens only when an
//!    anchor whose kind matches an enrolled slot unwraps the
//!    slot secret. There is no fallback between paths — a
//!    wrapped image with no matching anchor is
//!    [`ResumeRefusal::FactorUnavailable`], never a quieter
//!    policy (design §10.3).
//! 4. Verify the whole image ([`OpenedImage::verify_all`]): the
//!    manifest root must match the sealed header, and every
//!    chunk must AEAD-open. Only then does a [`VerifiedResume`]
//!    exist, and it is the only value this module hands to the
//!    handoff that restores state.
//! 5. Any failure on the way is a typed [`ResumeRefusal`] and no
//!    part of the image — not a chunk, not a hook blob — has
//!    been delivered to anyone.
//!
//! Scope boundaries, stated plainly: this module is the
//! environment and the anchor seam. The token ceremony that a
//! real FIDO anchor performs inside `unwrap` is P5 (#1001); the
//! passphrase slot's prompt/KDF discipline is P7 (#1004) — the
//! issue text's "passphrase resume end-to-end" acceptance reads
//! on the composed programme, and P4's part of it is that a
//! passphrase-kind slot, once P7 lands, flows through this exact
//! path unchanged. Boot wiring (partition discovery, mapping
//! the early window, calling [`attempt_resume`] from the boot
//! path) is a follow-on integration, the same way P1 landed the
//! service before any caller froze an image; the entry point is
//! shaped for it: synchronous, no scheduler, no initcall state,
//! one store + a prompt seam.
//!
//! [`OpenedImage::verify_all`]: super::image::OpenedImage::verify_all

use alloc::format;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use super::anchor::{KeyCustodyAnchor, UnwrapCtx};
use super::format::{ImageStore, PolicyLevel};
use super::image::{open_with_sms, parse_claims, TrustedImage};
use super::{off_policy_sms, ServiceError};

/// The resume environment's voice: one line at a time to the
/// early console. The seam exists so fixtures can assert exactly
/// what was said and in what order (the §6.2 step-2 discipline:
/// claims are announced as attempts; only verified facts are
/// announced as facts).
pub trait ResumePrompt {
    /// Emit one line of resume-console output.
    fn say(&mut self, line: &str);
}

/// Production prompt: the early console via `narf-console`.
pub struct ConsolePrompt;

impl ResumePrompt for ConsolePrompt {
    fn say(&mut self, line: &str) {
        narf_console::write_str(line);
        narf_console::write_str("\n");
    }
}

/// Why a resume attempt refused. Boot routing keys off the
/// class: `NoImage` is the ordinary cold-boot case (blank or
/// foreign partition), the factor classes are "a human with the
/// right factor could retry", and `AuthenticationFailed` is the
/// tamper class — one variant for SMK unwrap, header seal,
/// manifest, and chunk failures alike, so the resume path is
/// never an oracle for *which* check failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResumeRefusal {
    /// No suspend image on the store (header magic mismatch).
    NoImage,
    /// An image, but of a format version this environment does
    /// not read.
    UnsupportedVersion,
    /// The recorded policy needs a factor kind that none of the
    /// provided anchors implements (or no slot is enrolled for
    /// it). Never a cue to try a weaker policy.
    FactorUnavailable,
    /// Anchors of the right kind were present, but every unwrap
    /// refused or failed (presence not granted, token absent,
    /// ...). The anchor layer's distinctions end here.
    FactorRefused,
    /// A secret was obtained (or the OFF derivation applied) and
    /// the image did not authenticate under it: tampered image,
    /// or a factor that yielded the wrong secret. Indistinguish-
    /// able by construction.
    AuthenticationFailed,
    /// A structural or store failure from the image pipeline
    /// (truncated store, malformed header, I/O error).
    Service(ServiceError),
}

impl ResumeRefusal {
    fn from_open(err: ServiceError) -> Self {
        match err {
            ServiceError::AuthenticationFailed => ResumeRefusal::AuthenticationFailed,
            other => ResumeRefusal::Service(other),
        }
    }
}

fn level_name(level: PolicyLevel) -> &'static str {
    match level {
        PolicyLevel::Off => "off",
        PolicyLevel::Passphrase => "passphrase",
        PolicyLevel::Token => "token",
        PolicyLevel::TokenTpm => "token+tpm",
        PolicyLevel::Tpm => "tpm",
    }
}

/// The handoff value: a fully verified suspend image. This is
/// the only output of the resume environment that restored state
/// may be built from, and it is unconstructable outside the
/// verification pipeline — the inner [`TrustedImage`] can only
/// come from `verify_all`, and this wrapper is only minted at
/// the end of [`attempt_resume`]. Chunk reads re-verify against
/// the manifest at delivery time (the pipeline's own discipline),
/// so even a store mutated after verification fails closed at
/// the read, not silently.
pub struct VerifiedResume {
    trusted: TrustedImage,
    /// Hook-region length from the sealed header body, captured
    /// from the opened image at verification time.
    hook_region_len: u64,
}

impl VerifiedResume {
    /// The *authenticated* policy the image was sealed under
    /// (post-verification: a fact, not a claim).
    pub fn policy(&self) -> super::format::RecordedPolicy {
        self.trusted.claims().policy
    }

    /// Authenticated plaintext length of the frozen image.
    pub fn image_len(&self) -> u64 {
        self.trusted.image_len()
    }

    /// Authenticated chunk count.
    pub fn chunk_count(&self) -> u64 {
        self.trusted.chunk_count()
    }

    /// Authenticated hook-region length. The region's bytes are
    /// delivered through the hook blobs' own AEAD at unseal time
    /// (P2's registry); the pipeline authenticates the extent.
    pub fn hook_region_len(&self) -> u64 {
        self.hook_region_len
    }

    /// The per-hook key for `name`, derived from the image's
    /// SMK — the input P2's unseal path consumes once the
    /// handoff begins.
    pub fn hook_key(&self, name: &str) -> Zeroizing<[u8; 32]> {
        self.trusted.hook_key(name)
    }

    /// Read chunk `index` from `store`, appending its verified
    /// plaintext to `out`.
    pub fn read_chunk(
        &self,
        store: &dyn ImageStore,
        index: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), ServiceError> {
        self.trusted.read_chunk(store, index, out)
    }

    /// Read the whole verified plaintext image from `store`.
    pub fn read_all(&self, store: &dyn ImageStore) -> Result<Vec<u8>, ServiceError> {
        self.trusted.read_all(store)
    }

    /// Consume the handoff value into the pipeline's
    /// [`TrustedImage`] for the restore path.
    pub fn into_trusted(self) -> TrustedImage {
        self.trusted
    }
}

/// Drive one resume attempt over `store`, per the trust order in
/// the module docs. `anchors` are the custody anchors available
/// in the early environment (a token anchor, a TPM anchor, a
/// test anchor in fixtures); `prompt` receives the console
/// lines. Success is a [`VerifiedResume`] and nothing else —
/// every other outcome is a [`ResumeRefusal`] with no image
/// content delivered.
pub fn attempt_resume(
    store: &dyn ImageStore,
    anchors: &[&dyn KeyCustodyAnchor],
    prompt: &mut dyn ResumePrompt,
) -> Result<VerifiedResume, ResumeRefusal> {
    // Step 1: claims. A magic mismatch is the blank-partition
    // case, kept distinct so boot routing can cold-boot without
    // treating an unused partition as an attack.
    let claims = match parse_claims(store) {
        Ok(claims) => claims,
        Err(ServiceError::BadMagic) => return refuse(prompt, ResumeRefusal::NoImage),
        Err(ServiceError::BadVersion) => return refuse(prompt, ResumeRefusal::UnsupportedVersion),
        Err(other) => return refuse(prompt, ResumeRefusal::Service(other)),
    };

    // Step 2: announce the attempt under the *claimed* policy.
    prompt.say(&format!(
        "power: suspended image found; attempting resume under claimed policy {} (epoch {})",
        level_name(claims.policy.level),
        claims.sms_epoch
    ));

    // Step 3: satisfy the recorded policy through the seam.
    let opened = match claims.policy.level {
        PolicyLevel::Off => {
            // The OFF path: the published derivation, exactly as
            // the service opens it. Reaching for it is driven by
            // the recorded level, and the header seal still has
            // to verify under the derived SMK — a tampered image
            // cannot ride the OFF path anywhere.
            match open_with_sms(store, claims, &off_policy_sms()) {
                Ok(opened) => opened,
                Err(e) => return refuse(prompt, ResumeRefusal::from_open(e)),
            }
        }
        _ => {
            // First successful unwrap decides (the service's
            // semantics in `open_with_anchor`): the SMS either is
            // the slot secret or it is not, and if the header seal
            // then fails, that is an authentication failure of
            // the image under a genuinely unwrapped secret, not a
            // cue to shop for another factor.
            let mut matched = false;
            let mut unwrapped = None;
            'attempt: for anchor in anchors {
                for record in &claims.slots {
                    if record.kind != anchor.kind() {
                        continue;
                    }
                    matched = true;
                    let ctx = UnwrapCtx {
                        sms_epoch: claims.sms_epoch,
                    };
                    match anchor.unwrap(&ctx, &record.wrapped()) {
                        Ok(sms) => {
                            unwrapped = Some(sms);
                            break 'attempt;
                        }
                        // Refused, unavailable, or failed: all
                        // are "this factor did not open this
                        // slot"; try the next pairing, remember
                        // only that a pairing was attempted.
                        Err(_) => {}
                    }
                }
            }
            match (matched, unwrapped) {
                (false, _) => return refuse(prompt, ResumeRefusal::FactorUnavailable),
                (true, None) => return refuse(prompt, ResumeRefusal::FactorRefused),
                (true, Some(sms)) => match open_with_sms(store, claims, &sms) {
                    Ok(opened) => opened,
                    Err(e) => return refuse(prompt, ResumeRefusal::from_open(e)),
                },
            }
        }
    };

    // Step 4: verify the whole image before anything is handed
    // to restored state. No chunk has been delivered yet; the
    // opened image yields lengths, not plaintext. The hook-region
    // length comes from the sealed body via the opened image
    // (verify_all consumes it, and the trusted view does not
    // re-expose the extent).
    let hook_region_len = opened.hook_region_len();
    let trusted = match opened.verify_all(store) {
        Ok(trusted) => trusted,
        Err(e) => return refuse(prompt, ResumeRefusal::from_open(e)),
    };

    // Step 5: only now state facts: the policy is authenticated.
    let policy = trusted.claims().policy;
    prompt.say(&format!(
        "power: image verified under policy {} (epoch {}); resuming",
        level_name(policy.level),
        trusted.claims().sms_epoch
    ));
    Ok(VerifiedResume {
        trusted,
        hook_region_len,
    })
}

/// Say the refusal line and return the refusal. Refusal lines
/// carry the class only — never slot material, never which check
/// failed.
fn refuse<T>(prompt: &mut dyn ResumePrompt, refusal: ResumeRefusal) -> Result<T, ResumeRefusal> {
    prompt.say(&format!("power: resume refused: {:?}", refusal));
    Err(refusal)
}

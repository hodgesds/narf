//! The suspend service: KEYS-domain custody for hibernate images
//! (power-suspend design §3, issue #997).
//!
//! Shape, in one paragraph per piece:
//!
//! - **Key hierarchy** (design §3.1): a per-epoch *slot master
//!   secret* (SMS) lives only in [`Secret32`] custody. Custody
//!   factors — token, TPM, passphrase — never hold the SMS itself;
//!   each enrolled factor wraps it (a *slot*, §4.2) through the
//!   [`KeyCustodyAnchor`] trait. Each image draws a fresh per-image
//!   key (SMK); the SMK is AEAD-wrapped under a key derived from the
//!   SMS *and the epoch*, and the image / manifest keys are HKDF
//!   leaves under the SMK. Rotating the epoch therefore invalidates
//!   every previous wrapping in one move.
//! - **Image format** (`format`, design §3.3): header page +
//!   per-chunk tag manifest + hook region + AEAD chunks. The header's
//!   sealed body authenticates the entire preamble — including the
//!   *recorded policy* — so a tampered image, policy byte included,
//!   fails verification wholesale.
//! - **Verify before any execute** (`image`, design §6.2): the
//!   reader is a typestate pipeline
//!   `claims → opened → verified`; no type before `TrustedImage` can
//!   yield plaintext.
//! - **Entropy** (`entropy`): key generation draws only from
//!   `narf-crypto`'s seed-grade key-material surface (issue #996) and
//!   refuses — typed error, no fallback — when it is unavailable.
//!
//! - **Resume environment** (`resume` + `early_blk`, design §6,
//!   P4 #1000): the early context that drives this pipeline before
//!   any restored state is trusted — claims → factor via the
//!   anchor seam → whole-image verification → the `VerifiedResume`
//!   handoff — reading the image through a polled, read-only
//!   virtio-blk reader built for the pre-scheduler environment.
//!
//! Seams left for the follow-on lanes, deliberately minimal: P8
//! (#1006) gets the authenticated [`RecordedPolicy`] record to
//! enforce. Real anchors land per lane: the FIDO token anchor and
//! its resume ceremony are here ([`token_anchor`], P3 #999 + P5
//! #1001); TPM sealing is P6 (#1002) and the Argon2id passphrase
//! floor is P7 (#1004).
//!
//! The state-hook registry (design §5) lives in [`hooks`]: drivers
//! register [`SuspendStateHook`]s, the seal fan-out runs inside
//! [`SuspendService::seal_image_with_hooks`], and the unseal fan-out
//! ([`run_unseal_fanout`]) runs from a verified image after the
//! device resume fan-out. Hooks never see key material — the
//! derivations ([`derive_hook_key`], [`derive_hook_anchor_key`])
//! stay inside the service.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

mod anchor;
mod custody;
mod early_blk;
mod entropy;
mod format;
mod hooks;
mod image;
mod resume;
mod slots;
mod token_anchor;

pub use anchor::{AnchorError, AnchorKind, KeyCustodyAnchor, UnwrapCtx, WrapCtx, WrappedSlot};
pub use custody::Secret32;
pub use early_blk::{EarlyBlkError, EarlyTransport, PolledBlkReader};
pub use entropy::{HwKeyEntropy, KeyEntropy};
pub use format::{BlockStore, ImageClaims, ImageStore, PolicyLevel, RecordedPolicy};
pub use hooks::{
    decode_hook_region, encode_hook_region, register_suspend_state_hook, registered_hooks,
    run_unseal_fanout, suspend_state_hook_count, unseal_registered, BlobOutcome, BlobRef, HookBlob,
    SealCtx, SealError, SealFanoutFailure, SealFanoutReport, SealMode, SealedHook,
    SuspendStateHook, UnsealCtx, UnsealEntry, UnsealFanoutError, UnsealFanoutReport, UnsealOutcome,
    __reset_hooks_for_test, MAX_HOOK_STATE_LEN,
};
pub use image::{
    derive_hook_anchor_key, derive_hook_key, open_with_sms, parse_claims, OpenedImage, TrustedImage,
};
pub use resume::{attempt_resume, ConsolePrompt, ResumePrompt, ResumeRefusal, VerifiedResume};
pub use slots::{EpochSlots, SlotArea, SlotRecord};
pub use token_anchor::{
    resume_with_token, suspend_client_data_hash, ConsoleTokenUi, TokenAnchor, TokenAnchorConfig,
    TokenPinMode, TokenUserInterface, SUSPEND_RP_ID, SUSPEND_USER_NAME,
};

/// Crate-visible writer surface for fixtures (the resume-env
/// smokes craft hook-region images the service itself does not
/// write yet) and for P2's seal path. Not public API.
pub(crate) use image::{write_image, WriteRequest};

use anchor::AnchorKind as Kind;
use slots::{EpochCustody, SlotStore};

/// Suspend-service failure. The variants are deliberately coarse at
/// the security boundaries: `AuthenticationFailed` covers a wrong
/// secret, a wrong epoch, and a tampered byte indistinguishably (no
/// oracle), and `EntropyUnavailable` is a refusal, not a degradation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// No seed-grade entropy source: key generation refuses.
    EntropyUnavailable,
    /// Operation needs a current SMS epoch and none exists.
    NoEpoch,
    /// An epoch is already current (create), or the epoch named is
    /// the current one (retire).
    EpochIsCurrent,
    /// The operation needs at least one enrolled slot / anchor.
    NoSlotsEnrolled,
    /// The named SMS epoch is not retained.
    UnknownEpoch,
    /// The epoch still has unconsumed images written under it.
    EpochInUse,
    /// No slot record matches (epoch, kind, params) — or, at open
    /// time, the image carries no slot for the anchor presented.
    SlotNotFound,
    /// The open path does not match the image's recorded policy
    /// (anchor path for an OFF image, OFF path for a wrapped image).
    PolicyMismatch,
    /// A custody anchor failed; see [`AnchorError`].
    Anchor(AnchorError),
    /// The image store failed an I/O operation.
    Store,
    /// The header magic is not the suspend-image magic.
    BadMagic,
    /// The header format version is not supported by this build.
    BadVersion,
    /// The store ends before the image's authenticated length.
    Truncated,
    /// Bytes fail structural parsing (bounds, codes, counts).
    Malformed,
    /// An AEAD check failed: wrong key material or tampered bytes.
    AuthenticationFailed,
    /// The plaintext image does not fit the store.
    ImageTooLarge,
    /// A zero-length image is not a suspend image.
    EmptyImage,
    /// A state hook's seal failed; the suspend is aborted and no
    /// image was committed (design §5.2 rule 5). The failing hook
    /// and its error are in the fan-out failure the seal call
    /// reports through its own channel; at this layer the abort is
    /// deliberately coarse, like the other security boundaries.
    HookSealAborted,
}

impl From<AnchorError> for ServiceError {
    fn from(e: AnchorError) -> Self {
        ServiceError::Anchor(e)
    }
}

/// The published "secret" of an OFF-policy image (design §10.1):
/// derived from a fixed public label, recomputable by anyone. OFF
/// images go through exactly the same AEAD machinery as wrapped
/// images — the format stays uniform and honest about what OFF
/// means — but the wrap protects nothing, by the user's explicit,
/// authenticated choice.
pub fn off_policy_sms() -> Secret32 {
    let sms = image::derive32(b"narf-suspend/off-policy-published", b"sms");
    Secret32::mint(*sms)
}

/// The suspend service, generic over its entropy seam so fixtures
/// can script the seed-grade surface's two states. Production uses
/// [`SuspendService::production`] (the `narf-crypto` surface via
/// [`HwKeyEntropy`]).
pub struct SuspendService<E: KeyEntropy> {
    entropy: E,
    store: SlotStore,
}

impl SuspendService<HwKeyEntropy> {
    /// The production service: real seed-grade entropy, empty slot
    /// store (epochs are established by enrollment flows).
    pub fn production() -> Self {
        Self::new(HwKeyEntropy)
    }
}

impl<E: KeyEntropy> SuspendService<E> {
    pub fn new(entropy: E) -> Self {
        Self {
            entropy,
            store: SlotStore::default(),
        }
    }

    /// Whether the entropy surface currently reports a seed-grade
    /// source (diagnostics; key generation re-checks at draw time).
    pub fn entropy_available(&self) -> bool {
        self.entropy.has_seed_grade()
    }

    /// The current SMS epoch, if one is established.
    pub fn current_epoch(&self) -> Option<u64> {
        self.store.current_epoch()
    }

    /// The store in persisted, secret-free form (the slot area that
    /// mirrors to the suspend partition, design §10.2).
    pub fn slot_area(&self) -> SlotArea {
        self.store.slot_area()
    }

    fn draw<const N: usize>(&self) -> Result<[u8; N], ServiceError> {
        if !self.entropy.has_seed_grade() {
            return Err(ServiceError::EntropyUnavailable);
        }
        let mut out = [0u8; N];
        self.entropy.fill_key_material(&mut out)?;
        Ok(out)
    }

    fn mint_sms(&self) -> Result<Secret32, ServiceError> {
        Ok(Secret32::mint(self.draw::<32>()?))
    }

    fn next_epoch(&self) -> u64 {
        self.store.epochs.iter().map(|e| e.epoch).max().unwrap_or(0) + 1
    }

    /// Establish the first SMS epoch. Refuses while an epoch is
    /// current (use [`Self::rotate_epoch`]) and refuses — leaving no
    /// epoch behind — without seed-grade entropy.
    pub fn create_epoch(&mut self) -> Result<u64, ServiceError> {
        if self.store.current_epoch().is_some() {
            return Err(ServiceError::EpochIsCurrent);
        }
        let sms = self.mint_sms()?;
        let epoch = self.next_epoch();
        self.store.insert(EpochCustody {
            epoch,
            sms,
            slots: Vec::new(),
            images_outstanding: Vec::new(),
        });
        self.store.current = Some(epoch);
        Ok(epoch)
    }

    /// Enroll a custody factor into the current epoch: the anchor
    /// wraps the SMS and the stamped slot record is retained (and
    /// returned). The plaintext SMS never leaves custody.
    pub fn enroll(&mut self, anchor: &dyn KeyCustodyAnchor) -> Result<SlotRecord, ServiceError> {
        let epoch = self.store.current_epoch().ok_or(ServiceError::NoEpoch)?;
        let custody = self.store.get(epoch).ok_or(ServiceError::UnknownEpoch)?;
        let wrapped = anchor.wrap(&WrapCtx { sms_epoch: epoch }, &custody.sms)?;
        let record = SlotRecord {
            kind: anchor.kind(),
            epoch,
            params: wrapped.params,
            blob: wrapped.blob,
        };
        self.store
            .get_mut(epoch)
            .ok_or(ServiceError::UnknownEpoch)?
            .slots
            .push(record.clone());
        Ok(record)
    }

    /// Revoke one enrolled slot, identified by (epoch, kind,
    /// params) — two factors of the same kind (primary + backup
    /// tokens) differ by their params. Revoking a slot destroys that
    /// factor's path to the epoch's SMS; it does not rotate the SMS.
    pub fn revoke_slot(
        &mut self,
        epoch: u64,
        kind: Kind,
        params: &[u8],
    ) -> Result<(), ServiceError> {
        let custody = self
            .store
            .get_mut(epoch)
            .ok_or(ServiceError::UnknownEpoch)?;
        let idx = custody
            .slots
            .iter()
            .position(|s| s.kind == kind && s.params == params)
            .ok_or(ServiceError::SlotNotFound)?;
        custody.slots.remove(idx);
        Ok(())
    }

    /// Rotate to a fresh SMS epoch (design §10.4): mint a new SMS,
    /// wrap it under *every* anchor given, and only then switch the
    /// current epoch. If any anchor fails, the old epoch stays
    /// current and the new SMS is dropped (zeroized) — rotation is
    /// all-or-nothing, and from the moment it succeeds the previous
    /// epoch's wrappings unwrap nothing written under the new one.
    pub fn rotate_epoch(&mut self, anchors: &[&dyn KeyCustodyAnchor]) -> Result<u64, ServiceError> {
        if self.store.current_epoch().is_none() {
            return Err(ServiceError::NoEpoch);
        }
        if anchors.is_empty() {
            return Err(ServiceError::NoSlotsEnrolled);
        }
        let sms = self.mint_sms()?;
        let epoch = self.next_epoch();
        let mut records = Vec::with_capacity(anchors.len());
        for anchor in anchors {
            let wrapped = anchor.wrap(&WrapCtx { sms_epoch: epoch }, &sms)?;
            records.push(SlotRecord {
                kind: anchor.kind(),
                epoch,
                params: wrapped.params,
                blob: wrapped.blob,
            });
        }
        self.store.insert(EpochCustody {
            epoch,
            sms,
            slots: records,
            images_outstanding: Vec::new(),
        });
        self.store.current = Some(epoch);
        Ok(epoch)
    }

    /// Retire a non-current epoch with no outstanding images,
    /// dropping its SMS custody (zeroized) and its slot records.
    pub fn retire_epoch(&mut self, epoch: u64) -> Result<(), ServiceError> {
        if self.store.current_epoch() == Some(epoch) {
            return Err(ServiceError::EpochIsCurrent);
        }
        let custody = self.store.get(epoch).ok_or(ServiceError::UnknownEpoch)?;
        if !custody.images_outstanding.is_empty() {
            return Err(ServiceError::EpochInUse);
        }
        // Dropping the custody zeroizes the epoch's SMS.
        drop(self.store.remove(epoch));
        Ok(())
    }

    /// Seal `image` under `policy` into `store`, returning the image
    /// id. The SMK, image id, and wrap nonce are all drawn from the
    /// entropy seam — for every policy, OFF included — so sealing
    /// refuses without seed-grade entropy exactly like key
    /// generation does. A non-OFF policy requires a current epoch
    /// with at least one enrolled slot, failing closed otherwise.
    pub fn seal_image(
        &mut self,
        store: &mut dyn ImageStore,
        policy: RecordedPolicy,
        image: &[u8],
    ) -> Result<[u8; 16], ServiceError> {
        let (image_id, _report) = self.seal_image_hooked(store, policy, image, &[])?;
        Ok(image_id)
    }

    /// Seal with the state-hook seal fan-out (design §5, P2): the
    /// hooks in `hooks` run in reverse order after device quiesce
    /// and before the image write; their sealed blobs land in the
    /// image's hook region. Any hook failure aborts the seal with
    /// [`ServiceError::HookSealAborted`] *before* the writer runs,
    /// so an aborted suspend commits no image at all. Returns the
    /// image id and the fan-out report.
    pub fn seal_image_with_hooks(
        &mut self,
        store: &mut dyn ImageStore,
        policy: RecordedPolicy,
        image: &[u8],
        hooks: &[Arc<dyn SuspendStateHook>],
    ) -> Result<([u8; 16], SealFanoutReport), ServiceError> {
        self.seal_image_hooked(store, policy, image, hooks)
    }

    /// [`Self::seal_image_with_hooks`] over the global hook
    /// registry's snapshot — the production entry the suspend
    /// coordinator calls once devices have quiesced.
    pub fn seal_image_registered(
        &mut self,
        store: &mut dyn ImageStore,
        policy: RecordedPolicy,
        image: &[u8],
    ) -> Result<([u8; 16], SealFanoutReport), ServiceError> {
        let hooks = registered_hooks();
        self.seal_image_hooked(store, policy, image, &hooks)
    }

    fn seal_image_hooked(
        &mut self,
        store: &mut dyn ImageStore,
        policy: RecordedPolicy,
        image: &[u8],
        hooks: &[Arc<dyn SuspendStateHook>],
    ) -> Result<([u8; 16], SealFanoutReport), ServiceError> {
        let smk = Secret32::mint(self.draw::<32>()?);
        let image_id = self.draw::<16>()?;
        let smk_wrap_nonce = self.draw::<12>()?;
        match policy.level {
            format::PolicyLevel::Off => {
                let sms = off_policy_sms();
                let (region, report) = run_hooks(hooks, &smk, &sms, &image_id)?;
                image::write_image(
                    store,
                    &image::WriteRequest {
                        policy,
                        sms: &sms,
                        sms_epoch: 0,
                        slots: &[],
                        smk: &smk,
                        image_id,
                        smk_wrap_nonce,
                        image,
                        hook_region: &region,
                    },
                )?;
                Ok((image_id, report))
            }
            _ => {
                let epoch = self.store.current_epoch().ok_or(ServiceError::NoEpoch)?;
                let custody = self.store.get(epoch).ok_or(ServiceError::UnknownEpoch)?;
                if custody.slots.is_empty() {
                    return Err(ServiceError::NoSlotsEnrolled);
                }
                let (region, report) = run_hooks(hooks, &smk, &custody.sms, &image_id)?;
                let custody = self.store.get(epoch).ok_or(ServiceError::UnknownEpoch)?;
                image::write_image(
                    store,
                    &image::WriteRequest {
                        policy,
                        sms: &custody.sms,
                        sms_epoch: epoch,
                        slots: &custody.slots,
                        smk: &smk,
                        image_id,
                        smk_wrap_nonce,
                        image,
                        hook_region: &region,
                    },
                )?;
                self.store
                    .get_mut(epoch)
                    .ok_or(ServiceError::UnknownEpoch)?
                    .images_outstanding
                    .push(image_id);
                Ok((image_id, report))
            }
        }
    }

    /// Record that the image with this id has been consumed (resumed
    /// or discarded), releasing its hold on its epoch's retirement.
    pub fn note_image_consumed(&mut self, image_id: &[u8; 16]) {
        for custody in self.store.epochs.iter_mut() {
            custody.images_outstanding.retain(|id| id != image_id);
        }
    }

    /// Open an image through a custody anchor: parse the claims,
    /// try each of the image's slots for the anchor's kind (primary
    /// and backup factors share a kind) until one unwraps the SMS,
    /// then verify the header seal. Returns the opened image; the
    /// caller completes verification with
    /// [`OpenedImage::verify_all`] before any plaintext exists.
    pub fn open_with_anchor(
        &self,
        store: &dyn ImageStore,
        anchor: &dyn KeyCustodyAnchor,
    ) -> Result<OpenedImage, ServiceError> {
        let claims = image::parse_claims(store)?;
        if claims.policy.level == format::PolicyLevel::Off {
            return Err(ServiceError::PolicyMismatch);
        }
        let mut last_err = None;
        for record in claims.slots.iter().filter(|r| r.kind == anchor.kind()) {
            match anchor.unwrap(
                &UnwrapCtx {
                    sms_epoch: claims.sms_epoch,
                },
                &record.wrapped(),
            ) {
                Ok(sms) => return image::open_with_sms(store, claims, &sms),
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(e) => Err(ServiceError::Anchor(e)),
            None => Err(ServiceError::SlotNotFound),
        }
    }

    /// Open an OFF-policy image through its published derivation.
    /// Refuses a wrapped (non-OFF) image: the OFF path must never
    /// become a way around a factor.
    pub fn open_off(&self, store: &dyn ImageStore) -> Result<OpenedImage, ServiceError> {
        let claims = image::parse_claims(store)?;
        if claims.policy.level != format::PolicyLevel::Off {
            return Err(ServiceError::PolicyMismatch);
        }
        image::open_with_sms(store, claims, &off_policy_sms())
    }
}

/// The seal fan-out, shared by every policy arm: run the hooks,
/// encode their blobs into hook-region bytes. A hook failure is
/// the suspend's failure (design §5.2 rule 5) — mapped to the
/// coarse [`ServiceError::HookSealAborted`] at this layer, with the
/// failing hook's identity available to callers that run the
/// fan-out through [`hooks::run_seal_fanout`]'s own channel.
fn run_hooks(
    hooks: &[Arc<dyn SuspendStateHook>],
    smk: &Secret32,
    sms: &Secret32,
    image_id: &[u8; 16],
) -> Result<(Vec<u8>, SealFanoutReport), ServiceError> {
    if hooks.is_empty() {
        return Ok((Vec::new(), SealFanoutReport::default()));
    }
    let (blobs, report) = hooks::run_seal_fanout(hooks, smk, sms, image_id)
        .map_err(|_| ServiceError::HookSealAborted)?;
    Ok((hooks::encode_hook_region(&blobs), report))
}

impl<E: KeyEntropy> fmt::Debug for SuspendService<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuspendService")
            .field("current_epoch", &self.store.current_epoch())
            .field("epochs", &self.store.epochs.len())
            .finish_non_exhaustive()
    }
}

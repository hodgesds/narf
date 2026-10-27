//! The state-hook registry and the seal/unseal fan-outs
//! (power-suspend design §5, issue #998).
//!
//! Device quiesce (`crate::device_pm`) answers "stop the hardware."
//! This contract answers the second question: what state must
//! survive power loss, and who encrypts it. Drivers and core
//! libraries register a [`SuspendStateHook`]; at S4 seal time the
//! suspend service runs the *seal fan-out* (reverse registration
//! order, after the device quiesce fan-out) and each hook hands its
//! state to the service through [`SealCtx`]. On resume — after the
//! image has verified wholesale ([`super::TrustedImage`]) and the
//! device resume fan-out has run — the *unseal fan-out* (forward
//! order) hands each hook back exactly what it sealed.
//!
//! The contract's rules (design §5.2), as enforced here:
//!
//! 1. **No key material crosses the API.** Hooks hand plaintext in
//!    and receive plaintext back, inside the call. Keys are derived
//!    by the service: `HKDF(SMK, "narf-suspend/hook/" ‖ name)` in
//!    image mode, `HKDF(SMS, "narf-suspend/hook-anchor/" ‖ name)` in
//!    anchor mode (the derivations P1 pinned, [`super::derive_hook_key`]
//!    / [`super::derive_hook_anchor_key`]). A hook bug cannot leak a
//!    key it never held; one hook's compromise cannot reach another
//!    hook's key (HKDF separation by name).
//! 2. **Two modes, deliberately.** Image mode covers state only as
//!    sensitive as the image itself. Anchor mode is bound to the SMS
//!    epoch instead: an epoch rotation changes the SMS, so anchor
//!    blobs from a previous epoch no longer open — the hook receives
//!    [`BlobOutcome::Invalid`] and must re-establish state (design
//!    §5.2 rule 2), never a silent plaintext path.
//! 3. **Size discipline.** At most [`MAX_HOOK_STATE_LEN`] bytes per
//!    hook per mode per seal. Bulk data belongs to the image, which
//!    is already encrypted wholesale.
//! 4. **Ordering + device gating.** Seal runs reverse-registration,
//!    unseal forward. A hook whose device did not resume (the
//!    coordinator's `device_resumed` predicate, fed from the
//!    `device_pm` resume report) is not unsealed; the resume
//!    continues without it.
//! 5. **Abort semantics.** Any seal error aborts the suspend before
//!    anything is committed — the image writer commits its header
//!    last, and the fan-out runs before the writer, so an aborted
//!    seal leaves no image at all. At unseal, **every blob is
//!    AEAD-opened into staging before any hook's `unseal` runs**
//!    (verify-before-deliver, the hook-region analogue of design
//!    §6.2): a tampered blob for a `critical` hook aborts the whole
//!    fan-out before a single callback; a tampered blob for a
//!    non-critical hook is delivered to that hook as the fact
//!    [`BlobOutcome::Invalid`] — no bytes, just the refusal — so it
//!    can re-establish state loudly instead of consuming bad state.
//!
//! Blob wire format (the image's hook region; all integers
//! little-endian): `u32 count`, then per blob `u16 name_len ‖ name
//! ‖ u8 mode ‖ u32 sealed_len ‖ sealed`, where `sealed` is the
//! ChaCha20-Poly1305 ciphertext with its 16-byte tag appended. The
//! AEAD AAD is `image_id ‖ mode ‖ name`, and the nonce is the image
//! id's first 12 bytes (the image key and anchor key derivations
//! are per-image / per-epoch, and the image id is fresh randomness
//! per image, so the nonce never repeats under a key). The AAD binds
//! each blob to its image, its hook, and its mode: a blob copied
//! into another image, renamed, or re-moded fails its AEAD open and
//! surfaces as `Invalid`, never as delivered state. The directory
//! itself is structural only — every semantic field a consumer
//! trusts (the state bytes) is inside the AEAD, and every index
//! field is re-checked against the requesting hook at open time.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_lib::sync::IrqSafeSpinLock;
use zeroize::Zeroizing;

use super::custody::Secret32;
use super::format::{ImageStore, TAG_LEN};
use super::image::{derive_hook_anchor_key, derive_hook_key};
use super::{ServiceError, TrustedImage};

/// Maximum state one hook may seal per mode per suspend
/// (design §5.2 rule 3: hook state is small by definition).
pub const MAX_HOOK_STATE_LEN: usize = 64 * 1024;

/// Which key a hook blob is sealed under (design §5.2 rule 2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SealMode {
    /// Per-hook key derived from the per-image SMK.
    Image,
    /// Per-hook key derived from the epoch's SMS.
    Anchor,
}

impl SealMode {
    /// Stable code in the hook-region directory and the blob AAD.
    pub fn code(self) -> u8 {
        match self {
            SealMode::Image => 0,
            SealMode::Anchor => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(SealMode::Image),
            1 => Some(SealMode::Anchor),
            _ => None,
        }
    }
}

/// A hook-facing failure. The fan-outs treat any of these from
/// `seal` as an abort (design §5.2 rule 5) and from `unseal` as a
/// per-hook degradation unless the hook is critical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// State exceeded [`MAX_HOOK_STATE_LEN`] for one mode.
    StateTooLarge,
    /// The hook tried to seal a second blob in the same mode.
    DuplicateBlob,
    /// The hook refuses (its own state is not in a sealable shape).
    Refused(&'static str),
    /// At unseal, the restored bytes are not acceptable state for
    /// this hook (wrong shape, stale generation, …).
    BadState(&'static str),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::StateTooLarge => write!(f, "hook state exceeds the per-hook cap"),
            SealError::DuplicateBlob => write!(f, "hook sealed the same mode twice"),
            SealError::Refused(why) => write!(f, "hook refused: {why}"),
            SealError::BadState(why) => write!(f, "hook rejected restored state: {why}"),
        }
    }
}

/// Opaque proof that the service recorded a blob for a hook. A hook
/// cannot construct one; it can only observe the mode and the
/// plaintext length it sealed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    mode: SealMode,
    len: usize,
}

impl BlobRef {
    /// The mode this blob was sealed under.
    pub fn mode(&self) -> SealMode {
        self.mode
    }

    /// Plaintext length sealed (ciphertext is this plus the tag).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the sealed state was zero-length (a hook may seal
    /// an empty state to record "present, but empty").
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One sealed blob, directory entry and ciphertext together. The
/// resume environment (P4) decodes the region with
/// [`decode_hook_region`]; consumers never parse it directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookBlob {
    /// Hook name (also its HKDF info label and AAD component).
    pub name: String,
    /// Key mode the blob is sealed under.
    pub mode: SealMode,
    /// Ciphertext with the AEAD tag appended.
    pub sealed: Vec<u8>,
}

/// A driver or core library with state that must survive S4.
///
/// Registration is by [`Self::name`]: the registry replaces an
/// existing hook of the same name (re-probe is idempotent), and the
/// name is the HKDF info label — two hooks that share a name share
/// a key, so names are owned like device names.
pub trait SuspendStateHook: Send + Sync {
    /// Unique hook name; also the key-derivation label.
    fn name(&self) -> &str;

    /// Critical hooks abort the resume when their blob fails
    /// verification or their `unseal` fails (design §5.2 rule 4:
    /// a half-restored key custodian is worse than a clean cold
    /// boot). Default: not critical.
    fn critical(&self) -> bool {
        false
    }

    /// Hand this hook's must-survive state to the service through
    /// `ctx`. Called in reverse registration order, after device
    /// quiesce. Any error aborts the suspend.
    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError>;

    /// Receive back what `seal` sealed, through `ctx`. Called in
    /// forward registration order, after the device resume fan-out,
    /// and only if this hook's device resumed. A hook must treat
    /// [`BlobOutcome::Missing`] and [`BlobOutcome::Invalid`] as
    /// first-class outcomes (re-establish state), never as reasons
    /// to invent state silently.
    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError>;
}

/// Service-owned sealing context, one per hook per seal fan-out.
/// The hook sees plaintext and [`BlobRef`]s; the keys, nonce, and
/// AAD never leave this type (design §5.2 rule 1).
pub struct SealCtx<'a> {
    name: &'a str,
    smk: &'a Secret32,
    sms: &'a Secret32,
    image_id: &'a [u8; 16],
    sink: &'a mut Vec<HookBlob>,
    sealed_image: bool,
    sealed_anchor: bool,
}

/// Manual and redacting on purpose: this context holds the SMK and
/// SMS by reference. Only the hook's name and which modes it has
/// sealed are printable — never key material, the image id, or the
/// sealed sink.
impl fmt::Debug for SealCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealCtx")
            .field("name", &self.name)
            .field("sealed_image", &self.sealed_image)
            .field("sealed_anchor", &self.sealed_anchor)
            .finish_non_exhaustive()
    }
}

impl<'a> SealCtx<'a> {
    pub(crate) fn new(
        name: &'a str,
        smk: &'a Secret32,
        sms: &'a Secret32,
        image_id: &'a [u8; 16],
        sink: &'a mut Vec<HookBlob>,
    ) -> Self {
        Self {
            name,
            smk,
            sms,
            image_id,
            sink,
            sealed_image: false,
            sealed_anchor: false,
        }
    }

    /// The sealing hook's name (its key label).
    pub fn hook_name(&self) -> &str {
        self.name
    }

    /// Seal `plaintext` under this image's per-hook key
    /// (image mode — design §5.2 rule 2).
    pub fn seal_image(&mut self, plaintext: &[u8]) -> Result<BlobRef, SealError> {
        self.seal_inner(SealMode::Image, plaintext)
    }

    /// Seal `plaintext` under the SMS-epoch per-hook key
    /// (anchor mode — design §5.2 rule 2).
    pub fn seal_anchor(&mut self, plaintext: &[u8]) -> Result<BlobRef, SealError> {
        self.seal_inner(SealMode::Anchor, plaintext)
    }

    fn seal_inner(&mut self, mode: SealMode, plaintext: &[u8]) -> Result<BlobRef, SealError> {
        if plaintext.len() > MAX_HOOK_STATE_LEN {
            return Err(SealError::StateTooLarge);
        }
        let already = match mode {
            SealMode::Image => &mut self.sealed_image,
            SealMode::Anchor => &mut self.sealed_anchor,
        };
        if *already {
            return Err(SealError::DuplicateBlob);
        }
        *already = true;
        let key = match mode {
            SealMode::Image => derive_hook_key(self.smk, self.name),
            SealMode::Anchor => derive_hook_anchor_key(self.sms, self.name),
        };
        let mut sealed = plaintext.to_vec();
        let tag = chacha20_poly1305_seal(
            &key,
            &blob_nonce(self.image_id),
            &blob_aad(self.image_id, mode, self.name),
            &mut sealed,
        );
        sealed.extend_from_slice(&tag);
        self.sink.push(HookBlob {
            name: String::from(self.name),
            mode,
            sealed,
        });
        Ok(BlobRef {
            mode,
            len: plaintext.len(),
        })
    }
}

/// What the service can tell a hook about one of its blobs at
/// unseal time. `Restored` carries the verified plaintext — and is
/// the only variant that carries bytes at all, so unverified state
/// cannot be delivered by construction.
pub enum BlobOutcome {
    /// The blob verified and opened; here is the exact state that
    /// was sealed.
    Restored(Zeroizing<Vec<u8>>),
    /// No blob for this hook/mode exists in the image (the hook was
    /// not registered at seal time, or an epoch rotation retired
    /// it). Re-establish state.
    Missing,
    /// A blob exists but failed AEAD verification (tampered, wrong
    /// epoch, transplanted from another image). The state is
    /// refused; no bytes are delivered. Re-establish state.
    Invalid,
}

/// Manual and redacting on purpose: `Restored` carries verified
/// plaintext state, so only its byte length is printable — never
/// the bytes.
impl fmt::Debug for BlobOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restored(bytes) => write!(f, "Restored(<{} bytes>)", bytes.len()),
            Self::Missing => f.write_str("Missing"),
            Self::Invalid => f.write_str("Invalid"),
        }
    }
}

/// Service-owned unsealing context, one per hook per unseal fan-out.
/// Outcomes are staged (already AEAD-verified, or already known to
/// have failed) before the fan-out runs any callback — see the
/// module docs, rule 5.
pub struct UnsealCtx {
    image: Option<BlobOutcome>,
    anchor: Option<BlobOutcome>,
}

/// Delegates to [`BlobOutcome`]'s redacting `Debug`, so no restored
/// plaintext can print through this context either.
impl fmt::Debug for UnsealCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnsealCtx")
            .field("image", &self.image)
            .field("anchor", &self.anchor)
            .finish()
    }
}

impl UnsealCtx {
    pub(crate) fn new(image: BlobOutcome, anchor: BlobOutcome) -> Self {
        Self {
            image: Some(image),
            anchor: Some(anchor),
        }
    }

    /// Take the image-mode outcome (second call reports `Missing`).
    pub fn take_image(&mut self) -> BlobOutcome {
        self.image.take().unwrap_or(BlobOutcome::Missing)
    }

    /// Take the anchor-mode outcome (second call reports `Missing`).
    pub fn take_anchor(&mut self) -> BlobOutcome {
        self.anchor.take().unwrap_or(BlobOutcome::Missing)
    }
}

fn blob_nonce(image_id: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&image_id[..12]);
    nonce
}

fn blob_aad(image_id: &[u8; 16], mode: SealMode, name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(17 + name.len());
    aad.extend_from_slice(image_id);
    aad.push(mode.code());
    aad.extend_from_slice(name.as_bytes());
    aad
}

// ── Hook-region codec ────────────────────────────────────────────────

/// Encode sealed blobs into hook-region bytes (see the module docs
/// for the layout). An empty blob set encodes to an empty region —
/// the P1 format's length-0 hook region is exactly this case.
pub fn encode_hook_region(blobs: &[HookBlob]) -> Vec<u8> {
    if blobs.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
    for blob in blobs {
        out.extend_from_slice(&(blob.name.len() as u16).to_le_bytes());
        out.extend_from_slice(blob.name.as_bytes());
        out.push(blob.mode.code());
        out.extend_from_slice(&(blob.sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob.sealed);
    }
    out
}

/// Decode hook-region bytes. Structural only: nothing here is
/// believed — a blob earns trust only when its AEAD opens in the
/// unseal fan-out's staging phase. Any structural defect (overrun,
/// unknown mode code, trailing bytes) is `Malformed`: a directory
/// that cannot be parsed cannot be trusted to enumerate what must
/// be verified, so the fan-out refuses wholesale.
pub fn decode_hook_region(bytes: &[u8]) -> Result<Vec<HookBlob>, ServiceError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut cur = RegionCursor::new(bytes);
    let count = cur.u32()?;
    // Each entry needs at least 2 (name len) + 1 (mode) + 4 (sealed
    // len) bytes; refuse absurd counts before allocating.
    if count as usize > cur.remaining() / 7 + 1 {
        return Err(ServiceError::Malformed);
    }
    let mut blobs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name_len = cur.u16()? as usize;
        let name_bytes = cur.take(name_len)?;
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| ServiceError::Malformed)?
            .into();
        let mode = SealMode::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
        let sealed_len = cur.u32()? as usize;
        if sealed_len < TAG_LEN {
            return Err(ServiceError::Malformed);
        }
        let sealed = cur.take(sealed_len)?.to_vec();
        blobs.push(HookBlob { name, mode, sealed });
    }
    if cur.remaining() != 0 {
        return Err(ServiceError::Malformed);
    }
    Ok(blobs)
}

struct RegionCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> RegionCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ServiceError> {
        if self.remaining() < n {
            return Err(ServiceError::Truncated);
        }
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ServiceError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ServiceError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ServiceError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

// ── Registry ─────────────────────────────────────────────────────────

static HOOK_REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn SuspendStateHook>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register (or replace, by name) a suspend state hook. Follows the
/// `system_pm` registry shape: idempotent re-registration by name,
/// registration order preserved (it defines fan-out order).
pub fn register_suspend_state_hook(hook: Arc<dyn SuspendStateHook>) {
    let mut registry = HOOK_REGISTRY.lock();
    if let Some(slot) = registry.iter_mut().find(|h| h.name() == hook.name()) {
        *slot = hook;
    } else {
        registry.push(hook);
    }
}

/// Number of registered suspend state hooks.
pub fn suspend_state_hook_count() -> usize {
    HOOK_REGISTRY.lock().len()
}

/// Snapshot of the registered hooks, in registration order. The
/// registry lock is released before any hook runs (the fan-outs
/// iterate snapshots, never the locked registry).
pub fn registered_hooks() -> Vec<Arc<dyn SuspendStateHook>> {
    HOOK_REGISTRY.lock().clone()
}

/// Test-only registry reset.
#[doc(hidden)]
pub fn __reset_hooks_for_test() {
    HOOK_REGISTRY.lock().clear();
}

// ── Seal fan-out ─────────────────────────────────────────────────────

/// Per-hook record of a completed seal fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedHook {
    /// Hook name.
    pub name: String,
    /// Plaintext length sealed in image mode, if any.
    pub image_len: Option<usize>,
    /// Plaintext length sealed in anchor mode, if any.
    pub anchor_len: Option<usize>,
}

/// The completed seal fan-out's record: which hooks sealed what.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealFanoutReport {
    /// One entry per hook, in the order the hooks ran (reverse
    /// registration order).
    pub sealed: Vec<SealedHook>,
}

/// A seal fan-out abort: the hook that failed and why. The suspend
/// is aborted; no image is committed (design §5.2 rule 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealFanoutFailure {
    /// Name of the hook whose `seal` failed.
    pub hook: String,
    /// Its failure.
    pub error: SealError,
}

/// Run the seal fan-out over `hooks` in reverse registration order,
/// collecting AEAD-sealed blobs for the image's hook region. The
/// caller (the suspend service) owns `smk`/`sms` custody and the
/// image write; this function owns no key beyond the derivations
/// inside [`SealCtx`], which drop with each call.
pub(crate) fn run_seal_fanout(
    hooks: &[Arc<dyn SuspendStateHook>],
    smk: &Secret32,
    sms: &Secret32,
    image_id: &[u8; 16],
) -> Result<(Vec<HookBlob>, SealFanoutReport), SealFanoutFailure> {
    let mut blobs: Vec<HookBlob> = Vec::new();
    let mut report = SealFanoutReport::default();
    for hook in hooks.iter().rev() {
        let before = blobs.len();
        let mut ctx = SealCtx::new(hook.name(), smk, sms, image_id, &mut blobs);
        if let Err(error) = hook.seal(&mut ctx) {
            return Err(SealFanoutFailure {
                hook: String::from(hook.name()),
                error,
            });
        }
        // ctx's borrow of `blobs` ends with the seal call (NLL).
        let mut entry = SealedHook {
            name: String::from(hook.name()),
            image_len: None,
            anchor_len: None,
        };
        for blob in &blobs[before..] {
            let plain_len = blob.sealed.len() - TAG_LEN;
            match blob.mode {
                SealMode::Image => entry.image_len = Some(plain_len),
                SealMode::Anchor => entry.anchor_len = Some(plain_len),
            }
        }
        report.sealed.push(entry);
    }
    Ok((blobs, report))
}

// ── Unseal fan-out ───────────────────────────────────────────────────

/// What happened to one hook in the unseal fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsealOutcome {
    /// The hook ran; its blobs' outcomes were delivered to it.
    Delivered,
    /// The hook was not run: its device did not resume
    /// (design §5.2 rule 4). Its blobs are retained in the image.
    SkippedDeviceDown,
    /// The hook ran and its `unseal` failed (non-critical hooks
    /// only — a critical hook's failure aborts the fan-out).
    Failed(SealError),
}

/// Per-hook record of an unseal fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsealEntry {
    /// Hook name.
    pub name: String,
    /// What happened.
    pub outcome: UnsealOutcome,
}

/// The unseal fan-out's record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnsealFanoutReport {
    /// One entry per hook considered, in fan-out (forward
    /// registration) order.
    pub entries: Vec<UnsealEntry>,
    /// Blobs present in the image with no registered hook to
    /// deliver them to. Not an error (a hook may have been removed
    /// since the image was written); recorded for diagnostics.
    pub orphaned_blobs: Vec<String>,
}

/// An unseal fan-out abort. In every variant, the fan-out stopped
/// before delivering anything further; the report records how far
/// it got (empty when staging refused, by construction).
#[derive(Debug)]
pub enum UnsealFanoutError {
    /// The hook region could not be read or parsed. A directory
    /// that cannot be parsed cannot enumerate what must be
    /// verified, so nothing is delivered.
    Structure(ServiceError),
    /// A critical hook's blob failed verification in staging. No
    /// hook's `unseal` ran (verify-before-deliver).
    CriticalBlobInvalid {
        /// The critical hook whose blob failed.
        hook: String,
        /// The (empty) report — no entries were delivered.
        report: UnsealFanoutReport,
    },
    /// A critical hook's `unseal` itself failed. Earlier hooks may
    /// already have run; the coordinator treats this as a failed
    /// resume and falls back to a cold boot (design §5.2 rule 4).
    CriticalHookFailed {
        /// The critical hook that failed.
        hook: String,
        /// Its failure.
        error: SealError,
        /// Entries up to and including the failed hook.
        report: UnsealFanoutReport,
    },
}

impl From<ServiceError> for UnsealFanoutError {
    fn from(e: ServiceError) -> Self {
        UnsealFanoutError::Structure(e)
    }
}

/// One blob's staged verification result.
enum Staged {
    Restored(Zeroizing<Vec<u8>>),
    Invalid,
}

fn stage_blob(
    trusted: &TrustedImage,
    sms: &Secret32,
    image_id: &[u8; 16],
    blob: &HookBlob,
) -> Staged {
    if blob.sealed.len() < TAG_LEN {
        return Staged::Invalid;
    }
    let key = match blob.mode {
        SealMode::Image => trusted.hook_key(&blob.name),
        SealMode::Anchor => derive_hook_anchor_key(sms, &blob.name),
    };
    let (ct, tag) = blob.sealed.split_at(blob.sealed.len() - TAG_LEN);
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);
    let mut plain = ct.to_vec();
    if !chacha20_poly1305_open(
        &key,
        &blob_nonce(image_id),
        &blob_aad(image_id, blob.mode, &blob.name),
        &mut plain,
        &tag_arr,
    ) {
        return Staged::Invalid;
    }
    Staged::Restored(Zeroizing::new(plain))
}

/// Run the unseal fan-out over `hooks` in forward registration
/// order, from a fully verified image. `sms` is the epoch's slot
/// master secret (obtained by the resume path's factor unwrap —
/// the same value [`super::open_with_sms`] consumed); it is used
/// only to derive anchor-mode hook keys and never leaves this call.
/// `device_resumed` is the coordinator's predicate over hook names,
/// fed from the `device_pm` resume report (design §5.2 rule 4).
///
/// Staging (AEAD-open of every blob) completes before the first
/// `unseal` callback runs; see the module docs, rule 5.
pub fn run_unseal_fanout(
    trusted: &TrustedImage,
    store: &dyn ImageStore,
    sms: &Secret32,
    hooks: &[Arc<dyn SuspendStateHook>],
    device_resumed: &dyn Fn(&str) -> bool,
) -> Result<UnsealFanoutReport, UnsealFanoutError> {
    let image_id = trusted.claims().image_id;
    let region = trusted.read_hook_region(store)?;
    let blobs = decode_hook_region(&region)?;

    // Stage: verify every blob before any callback runs.
    let mut staged: Vec<(HookBlob, Staged)> = Vec::with_capacity(blobs.len());
    for blob in blobs {
        let outcome = stage_blob(trusted, sms, &image_id, &blob);
        staged.push((blob, outcome));
    }

    // A critical hook whose device resumed and whose blob failed
    // verification aborts the resume before any delivery.
    for hook in hooks {
        if !hook.critical() || !device_resumed(hook.name()) {
            continue;
        }
        let invalid = staged
            .iter()
            .any(|(blob, s)| blob.name == hook.name() && matches!(s, Staged::Invalid));
        if invalid {
            return Err(UnsealFanoutError::CriticalBlobInvalid {
                hook: String::from(hook.name()),
                report: UnsealFanoutReport::default(),
            });
        }
    }

    let mut report = UnsealFanoutReport::default();
    // Orphaned blobs: present in the image, no registered hook.
    for (blob, _) in &staged {
        if !hooks.iter().any(|h| h.name() == blob.name) {
            report.orphaned_blobs.push(blob.name.clone());
        }
    }

    for hook in hooks {
        let name = hook.name();
        if !device_resumed(name) {
            report.entries.push(UnsealEntry {
                name: String::from(name),
                outcome: UnsealOutcome::SkippedDeviceDown,
            });
            continue;
        }
        // Move this hook's staged outcomes out for delivery (the
        // staged slot is left as Invalid, which is never read again:
        // each (name, mode) pair is delivered exactly once).
        let mut image_outcome = BlobOutcome::Missing;
        let mut anchor_outcome = BlobOutcome::Missing;
        for (blob, staged_outcome) in staged.iter_mut() {
            if blob.name != name {
                continue;
            }
            let slot = match blob.mode {
                SealMode::Image => &mut image_outcome,
                SealMode::Anchor => &mut anchor_outcome,
            };
            match core::mem::replace(staged_outcome, Staged::Invalid) {
                Staged::Restored(plain) => *slot = BlobOutcome::Restored(plain),
                Staged::Invalid => *slot = BlobOutcome::Invalid,
            }
        }
        let mut ctx = UnsealCtx::new(image_outcome, anchor_outcome);
        match hook.unseal(&mut ctx) {
            Ok(()) => report.entries.push(UnsealEntry {
                name: String::from(name),
                outcome: UnsealOutcome::Delivered,
            }),
            Err(error) => {
                if hook.critical() {
                    report.entries.push(UnsealEntry {
                        name: String::from(name),
                        outcome: UnsealOutcome::Failed(error.clone()),
                    });
                    return Err(UnsealFanoutError::CriticalHookFailed {
                        hook: String::from(name),
                        error,
                        report,
                    });
                }
                report.entries.push(UnsealEntry {
                    name: String::from(name),
                    outcome: UnsealOutcome::Failed(error),
                });
            }
        }
    }
    Ok(report)
}

/// [`run_unseal_fanout`] over the global registry's snapshot.
pub fn unseal_registered(
    trusted: &TrustedImage,
    store: &dyn ImageStore,
    sms: &Secret32,
    device_resumed: &dyn Fn(&str) -> bool,
) -> Result<UnsealFanoutReport, UnsealFanoutError> {
    run_unseal_fanout(trusted, store, sms, &registered_hooks(), device_resumed)
}

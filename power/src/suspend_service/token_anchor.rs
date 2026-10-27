//! The FIDO token custody anchor (power-suspend design §4, lane
//! P5 #1001): a [`KeyCustodyAnchor`] whose factor is a CTAP2
//! authenticator speaking the `hmac-secret` extension through
//! `narf-ctap2`, over the transport-agnostic
//! [`HidPipe`](narf_ctap2::ctaphid::HidPipe) seam.
//!
//! The ceremony, on both sides of the seam:
//!
//! - **Wrap (enrollment time, running system).** The anchor is
//!   constructed around the token being enrolled (its credential
//!   id comes from `narf_ctap2::enroll::enroll_token`, which owns
//!   credential creation and PIN setup). `wrap` draws a fresh
//!   32-byte slot salt, runs one `derive_slot_output` assertion
//!   against it, and AEAD-wraps the SMS under
//!   `KEK = HKDF-SHA256(output, "narf-suspend/token-slot" ‖ epoch)`
//!   (design §4.2) with the epoch and credential id as AAD. The
//!   hmac-secret output and the KEK exist only inside the call;
//!   neither is stored anywhere. The slot `params` carry exactly
//!   what resume needs to repeat the derivation: the credential
//!   id and the salt.
//! - **Unwrap (resume time, resume environment).** The anchor is
//!   deliberately *not* bound to one credential: the slot record
//!   names the credential, and the ceremony asserts against
//!   whichever enrolled credential the record carries. A plugged
//!   token that does not hold that credential refuses with
//!   `CTAP2_ERR_NO_CREDENTIALS`, the anchor returns
//!   [`AnchorError::Refused`], and `attempt_resume` moves on to
//!   the next slot — which is how a backup token resumes an
//!   image whose primary slot was tried first (design §4.9).
//!   Presence is the token's own requirement: the assertion
//!   parks until the user touches, and no code path in this
//!   module can produce an output without that touch.
//!
//! PIN discipline (the decided touch+PIN default, design §4.5):
//! the PIN is collected through the [`TokenUserInterface`] seam
//! *inside* the ceremony and never stored on the anchor. A wrong
//! PIN is answered from the token's own retry counter: the
//! ceremony reads the remaining count back (`pin_retries`),
//! announces it, and asks again while the interface supplies
//! PINs. The token enforces the lockout — after its retries are
//! spent it blocks PIN auth and the ceremony refuses. There is
//! no fallback from a failed PIN ceremony to a weaker factor:
//! every failure leaves this module as a typed [`AnchorError`]
//! and `attempt_resume` decides what that means (in practice:
//! try the next slot, else `FactorRefused`).
//!
//! Prompt discipline: the interface's lines are instructions
//! and attempt outcomes ("insert your resume token…", "wrong
//! PIN — N attempts remain"). They never state the recorded
//! policy as fact; that phrasing belongs to `attempt_resume`,
//! which announces claims as attempts and facts only after
//! verification (design §6.2 step 2).
//!
//! Transport scope, stated plainly: this module is generic
//! over the pipe. The running system binds `narf-ctap2` to its
//! xHCI stack (lane P3); the resume environment binds the same
//! client to its polled HID transport when the boot wiring
//! lands — the same follow-on that owns partition discovery
//! and calling [`resume_with_token`] from the boot path, and
//! the secure-boot verification of the resume loader
//! (design §6.2 step 1). Fixtures bind the pipe to P3's
//! independent fixture authenticator.

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroizing;

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_ctap2::ctaphid::HidPipe;
use narf_ctap2::enroll::{derive_slot_output, DeriveParams};
use narf_ctap2::status::{
    CTAP2_ERR_INVALID_CREDENTIAL, CTAP2_ERR_NO_CREDENTIALS, CTAP2_ERR_PIN_AUTH_BLOCKED,
    CTAP2_ERR_PIN_BLOCKED,
};
use narf_ctap2::{Client, Error as CtapError, RandomSource};
use narf_lib::sync::IrqSafeSpinLock;

use super::anchor::{AnchorError, AnchorKind, KeyCustodyAnchor, UnwrapCtx, WrapCtx, WrappedSlot};
use super::custody::Secret32;
use super::format::ImageStore;
use super::resume::{attempt_resume, ResumePrompt, ResumeRefusal, VerifiedResume};

/// The relying-party id every suspend credential is enrolled
/// under (P3's landed constant; the credential's identity binds
/// it, so enrollment and resume must agree on it forever).
pub const SUSPEND_RP_ID: &str = "suspend.narf";

/// User name recorded on suspend credentials at enrollment.
pub const SUSPEND_USER_NAME: &str = "keys";

/// The fixed client-data hash of the suspend flows. The flows
/// have no web origin and no user-supplied client data: the
/// "client data" is this protocol constant, identical at
/// enrollment and at resume (it feeds the assertion's
/// pinUvAuthParam, never the hmac-secret output itself, which
/// depends only on the credential secret and the slot salt).
pub fn suspend_client_data_hash() -> [u8; 32] {
    hkdf32(b"narf-suspend/ctap-client-data", b"client-data-hash")
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// How the token's user verification is driven, mirroring
/// `narf_ctap2::enroll::PinSetup`'s policy choice at the anchor
/// level. The anchor's mode is part of the machine's configured
/// policy, set the same way at enrollment and at resume.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenPinMode {
    /// Touch + PIN: the decided default for token-only unlock
    /// (design §4.5). The PIN is collected per ceremony through
    /// the user interface; the token's hardware retry limit is
    /// the lockout.
    TouchAndPin,
    /// Touch only: assertion without user verification. An
    /// explicit policy choice, never the default.
    TouchOnly,
}

/// The ceremony's voice and ears: one line of output at a time,
/// and PIN collection. A separate seam from [`ResumePrompt`]
/// because the ceremony happens *inside* `unwrap`, where
/// `attempt_resume`'s prompt cannot reach — and because PIN
/// entry is input, which `ResumePrompt` deliberately is not.
pub trait TokenUserInterface {
    /// Emit one line of ceremony output: an instruction or an
    /// attempt outcome, never a policy fact.
    fn say(&mut self, line: &str);

    /// Collect one PIN entry. `retries_remaining` is the
    /// token's own remaining-retry count when the ceremony just
    /// learned it (a wrong PIN was presented); `None` for the
    /// first ask or when the count could not be read. Returning
    /// `None` abandons the ceremony (the user gave up, or input
    /// ended) and the unwrap refuses.
    fn read_pin(&mut self, retries_remaining: Option<u64>) -> Option<Zeroizing<Vec<u8>>>;
}

/// Production user interface over the early console
/// (`narf-console`): output via `write_str`, PIN entry polled
/// byte-by-byte from `try_read_byte` with `*` echo, backspace
/// editing, and no plaintext echo. PINs are capped at 63 bytes
/// (the CTAP2 maximum); an empty entry is an abandonment.
#[derive(Debug)]
pub struct ConsoleTokenUi;

impl TokenUserInterface for ConsoleTokenUi {
    fn say(&mut self, line: &str) {
        narf_console::write_str(line);
        narf_console::write_str("\n");
    }

    fn read_pin(&mut self, _retries_remaining: Option<u64>) -> Option<Zeroizing<Vec<u8>>> {
        let mut pin: Vec<u8> = Vec::new();
        loop {
            let byte = match narf_console::try_read_byte() {
                Some(b) => b,
                None => {
                    core::hint::spin_loop();
                    continue;
                }
            };
            match byte {
                b'\r' | b'\n' => {
                    narf_console::write_str("\n");
                    if pin.is_empty() {
                        return None;
                    }
                    return Some(Zeroizing::new(pin));
                }
                0x08 | 0x7f => {
                    if pin.pop().is_some() {
                        narf_console::write_str("\u{8} \u{8}");
                    }
                }
                0x20..=0x7e => {
                    if pin.len() < 63 {
                        pin.push(byte);
                        narf_console::write_str("*");
                    }
                }
                _ => {}
            }
        }
    }
}

/// Construction parameters for a [`TokenAnchor`].
#[derive(Clone, Debug)]
pub struct TokenAnchorConfig {
    /// PIN policy for both wrap and unwrap ceremonies.
    pub pin_mode: TokenPinMode,
    /// The credential this anchor enrolls (wrap side). Set from
    /// `enroll_token`'s output at enrollment time; `None` for a
    /// resume-side anchor, which is unwrap-only — the slot
    /// records name the credentials there.
    pub enroll_credential: Option<Vec<u8>>,
    /// RP id override; production uses [`SUSPEND_RP_ID`].
    pub rp_id: &'static str,
}

impl Default for TokenAnchorConfig {
    fn default() -> Self {
        Self {
            pin_mode: TokenPinMode::TouchAndPin,
            enroll_credential: None,
            rp_id: SUSPEND_RP_ID,
        }
    }
}

/// Slot `params` framing, version 1:
/// `version(1) ‖ cred_id_len(2, LE) ‖ cred_id ‖ salt(32)`.
const PARAMS_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
/// Slot `blob` framing: `nonce(12) ‖ ciphertext(32) ‖ tag(16)`,
/// the suspend service's AEAD wrap shape.
const NONCE_LEN: usize = 12;
const BLOB_LEN: usize = NONCE_LEN + 32 + 16;
/// Hard cap on PIN entries per ceremony. The token's own retry
/// limit (8) blocks long before this; the cap exists so a user
/// interface that never gives up cannot spin the ceremony.
const MAX_PIN_ATTEMPTS: usize = 16;

fn write_params(credential_id: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + credential_id.len() + SALT_LEN);
    out.push(PARAMS_VERSION);
    out.extend_from_slice(&(credential_id.len() as u16).to_le_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(salt);
    out
}

/// Parse slot params strictly: exact version, exact total
/// length, non-empty credential. Anything else is a malformed
/// slot, reported as an anchor failure (the service's no-oracle
/// discipline: malformed and tampered are one class).
fn read_params(params: &[u8]) -> Option<(Vec<u8>, [u8; SALT_LEN])> {
    if params.len() < 3 + SALT_LEN || params[0] != PARAMS_VERSION {
        return None;
    }
    let cred_len = u16::from_le_bytes([params[1], params[2]]) as usize;
    if cred_len == 0 || params.len() != 3 + cred_len + SALT_LEN {
        return None;
    }
    let credential_id = params[3..3 + cred_len].to_vec();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&params[3 + cred_len..]);
    Some((credential_id, salt))
}

fn slot_kek(hmac_output: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(28);
    info.extend_from_slice(b"narf-suspend/token-slot");
    info.extend_from_slice(&epoch.to_le_bytes());
    hkdf32(hmac_output, &info)
}

fn slot_aad(epoch: u64, credential_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + credential_id.len());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(credential_id);
    aad
}

/// A custody anchor backed by one CTAP2 authenticator session.
/// Generic over the transport (`HidPipe`), the client's
/// randomness, and the ceremony's user interface, so the same
/// anchor serves the running system's enrollment, the resume
/// environment, and the fixtures.
pub struct TokenAnchor<P: HidPipe, R: RandomSource, U: TokenUserInterface> {
    client: IrqSafeSpinLock<Client<P, R>>,
    ui: IrqSafeSpinLock<U>,
    config: TokenAnchorConfig,
}

/// Deliberately shallow: the anchor holds a live authenticator
/// session, and its `Debug` shows the ceremony posture only —
/// never session state, credential ids, or key material.
impl<P: HidPipe, R: RandomSource, U: TokenUserInterface> fmt::Debug for TokenAnchor<P, R, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenAnchor")
            .field("pin_mode", &self.config.pin_mode)
            .field("rp_id", &self.config.rp_id)
            .field("enrollment_side", &self.config.enroll_credential.is_some())
            .finish()
    }
}

impl<P: HidPipe, R: RandomSource, U: TokenUserInterface> TokenAnchor<P, R, U> {
    /// Open a session to the authenticator on `pipe` now
    /// (`Client::connect` runs CTAPHID INIT, the capability
    /// check, and `getInfo` — together they prove a CTAP2
    /// authenticator is actually answering). Any failure (no
    /// device, no answer, garbage) is the raw client error —
    /// callers deciding presence (see [`resume_with_token`])
    /// treat every connect failure as "no token factor here".
    pub fn connect(pipe: P, rng: R, ui: U, config: TokenAnchorConfig) -> Result<Self, CtapError> {
        let client = Client::connect(pipe, rng)?;
        Ok(Self::from_client(client, ui, config))
    }

    /// Adopt an already-connected client session (enrollment
    /// drives `enroll_token` on its own client first, then hands
    /// the session to the anchor for the wrap).
    pub fn from_client(client: Client<P, R>, ui: U, config: TokenAnchorConfig) -> Self {
        Self {
            client: IrqSafeSpinLock::new(client),
            ui: IrqSafeSpinLock::new(ui),
            config,
        }
    }

    /// Run one hmac-secret derivation against `credential_id`
    /// with the ceremony's PIN discipline: announce, collect the
    /// PIN when the mode demands it, assert, and on a wrong PIN
    /// read the token's remaining retries back and ask again.
    /// Returns the 32-byte slot output. Every failure is a typed
    /// anchor error; the distinctions that survive are exactly
    /// the ones `attempt_resume` may act on: `Refused` (this
    /// factor did not satisfy — wrong credential, no presence,
    /// PIN blocked or abandoned) vs `Failed` (the conversation
    /// itself broke — proof or framing invalid).
    fn derive_with_ceremony(
        &self,
        credential_id: &[u8],
        salt: [u8; SALT_LEN],
    ) -> Result<[u8; 32], AnchorError> {
        {
            let mut ui = self.ui.lock();
            ui.say("power: token factor selected; touch your resume token when it blinks");
        }
        let mut retries_hint: Option<u64> = None;
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            if attempts > MAX_PIN_ATTEMPTS {
                return Err(AnchorError::Refused);
            }
            let pin = match self.config.pin_mode {
                TokenPinMode::TouchOnly => None,
                TokenPinMode::TouchAndPin => {
                    let mut ui = self.ui.lock();
                    match ui.read_pin(retries_hint) {
                        Some(pin) => Some(pin),
                        None => return Err(AnchorError::Refused),
                    }
                }
            };
            let result = {
                let mut client = self.client.lock();
                derive_slot_output(
                    &mut client,
                    &DeriveParams {
                        client_data_hash: suspend_client_data_hash(),
                        rp_id: self.config.rp_id,
                        credential_id,
                        salt1: salt,
                        salt2: None,
                        pin: pin.as_ref().map(|p| p.as_slice()),
                    },
                )
            };
            match result {
                Ok(output) => return Ok(output.first),
                Err(e) if e.is_pin_invalid() => {
                    // The token decremented its own counter; read
                    // the authoritative remainder back and surface
                    // it — never guess the count locally.
                    let remaining = {
                        let mut client = self.client.lock();
                        client.pin_retries().ok()
                    };
                    {
                        let mut ui = self.ui.lock();
                        match remaining {
                            Some(0) => {
                                ui.say("power: wrong PIN; the token reports no attempts remain");
                                return Err(AnchorError::Refused);
                            }
                            Some(n) => ui.say(&format!(
                                "power: wrong PIN; the token reports {n} attempts remain"
                            )),
                            None => ui.say("power: wrong PIN"),
                        }
                    }
                    retries_hint = remaining;
                }
                Err(CtapError::Ctap(CTAP2_ERR_PIN_BLOCKED | CTAP2_ERR_PIN_AUTH_BLOCKED)) => {
                    let mut ui = self.ui.lock();
                    ui.say("power: the token has blocked PIN authentication");
                    return Err(AnchorError::Refused);
                }
                Err(CtapError::Ctap(CTAP2_ERR_NO_CREDENTIALS | CTAP2_ERR_INVALID_CREDENTIAL)) => {
                    // The plugged token does not hold this slot's
                    // credential: an ordinary refusal that lets
                    // attempt_resume try the next slot (the
                    // backup token's).
                    return Err(AnchorError::Refused);
                }
                Err(CtapError::Timeout) => return Err(AnchorError::Unavailable),
                Err(_) => return Err(AnchorError::Failed),
            }
        }
    }
}

impl<P: HidPipe + Send, R: RandomSource + Send, U: TokenUserInterface + Send> KeyCustodyAnchor
    for TokenAnchor<P, R, U>
{
    fn kind(&self) -> AnchorKind {
        AnchorKind::Token
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        // Wrap is the enrollment-time act and is bound to the
        // credential this anchor was constructed around. A
        // resume-side anchor (no enroll credential) cannot wrap.
        let credential_id = self
            .config
            .enroll_credential
            .clone()
            .ok_or(AnchorError::Failed)?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        {
            let mut client = self.client.lock();
            client
                .rng_mut()
                .fill_random(&mut salt)
                .map_err(|_| AnchorError::Failed)?;
            client
                .rng_mut()
                .fill_random(&mut nonce)
                .map_err(|_| AnchorError::Failed)?;
        }
        let output = self.derive_with_ceremony(&credential_id, salt)?;
        let kek = Zeroizing::new(slot_kek(&output, ctx.sms_epoch));
        let aad = slot_aad(ctx.sms_epoch, &credential_id);
        let mut ct = [0u8; 32];
        secret.with_bytes(|s| ct.copy_from_slice(s));
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::with_capacity(BLOB_LEN);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        Ok(WrappedSlot {
            params: write_params(&credential_id, &salt),
            blob,
        })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        let (credential_id, salt) = read_params(&slot.params).ok_or(AnchorError::Failed)?;
        if slot.blob.len() != BLOB_LEN {
            return Err(AnchorError::Failed);
        }
        let output = self.derive_with_ceremony(&credential_id, salt)?;
        let kek = Zeroizing::new(slot_kek(&output, ctx.sms_epoch));
        let aad = slot_aad(ctx.sms_epoch, &credential_id);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&slot.blob[..NONCE_LEN]);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&slot.blob[NONCE_LEN..NONCE_LEN + 32]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&slot.blob[NONCE_LEN + 32..]);
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            // A wrong output (different token, substituted slot)
            // and a tampered blob are one class here, exactly as
            // at every other custody boundary in the service.
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

/// Drive one token-policy resume attempt (design §4.4): probe
/// for a token, and hand `attempt_resume` the token anchor when
/// one answered. When no token answers the probe, the attempt
/// proceeds with **no** token anchor, so a token-policy image
/// refuses as [`ResumeRefusal::FactorUnavailable`] — the
/// recorded-policy class for "the factor is not here" — rather
/// than the `FactorRefused` a present-but-failing token earns,
/// and rather than any weaker path (design §10.3: absence never
/// degrades the policy). Every other policy level flows through
/// `attempt_resume`'s own handling unchanged.
pub fn resume_with_token<
    P: HidPipe + Send,
    R: RandomSource + Send,
    U: TokenUserInterface + Send,
>(
    store: &dyn ImageStore,
    pipe: P,
    rng: R,
    ui: U,
    config: TokenAnchorConfig,
    prompt: &mut dyn ResumePrompt,
) -> Result<VerifiedResume, ResumeRefusal> {
    match TokenAnchor::connect(pipe, rng, ui, config) {
        Ok(anchor) => attempt_resume(store, &[&anchor], prompt),
        Err(_) => attempt_resume(store, &[], prompt),
    }
}

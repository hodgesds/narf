//! The TPM custody anchor (power-suspend design §8.3, lane P6
//! #1002): a [`KeyCustodyAnchor`] that seals the per-epoch slot
//! master secret to the platform TPM, bound to the measured-boot
//! PCR state.
//!
//! ## Construction (design §8.3, pinned there)
//!
//! - **Wrap.** The seal policy is computed through a *trial*
//!   session: `PolicyPCR` over the recorded selection with the
//!   digest of the PCRs' *current* values, read back with
//!   `PolicyGetDigest` — that digest becomes the sealed object's
//!   `authPolicy`. The object is a KEYEDHASH data blob
//!   (`objects::keyedhash_seal_template`, caller-supplied data:
//!   `sensitiveDataOrigin` CLEAR) created under an owner-hierarchy
//!   RSA-2048 storage primary that is regenerated from its
//!   template on every use and flushed immediately after, so no
//!   primary material ever persists in the service.
//! - **Unwrap.** The primary is regenerated, the sealed object
//!   loaded, and a fresh *policy* session satisfies the same
//!   `PolicyPCR` — this time with an empty digest argument, so
//!   the TPM itself compares its own computed PCR digest
//!   (Part 3 §23.7). `Unseal` releases the secret only when the
//!   session's digest equals the object's `authPolicy`; any PCR
//!   drift since sealing — a firmware update, a different boot
//!   chain — is `TPM_RC_POLICY_FAIL`, mapped to
//!   [`AnchorError::Refused`]. The policy session carries
//!   `continueSession = 0` at the Unseal, so it cannot be
//!   replayed by a later caller.
//! - **PCR selection (§8.3).** The firmware SRTM range 0–7 plus
//!   the PCRs the NARF boot chain extends (4/5/6 already inside
//!   the range, 9/10 outside it): `[0,1,2,3,4,5,6,7,9,10]` in the
//!   SHA-256 bank. Firmware updates change PCR 0, so a
//!   post-update refusal is an expected event with a documented
//!   remedy (re-enroll under the still-current factors), never a
//!   silent bypass.
//! - **Epoch.** The monotonic source is the NV counter index
//!   [`tpm_nv::NV_IDX_SUSPEND_EPOCH`]: `epoch()` reads it,
//!   `advance_epoch()` increments it (defining it on first use).
//!   The wrap-time epoch is recorded in the slot `params` and an
//!   unwrap whose context epoch disagrees is refused before the
//!   TPM is touched.
//! - **Absence (design §10.2 discipline).** The anchor is only
//!   ever constructed over a transport. A transport-level
//!   failure is [`AnchorError::Unavailable`] — the factor is
//!   absent — never a fallback to a weaker policy and never a
//!   service-wide failure: token and passphrase policies on a
//!   TPM-less machine are untouched by this anchor's state.
//!   Production construction reads the platform injection point
//!   ([`TpmAnchor::production`]); when nothing is registered
//!   there, no anchor exists at all.
//!
//! Deliberately absent (later lanes): HMAC / parameter-encrypted
//! sessions (§8.3 follow-up), TPM lockout recovery (#1003 owns
//! the lifecycle), and policy composition *storage* (§8.5/P8 —
//! the composition this anchor enables is expressed through the
//! slot set the service records, one slot per factor).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_drivers_tpm::devfs_bridge::{self, TpmTransport};
use narf_drivers_tpm::tpm2::{
    commands as cmds, nv as tpm_nv, objects, TPM_ALG_SHA256, TPM_RC_LOCKOUT, TPM_RC_POLICY_FAIL,
    TPM_RC_SUCCESS, TPM_RH_NULL, TPM_RH_OWNER, TPM_SE_POLICY, TPM_SE_TRIAL,
};
use zeroize::Zeroizing;

use super::anchor::{AnchorError, AnchorKind, KeyCustodyAnchor, UnwrapCtx, WrapCtx, WrappedSlot};
use super::custody::Secret32;

/// Slot `params` version byte (params layout v1).
const PARAMS_VERSION: u8 = 0x01;
/// params: version(1) ‖ algorithm(2, BE) ‖ selection mask(3) ‖
/// SMS epoch at wrap(8, BE).
const PARAMS_LEN: usize = 1 + 2 + 3 + 8;

/// The §8.3 PCR selection in the SHA-256 bank: PCRs 0–7
/// (firmware SRTM), 9, 10 (NARF boot-chain extensions beyond the
/// SRTM range). Mask bytes are little-endian per PCR byte, as
/// `TPMS_PCR_SELECTION` marshals them.
const POLICY_PCRS: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10];
const POLICY_MASK: [u8; 3] = [0xFF, 0x06, 0x00];

/// A custody anchor backed by TPM 2.0 sealing. Holds no key
/// material: the primary is a derivation, the sealed object is
/// the caller's slot record, and the SMS transits the TPM only
/// as `inSensitive` data on wrap and `outData` on unwrap.
pub struct TpmAnchor {
    transport: Arc<dyn TpmTransport>,
    nonces: AtomicU64,
}

impl fmt::Debug for TpmAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmAnchor")
    }
}

impl TpmAnchor {
    /// An anchor over an explicit transport (fixtures, and the
    /// resume environment's own injection).
    pub fn with_transport(transport: Arc<dyn TpmTransport>) -> Self {
        Self {
            transport,
            nonces: AtomicU64::new(0),
        }
    }

    /// The production anchor: the transport the platform probe
    /// registered ([`devfs_bridge::installed_transport`]).
    /// `None` on a TPM-less machine — the anchor is simply not
    /// part of that machine's factor set.
    pub fn production() -> Option<Self> {
        devfs_bridge::installed_transport().map(Self::with_transport)
    }

    /// Submit one command and classify the outcome. Transport
    /// failure is the factor's absence (`Unavailable`); a policy
    /// refusal or DA lockout is the factor's answer (`Refused`);
    /// every other response code is a malfunction-class failure
    /// (`Failed`) — deliberately one bucket, so no caller can
    /// build an oracle out of TPM return codes.
    fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let raw = self
            .transport
            .submit(cmd)
            .map_err(|()| AnchorError::Unavailable)?;
        match cmds::response_rc(&raw) {
            Some(TPM_RC_SUCCESS) => Ok(raw),
            // Exact codes (Part 2 §6.6): TPM returns
            // TPM_RC_POLICY_FAIL verbatim for an Unseal whose
            // policy session does not satisfy the object, and
            // TPM_RC_LOCKOUT verbatim for DA lockout. Anything
            // else — including any augmented variant — falls in
            // the no-oracle bucket below, never in Refused's
            // neighbours.
            Some(TPM_RC_POLICY_FAIL) | Some(TPM_RC_LOCKOUT) => Err(AnchorError::Refused),
            Some(_) | None => Err(AnchorError::Failed),
        }
    }

    /// Best-effort context flush: cleanup only — its outcome
    /// never changes the result of the operation that needed the
    /// handle gone.
    fn flush(&self, handle: u32) {
        let _ = self.transport.submit(&cmds::flush_context(handle));
    }

    fn next_nonce(&self) -> [u8; 32] {
        let n = self.nonces.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 32];
        nonce[..23].copy_from_slice(b"narf-suspend-tpm-anchor");
        nonce[23..31].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    fn start_session(&self, kind: u8) -> Result<u32, AnchorError> {
        let raw = self.submit(&cmds::start_auth_session(
            TPM_RH_NULL,
            TPM_RH_NULL,
            &self.next_nonce(),
            &[],
            kind,
            TPM_ALG_SHA256,
        ))?;
        let (handle, _nonce_tpm) =
            cmds::parse_start_auth_session_response(&raw).map_err(|_| AnchorError::Failed)?;
        Ok(handle)
    }

    /// Regenerate the owner storage primary. The template is a
    /// constant, so the derivation — and therefore the primary —
    /// is the same at wrap and unwrap; it is flushed by the
    /// caller as soon as the child operation completes.
    fn create_primary(&self) -> Result<u32, AnchorError> {
        let raw = self.submit(&cmds::create_primary(
            TPM_RH_OWNER,
            &[],
            &objects::rsa2048_template(objects::OBJ_ATTR_STORAGE),
        ))?;
        let (handle, _outputs) =
            cmds::parse_create_primary_response(&raw).map_err(|_| AnchorError::Failed)?;
        Ok(handle)
    }

    /// Compute the seal-time `authPolicy`: run `PolicyPCR` on a
    /// trial session over the digest of the PCRs' current values
    /// and read the resulting session digest back. Per Part 3
    /// §23.7 (equations 19/20), a trial session folds the
    /// caller-provided digest in unchecked — here the provided
    /// digest is the TPM's own PCR_Read composite, so the
    /// policy names exactly the state the TPM reports now.
    fn auth_policy(&self) -> Result<[u8; 32], AnchorError> {
        let session = self.start_session(TPM_SE_TRIAL)?;
        let result = self.auth_policy_in(session);
        self.flush(session);
        result
    }

    fn auth_policy_in(&self, session: u32) -> Result<[u8; 32], AnchorError> {
        let raw = self.submit(&cmds::pcr_read(TPM_ALG_SHA256, &POLICY_MASK))?;
        let read = cmds::parse_pcr_read_response(&raw).map_err(|_| AnchorError::Failed)?;
        if read.digests.len() != POLICY_PCRS.len() {
            return Err(AnchorError::Failed);
        }
        // Part 1, "Selecting Multiple PCR": the composite digest
        // is H of the selected PCR values concatenated in
        // increasing PCR order. narf-crypto's streaming SHA-256
        // keeps the values out of a heap buffer.
        let mut hasher = narf_crypto::sha256::Sha256::new();
        for digest in &read.digests {
            if digest.len() != 32 {
                return Err(AnchorError::Failed);
            }
            hasher.update(digest);
        }
        let composite = hasher.finalize();
        self.submit(&cmds::policy_pcr(
            session,
            &composite,
            &[(TPM_ALG_SHA256, &POLICY_MASK)],
        ))?;
        let raw = self.submit(&cmds::policy_get_digest(session))?;
        let digest =
            cmds::parse_policy_get_digest_response(&raw).map_err(|_| AnchorError::Failed)?;
        digest.try_into().map_err(|_| AnchorError::Failed)
    }

    fn read_epoch(&self) -> Result<u64, AnchorError> {
        let raw = self.submit(&cmds::nv_read(tpm_nv::NV_IDX_SUSPEND_EPOCH, 8, 0))?;
        let data = cmds::parse_nv_read_response(&raw).map_err(|_| AnchorError::Failed)?;
        if data.len() != 8 {
            return Err(AnchorError::Failed);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data);
        Ok(u64::from_be_bytes(buf))
    }
}

impl KeyCustodyAnchor for TpmAnchor {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Tpm
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        let policy = self.auth_policy()?;
        let primary = self.create_primary()?;
        let result = self.wrap_under(primary, &policy, secret);
        self.flush(primary);
        let created = result?;
        let mut blob = Vec::with_capacity(4 + created.out_private.len() + created.out_public.len());
        blob.extend_from_slice(&(created.out_private.len() as u16).to_be_bytes());
        blob.extend_from_slice(&created.out_private);
        blob.extend_from_slice(&(created.out_public.len() as u16).to_be_bytes());
        blob.extend_from_slice(&created.out_public);
        let mut params = Vec::with_capacity(PARAMS_LEN);
        params.push(PARAMS_VERSION);
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        params.extend_from_slice(&POLICY_MASK);
        params.extend_from_slice(&ctx.sms_epoch.to_be_bytes());
        Ok(WrappedSlot { params, blob })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        if slot.params.len() != PARAMS_LEN || slot.params[0] != PARAMS_VERSION {
            return Err(AnchorError::Failed);
        }
        let alg = u16::from_be_bytes([slot.params[1], slot.params[2]]);
        if alg != TPM_ALG_SHA256 {
            return Err(AnchorError::Failed);
        }
        let mask: [u8; 3] = slot.params[3..6]
            .try_into()
            .map_err(|_| AnchorError::Failed)?;
        let mut epoch_buf = [0u8; 8];
        epoch_buf.copy_from_slice(&slot.params[6..14]);
        if u64::from_be_bytes(epoch_buf) != ctx.sms_epoch {
            // The slot belongs to another epoch: refuse before
            // the TPM is touched rather than unwrap into the
            // wrong epoch's custody.
            return Err(AnchorError::Failed);
        }
        let (private, public) = split_blob(&slot.blob)?;
        let primary = self.create_primary()?;
        let result = self.unwrap_under(primary, &mask, &private, &public);
        self.flush(primary);
        let data = result?;
        if data.len() != 32 {
            return Err(AnchorError::Failed);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&data);
        Ok(Secret32::mint(secret))
    }

    fn epoch(&self) -> Option<u64> {
        self.read_epoch().ok()
    }

    fn advance_epoch(&self) -> Result<Option<u64>, AnchorError> {
        if self
            .submit(&cmds::nv_increment(tpm_nv::NV_IDX_SUSPEND_EPOCH))
            .is_ok()
        {
            return self.read_epoch().map(Some);
        }
        // First use on this machine (index undefined), or the
        // increment failed for a reason defining cannot fix —
        // either way the sequence is the same: define the index
        // (result deliberately ignored; a pre-existing index is
        // equally fine), increment, and report what the counter
        // reads back. If the counter still will not move, the
        // failure class comes from the increment itself.
        let _ = self.submit(&tpm_nv::NARF_SUSPEND_EPOCH_NV.define_space_cmd());
        self.submit(&cmds::nv_increment(tpm_nv::NV_IDX_SUSPEND_EPOCH))?;
        self.read_epoch().map(Some)
    }
}

impl TpmAnchor {
    fn wrap_under(
        &self,
        primary: u32,
        policy: &[u8; 32],
        secret: &Secret32,
    ) -> Result<cmds::CreateOutputs, AnchorError> {
        let template = objects::keyedhash_seal_template(policy);
        let secret_bytes = Zeroizing::new(secret.with_bytes(|b| *b));
        let raw = self.submit(&cmds::create_sealed_object(
            primary,
            &*secret_bytes,
            &template,
        ))?;
        cmds::parse_create_response(&raw).map_err(|_| AnchorError::Failed)
    }

    fn unwrap_under(
        &self,
        primary: u32,
        mask: &[u8; 3],
        private: &[u8],
        public: &[u8],
    ) -> Result<Vec<u8>, AnchorError> {
        let raw = self.submit(&cmds::load(primary, private, public))?;
        let (object, _name) = cmds::parse_load_response(&raw).map_err(|_| AnchorError::Failed)?;
        let result = self.unseal_loaded(object, mask);
        self.flush(object);
        result
    }

    fn unseal_loaded(&self, object: u32, mask: &[u8; 3]) -> Result<Vec<u8>, AnchorError> {
        let session = self.start_session(TPM_SE_POLICY)?;
        // Empty pcrDigest: the TPM computes the digest of the
        // PCRs' current values itself and refuses the command if
        // its own policy-update rules are violated — the check
        // that matters is Unseal's, next.
        let policy_result = self.submit(&cmds::policy_pcr(session, &[], &[(TPM_ALG_SHA256, mask)]));
        if let Err(e) = policy_result {
            self.flush(session);
            return Err(e);
        }
        // continueSession = 0 in unseal_with_session: the TPM
        // flushes the policy session as part of the command,
        // success or failure, so nothing here flushes it again.
        let raw = self.submit(&cmds::unseal_with_session(object, session))?;
        cmds::parse_unseal_response(&raw).map_err(|_| AnchorError::Failed)
    }
}

/// Split a slot blob into its `(private, public)` TPM2B payloads,
/// requiring exact consumption: trailing bytes are a malformed
/// slot, not padding.
fn split_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AnchorError> {
    let mut pos = 0usize;
    let mut take = |blob: &[u8]| -> Result<Vec<u8>, AnchorError> {
        if blob.len() < pos + 2 {
            return Err(AnchorError::Failed);
        }
        let len = u16::from_be_bytes([blob[pos], blob[pos + 1]]) as usize;
        pos += 2;
        if blob.len() < pos + len {
            return Err(AnchorError::Failed);
        }
        let out = blob[pos..pos + len].to_vec();
        pos += len;
        Ok(out)
    };
    let private = take(blob)?;
    let public = take(blob)?;
    if pos != blob.len() {
        return Err(AnchorError::Failed);
    }
    Ok((private, public))
}

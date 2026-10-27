//! The credential-management surface the suspend service (lane
//! P1) consumes. This crate owns the token conversation; P1 owns
//! key custody — the seam is exactly these functions:
//!
//! - [`enroll_token`]: one token's enrollment. Creates a
//!   discoverable, `hmac-secret`-enabled credential, optionally
//!   configuring the token PIN first (the decided touch+PIN
//!   default). Verifies the authenticator actually granted the
//!   extension (authData ED extensions) — a token that returns a
//!   credential *without* hmac-secret is an enrollment failure,
//!   not a silent downgrade.
//! - [`derive_slot_output`]: resume-side derivation — one
//!   getAssertion with the caller-chosen salt, returning the
//!   hmac-secret output that wraps the per-epoch slot secret.
//!   Each enrolled token wraps independently: enrollment stores
//!   one wrapped blob *per token* (the primary and the backup
//!   have different credential keys and therefore different
//!   outputs for the same salt) — the two-token recovery story is
//!   "either token unwraps its own blob", not "both tokens are
//!   interchangeable".
//! - [`enrollment_complete`]: the mandatory-backup rule. An
//!   enrollment set is complete only with ≥ 2 DISTINCT credential
//!   ids. A single token is *incomplete by design* (decisions
//!   doc, 2026-10-26) — the caller (P1) must not treat one
//!   enrolled token as a finished setup.

extern crate alloc;

use alloc::vec::Vec;

use crate::cbor::Value;
use crate::client::{
    Client, CredentialRef, GetAssertionParams, HmacSecretOutput, HmacSecretParams, UserVerification,
};
use crate::ctaphid::HidPipe;
use crate::{Error, RandomSource};

/// How a token's user verification is set up at enrollment.
#[derive(Clone, Copy)]
pub enum PinSetup<'a> {
    /// Touch+PIN (the decided default for token-only unlock):
    /// if the token has no PIN yet, set this one; then enroll
    /// with UV via the PIN. If the token already has a PIN, the
    /// supplied PIN must be that PIN.
    TouchAndPin(&'a [u8]),
    /// Touch only: enroll without UV. Only for enrollment
    /// policies that explicitly choose it — never the default.
    TouchOnly,
}

/// Inputs for [`enroll_token`].
pub struct EnrollParams<'a> {
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub pin_setup: PinSetup<'a>,
}

/// What enrollment produced — the caller (P1) persists this
/// alongside the wrapped slot secret for this token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledToken {
    pub credential_id: Vec<u8>,
    pub aaguid: [u8; 16],
    pub rp_id: alloc::string::String,
    /// Attestation format from the enrollment response.
    pub fmt: alloc::string::String,
}

/// Enroll one authenticator: (maybe) set its PIN, create the
/// credential with the hmac-secret extension, and verify the
/// extension was granted.
pub fn enroll_token<P: HidPipe, R: RandomSource>(
    client: &mut Client<P, R>,
    params: &EnrollParams<'_>,
) -> Result<EnrolledToken, Error> {
    let info = client.get_info()?;
    if !info.supports_extension("hmac-secret") {
        return Err(Error::Unsupported(
            "authenticator does not list the hmac-secret extension",
        ));
    }

    let (pin, uv) = match params.pin_setup {
        PinSetup::TouchAndPin(pin) => {
            match info.client_pin_state() {
                // No clientPIN on this authenticator at all.
                None => return Err(Error::Unsupported("authenticator has no clientPin option")),
                // Supported but unset: configure it now.
                Some(false) => {
                    let session = client.pin_session()?;
                    session.set_pin(client.channel(), pin)?;
                    // The cached options map now lies; refresh.
                    client.refresh_info()?;
                }
                // Already set: the supplied PIN is used as-is and
                // make_credential will prove it.
                Some(true) => {}
            }
            (Some(pin), UserVerification::Required)
        }
        PinSetup::TouchOnly => (None, UserVerification::Discouraged),
    };

    let result = client.make_credential(&crate::client::MakeCredentialParams {
        client_data_hash: params.client_data_hash,
        rp_id: params.rp_id,
        rp_name: params.rp_name,
        user_id: params.user_id,
        user_name: params.user_name,
        user_display_name: None,
        exclude: &[],
        resident_key: true,
        user_verification: uv,
        pin,
    })?;

    // Verify the extension actually landed: ED flag + extensions
    // map must report hmac-secret == true.
    let granted = result
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.get_text("hmac-secret"))
        .map(|v| matches!(v, Value::Bool(true)))
        .unwrap_or(false);
    if !granted {
        return Err(Error::Unsupported(
            "authenticator did not grant hmac-secret at enrollment",
        ));
    }
    let attested = result
        .auth_data
        .attested
        .ok_or(Error::Protocol("enroll: no attested credential data"))?;
    Ok(EnrolledToken {
        credential_id: attested.credential_id,
        aaguid: attested.aaguid,
        rp_id: params.rp_id.into(),
        fmt: result.fmt,
    })
}

/// Inputs for [`derive_slot_output`].
pub struct DeriveParams<'a> {
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a str,
    pub credential_id: &'a [u8],
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
    /// PIN for the token (touch+PIN policy). `None` only for
    /// tokens enrolled touch-only.
    pub pin: Option<&'a [u8]>,
}

/// Derive the hmac-secret output for one enrolled token. The
/// returned 32 (or 64) bytes are the wrapping input P1 uses —
/// this crate does not wrap anything itself.
pub fn derive_slot_output<P: HidPipe, R: RandomSource>(
    client: &mut Client<P, R>,
    params: &DeriveParams<'_>,
) -> Result<HmacSecretOutput, Error> {
    let uv = if params.pin.is_some() {
        UserVerification::Required
    } else {
        UserVerification::Discouraged
    };
    let assertion = client.get_assertion(&GetAssertionParams {
        rp_id: params.rp_id,
        client_data_hash: params.client_data_hash,
        allow: &[CredentialRef::new(params.credential_id.to_vec())],
        user_verification: uv,
        hmac_secret: Some(HmacSecretParams {
            salt1: params.salt1,
            salt2: params.salt2,
        }),
        pin: params.pin,
    })?;
    // The token must answer for the credential we asked about —
    // a substituted credential would unwrap the wrong blob.
    if let Some(cred) = &assertion.credential {
        if cred.id != params.credential_id {
            return Err(Error::Protocol(
                "derive: assertion for a different credential",
            ));
        }
    }
    assertion.hmac_secret.ok_or(Error::Protocol(
        "derive: assertion carried no hmac-secret output",
    ))
}

/// The mandatory-backup completeness rule: an enrollment set is
/// complete only when it holds at least two tokens with DISTINCT
/// credential ids. Duplicate entries for one credential (the
/// same token enrolled twice into the set) do not count.
pub fn enrollment_complete(tokens: &[EnrolledToken]) -> bool {
    let mut distinct = 0usize;
    for (i, t) in tokens.iter().enumerate() {
        if tokens[..i]
            .iter()
            .all(|u| u.credential_id != t.credential_id)
        {
            distinct += 1;
        }
    }
    distinct >= 2
}

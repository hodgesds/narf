//! # narf-ctap2 — FIDO2/CTAP2 client for suspend tokens
//!
//! A transport-agnostic CTAP2 client in the running system:
//! CBOR (RFC 8949 canonical form) + CTAPHID framing + the CTAP2
//! command set the suspend-token flows need —
//! `authenticatorGetInfo`, `authenticatorMakeCredential`,
//! `authenticatorGetAssertion` with the `hmac-secret` extension,
//! and `authenticatorClientPIN` (PIN/UV auth protocol one) for the
//! decided touch+PIN default.
//!
//! Lane P3 of the power-suspend programme (issue #999; design
//! §4/§12). The suspend *service* (lane P1) owns key custody; this
//! crate owns the token conversation only. It exposes the
//! hmac-secret derivation result through the narrow API in
//! [`enroll`]; it never wraps or stores key material.
//!
//! The protocol layer is deliberately split from transport: it
//! runs over any [`ctaphid::HidPipe`]. `drivers/usb` binds the
//! pipe to a real xHCI interrupt endpoint pair; the P5 resume
//! environment can bind the same protocol layer to its polled
//! stack, as design §4.6 intends. The fixture token in
//! [`fixture_token`] (test-only) is a third pipe implementation —
//! an independent, spec-shaped authenticator the fixtures drive
//! the client against.
//!
//! ## Spec sources (everything below derives from these texts)
//!
//! - FIDO2 Client to Authenticator Protocol (CTAP2), W3C/FIDO
//!   Alliance: §5.3/§8 (CBOR), CTAPHID transport section, §6.1
//!   (getInfo), §6.2 (makeCredential), §6.3/§6.4 (getAssertion +
//!   hmac-secret extension), §6.5 (clientPIN + PIN protocol one).
//! - RFC 8949 (CBOR), RFC 8152 (COSE), RFC 2104 (HMAC),
//!   NIST SP 800-38A (AES-CBC), RFC 5903 (P-256 ECDH).
//! - USB HID 1.11 (report transport the CTAPHID layer rides on).

#![no_std]

extern crate alloc;

pub mod cbor;
pub mod client;
pub mod cose;
pub mod crypto;
pub mod ctaphid;
pub mod enroll;
pub mod pin;
pub mod status;

#[cfg(any(test, feature = "fixture-token", feature = "kernel-test"))]
pub mod fixture_token;

#[cfg(any(test, feature = "kernel-test"))]
mod fixture_tests;

pub use client::{Assertion, AuthenticatorInfo, Client, CredentialRef, MakeCredentialResult};
pub use enroll::{derive_slot_output, enroll_token, EnrolledToken, PinSetup};
pub use status::CtapStatus;

/// Randomness the client consumes for ephemeral key agreement.
/// Production binds this to `narf-crypto`'s HW-entropy-gated fill;
/// fixtures bind it to a deterministic source. The client never
/// invents its own entropy.
pub trait RandomSource {
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// Every failure of the client, the framing layer, or the pipe.
/// Authenticator rejections keep their raw status byte — callers
/// match on [`Error::Ctap`] with the [`status`] constants, because
/// the PIN retry semantics the enrollment UX must surface live in
/// those codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The HID pipe itself failed (endpoint error, disconnect).
    Transport,
    /// The exchange exceeded its packet/keepalive bounds.
    Timeout,
    /// CBOR encode/decode failure (ours or the authenticator's).
    Cbor(cbor::CborError),
    /// CTAPHID error frame from the device (payload byte).
    Hid(u8),
    /// CTAP2 status byte (0x00 is success and never appears here).
    Ctap(u8),
    /// The peer sent something structurally valid CBOR but not
    /// valid for the command in flight (missing key, wrong type).
    Protocol(&'static str),
    /// A cryptographic primitive failed (bad peer key, bad length).
    Crypto,
    /// The caller's randomness source failed.
    Random,
    /// The authenticator does not offer a capability the flow
    /// requires (e.g. no `hmac-secret` extension, no clientPIN).
    Unsupported(&'static str),
}

impl From<cbor::CborError> for Error {
    fn from(e: cbor::CborError) -> Self {
        Error::Cbor(e)
    }
}

impl Error {
    /// True when the authenticator rejected a PIN as wrong
    /// (CTAP2_ERR_PIN_INVALID) — the retry counter has decremented
    /// and the caller should surface the remaining count.
    pub fn is_pin_invalid(&self) -> bool {
        matches!(self, Error::Ctap(s) if *s == status::CTAP2_ERR_PIN_INVALID)
    }

    /// True when a presented pinUvAuthParam did not verify against
    /// the issued token (CTAP2_ERR_PIN_AUTH_INVALID) — distinct
    /// from a wrong PIN: the token was fine, the proof was not.
    pub fn is_pin_auth_invalid(&self) -> bool {
        matches!(self, Error::Ctap(s) if *s == status::CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

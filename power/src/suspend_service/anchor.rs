//! The key-custody anchor abstraction (power-suspend design §3.2).
//!
//! The suspend service depends only on this trait. Anchor
//! *implementations* are separate lanes: the FIDO token (P3, #999),
//! TPM sealing (P6, #1002), and the Argon2id passphrase floor (P7,
//! #1004). This lane ships the trait and one fixture-grade test anchor
//! (see `fixtures`), so the service is proven end to end before any
//! real factor lands.
//!
//! Nothing above this trait knows what a TPM or a FIDO token is.

use alloc::vec::Vec;

use super::custody::Secret32;

/// Which implementation backs an anchor. Recorded in slot records so
/// a resume environment can select the matching factor machinery; the
/// `Test` kind is fixture-grade and must never appear in a production
/// policy's slot set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AnchorKind {
    Token,
    Tpm,
    Tee,
    Dice,
    Passphrase,
    Test,
}

impl AnchorKind {
    /// Stable on-disk code for slot records.
    pub fn code(self) -> u8 {
        match self {
            AnchorKind::Token => 1,
            AnchorKind::Tpm => 2,
            AnchorKind::Tee => 3,
            AnchorKind::Dice => 4,
            AnchorKind::Passphrase => 5,
            AnchorKind::Test => 0xff,
        }
    }

    /// Decode an on-disk anchor-kind code. Unknown codes are rejected
    /// (a slot this build cannot name is a slot it must not use).
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(AnchorKind::Token),
            2 => Some(AnchorKind::Tpm),
            3 => Some(AnchorKind::Tee),
            4 => Some(AnchorKind::Dice),
            5 => Some(AnchorKind::Passphrase),
            0xff => Some(AnchorKind::Test),
            _ => None,
        }
    }
}

/// Context for a wrap operation: the SMS epoch the secret belongs
/// to. Anchors that can bind a wrap to the epoch (in their KEK
/// derivation or a PCR-style policy) should do so.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WrapCtx {
    pub sms_epoch: u64,
}

/// Context for an unwrap operation: the SMS epoch the slot record
/// claims. An anchor must refuse a slot whose epoch it cannot honour
/// rather than unwrap it into the wrong epoch's custody.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnwrapCtx {
    pub sms_epoch: u64,
}

/// A wrapped slot secret as produced by an anchor: opaque to the
/// service. `params` carries the anchor's public parameters (slot
/// salt, credential id, KDF parameters — whatever the anchor needs at
/// unwrap time); `blob` is the wrapped secret in the anchor's own
/// framing. The service stamps kind + epoch around it in a
/// [`super::slots::SlotRecord`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSlot {
    pub params: Vec<u8>,
    pub blob: Vec<u8>,
}

/// Anchor failure. `Refused` is the expected shape of a factor that
/// was not satisfied (no user presence, wrong credential, policy
/// mismatch): it is not a malfunction and must not be retried in a
/// hot loop. `Unavailable` means the anchor hardware/path is absent.
/// `Failed` covers everything else, including AEAD failure inside
/// the anchor — a wrong secret and a tampered blob are deliberately
/// indistinguishable at this boundary (no oracle).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AnchorError {
    Refused,
    Unavailable,
    Failed,
}

/// A custody factor: something that can wrap the slot master secret
/// so only it can unwrap it again (design §3.2). Implementations may
/// require user presence or verification inside `unwrap`; the caller
/// drives that interaction.
pub trait KeyCustodyAnchor: Send + Sync {
    /// Which implementation backs this anchor (policy records and
    /// diagnostics).
    fn kind(&self) -> AnchorKind;

    /// Wrap `secret` so only this anchor can unwrap it, bound to the
    /// SMS epoch in `ctx` where the anchor supports binding.
    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError>;

    /// Unwrap a slot previously produced by [`Self::wrap`]. May
    /// require user presence / verification — the resume path drives
    /// the interaction.
    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError>;

    /// Monotonic epoch source, if the anchor has one (TPM NV
    /// counter). Most anchors have none.
    fn epoch(&self) -> Option<u64> {
        None
    }

    /// Advance the anchor's monotonic epoch, if it has one.
    fn advance_epoch(&self) -> Result<Option<u64>, AnchorError> {
        Ok(None)
    }
}

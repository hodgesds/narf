//! SAE finite-cyclic-group identifiers.
//!
//! Values from the IANA "Transform Type 4 - DH Group" registry
//! (originally IKEv2 RFC 7296 §3.3.2; SAE inherits the same numbering
//! via IEEE 802.11-2020 §12.4.4.1).
//!
//! NARF implements Group 19 (NIST P-256) as the floor; SAE-capable APs
//! across the field default to it, and WPA3-Personal certification
//! requires at minimum P-256. Groups 20 (P-384) and 21 (P-521) are
//! enum-recognised but the curve arithmetic is not yet wired — calling
//! into them returns `SaeError::InvalidParameters`.

use super::dragonfly::SaeError;

/// Identifiers SAE recognises on the wire.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SaeGroup {
    /// NIST P-256 (secp256r1). The required-to-implement group for
    /// WPA3-Personal certification.
    P256 = 19,
    /// NIST P-384 (secp384r1). Recognised; arithmetic not yet wired.
    P384 = 20,
    /// NIST P-521 (secp521r1). Recognised; arithmetic not yet wired.
    P521 = 21,
}

impl SaeGroup {
    /// Map a 16-bit wire value to a known group. Returns `None` for
    /// unsupported groups (RSN IE peers may request groups NARF does
    /// not implement; callers should fail negotiation with the wire
    /// status code 77 "Unsupported finite cyclic group" — §9.4.1.9).
    pub fn from_wire(group: u16) -> Option<Self> {
        match group {
            19 => Some(Self::P256),
            20 => Some(Self::P384),
            21 => Some(Self::P521),
            _ => None,
        }
    }

    /// Wire-format identifier.
    pub fn id(&self) -> u16 {
        *self as u16
    }

    /// Length in bytes of the scalar field for this group's order n.
    /// Returns `Err(InvalidParameters)` for unsupported groups.
    pub fn scalar_len(&self) -> Result<usize, SaeError> {
        match self {
            Self::P256 => Ok(32),
            Self::P384 | Self::P521 => Err(SaeError::InvalidParameters),
        }
    }

    /// Length in bytes of an encoded affine element (X || Y).
    pub fn element_len(&self) -> Result<usize, SaeError> {
        match self {
            Self::P256 => Ok(64),
            Self::P384 | Self::P521 => Err(SaeError::InvalidParameters),
        }
    }

    /// True if this group is fully implemented (curve arithmetic +
    /// hash-to-curve + state-machine plumbing all wired).
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::P256)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod group_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sae_group_p256_recognised() -> TestResult {
        // IEEE 802.11-2020 §12.4.4.1: 19 is the P-256 ID.
        let g = match SaeGroup::from_wire(19) {
            Some(g) => g,
            None => return TestResult::Fail("group 19 not recognised"),
        };
        if g.id() != 19 {
            return TestResult::Fail("group id round-trip mismatch");
        }
        if !g.is_supported() {
            return TestResult::Fail("P-256 must be supported");
        }
        if g.scalar_len() != Ok(32) {
            return TestResult::Fail("P-256 scalar should be 32 bytes");
        }
        if g.element_len() != Ok(64) {
            return TestResult::Fail("P-256 element should be 64 bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_group_p256_recognised);

    fn smoke_sae_group_p384_p521_unsupported() -> TestResult {
        // P-384 / P-521 are spec-recognised but NARF doesn't ship the
        // curve arithmetic for them; they return InvalidParameters
        // from scalar_len/element_len.
        let p384 = SaeGroup::from_wire(20).expect("p384 enum");
        let p521 = SaeGroup::from_wire(21).expect("p521 enum");
        if p384.is_supported() || p521.is_supported() {
            return TestResult::Fail("P-384/P-521 must report unsupported");
        }
        if p384.scalar_len().is_ok() || p521.scalar_len().is_ok() {
            return TestResult::Fail("unsupported groups should err on scalar_len");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_group_p384_p521_unsupported);

    fn smoke_sae_group_unknown_returns_none() -> TestResult {
        // 22 onward — not assigned to NIST curves in the IANA registry.
        if SaeGroup::from_wire(22).is_some() {
            return TestResult::Fail("group 22 should not be recognised");
        }
        if SaeGroup::from_wire(0).is_some() {
            return TestResult::Fail("group 0 should not be recognised");
        }
        if SaeGroup::from_wire(999).is_some() {
            return TestResult::Fail("nonsense group should not be recognised");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_group_unknown_returns_none);
}

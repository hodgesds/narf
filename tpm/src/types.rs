#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmError {
    NotPresent,
    LocalityTimeout,
    BusyTimeout,
    NoCommandBuffer,
    BadResponse,
    InvalidArgs,
    Denied,
    HardwareError,
    /// Categorised TPM2 response code (see [`TpmRc`]). Raised when the
    /// TPM returned non-zero `TPM_RC` in the response header. The
    /// 32-bit RC is preserved so debugging hooks can log the exact
    /// bits per TCG Part 2 §6.6.
    Rc(TpmRc),
}

/// Typed categories of TPM 2.0 response codes (TCG Part 2 §6.6 /
/// Part 1 §39). The wire encoding is a single 32-bit `TPM_RC` field
/// whose bits encode error class, parameter / handle / session
/// number, and a vendor flag. Linux's `drivers/char/tpm/tpm2-cmd.c`
/// maps these to subsystem errnos; NARF surfaces a small finite
/// enumeration so callers don't have to memorise the bit layout.
///
/// Encoding (TCG Part 1 §39.4):
///
/// ```text
///   bit 7    = format selector
///   if format == 0:  // legacy / VER1 codes
///     bits 0..6  = base error
///     bit 8      = vendor-defined
///     bits 9..11 = reserved
///   if format == 1:  // FMT1 — per-parameter / per-handle / per-session
///     bits 0..5  = base error
///     bit 6      = parameter-related
///     bits 8..11 = parameter / handle / session number
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmRc {
    /// `TPM_RC_INITIALIZE` (0x100) — TPM not initialised. Linux:
    /// retry after `TPM2_Startup`.
    Initialize,
    /// `TPM_RC_FAILURE` (0x101) — internal TPM failure (selftest).
    Failure,
    /// `TPM_RC_DISABLED` (0x120) — command blocked by current state.
    Disabled,
    /// `TPM_RC_AUTH_FAIL` (0x98E or FMT1+0x0E with session) — bad
    /// auth value / HMAC. Caller should reset session.
    AuthFail,
    /// `TPM_RC_LOCKOUT` (0x921) — dictionary attack lockout active.
    Lockout,
    /// `TPM_RC_RETRY` (0x922) — TPM busy, retry. Linux returns
    /// EAGAIN; callers may resubmit after a short delay.
    Retry,
    /// `TPM_RC_NV_UNAVAILABLE` (0x923) — NV write blocked.
    NvUnavailable,
    /// `TPM_RC_NV_RATE` (0x920) — too many NV writes; back off.
    NvRate,
    /// `TPM_RC_HANDLE` (FMT1 base 0x0B) — invalid handle reference.
    Handle,
    /// `TPM_RC_VALUE` (FMT1 base 0x04) — out-of-range parameter.
    Value,
    /// `TPM_RC_SIZE` (FMT1 base 0x15) — bad command/structure size.
    Size,
    /// `TPM_RC_BAD_TAG` (0x1E) — unrecognised TPM_ST tag.
    BadTag,
    /// Vendor-defined (`TPM_RC_VER1` + bit 10) or unrecognised
    /// numeric code. The raw 32-bit `TPM_RC` is preserved.
    Other(u32),
}

impl TpmRc {
    /// Decode a non-zero `TPM_RC` from a TPM 2.0 response header.
    /// Returns `Other(rc)` for codes we don't categorise so the
    /// caller can still log the raw value.
    ///
    /// Bit layout: TCG Part 1 §39.4. Most-significant byte indexes
    /// into the format-selector / vendor / severity bits; the low
    /// byte carries the base error.
    pub fn from_rc(rc: u32) -> Self {
        // Mask off the LSB used to distinguish error from warning
        // levels (bit 11). We treat warnings (`TPM_RC_WARN`) the
        // same as errors at the rust API surface.
        let v = rc;
        // FMT1 — bit 7 set. The remaining 6 bits (0..5) encode the
        // base error; bits 8..11 carry the parameter/handle/session
        // index which we don't surface at this layer.
        if (v & 0x80) != 0 {
            let base = (v & 0x3F) as u8;
            return match base {
                0x04 => Self::Value,
                0x0B => Self::Handle,
                0x15 => Self::Size,
                _ => Self::Other(rc),
            };
        }
        // VER1 — drop the high-bit (vendor) and severity bits to
        // get the canonical numeric code.
        match v & 0xFFF {
            0x01E => Self::BadTag,
            0x100 => Self::Initialize,
            0x101 => Self::Failure,
            0x120 => Self::Disabled,
            0x18E => Self::AuthFail,
            0x920 => Self::NvRate,
            0x921 => Self::Lockout,
            0x922 => Self::Retry,
            0x923 => Self::NvUnavailable,
            _ => Self::Other(rc),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcrSet(pub u32); // Bitmask of PCRs 0-31

impl PcrSet {
    pub const ALL: Self = Self(u32::MAX);
    pub const NONE: Self = Self(0);

    pub fn contains(self, pcr: u32) -> bool {
        if pcr >= 32 {
            return false;
        }
        (self.0 & (1 << pcr)) != 0
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PolicyHash(pub [u8; 32]);

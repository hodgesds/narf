//! CTAP status codes (FIDO2 CTAP2 specification, status-code
//! table). The first byte of every CTAPHID_CBOR response is one of
//! these; 0x00 is success, everything else is an error whose CBOR
//! body is normally empty.

/// Operation completed successfully.
pub const CTAP1_ERR_SUCCESS: u8 = 0x00;
/// The requested command is not valid on this authenticator.
pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
/// A parameter was malformed or inconsistent.
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
/// A length field was inconsistent with the message.
pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
/// A continuation packet arrived out of sequence.
pub const CTAP1_ERR_INVALID_SEQ: u8 = 0x05;
/// The command timed out on the authenticator.
pub const CTAP1_ERR_TIMEOUT: u8 = 0x06;
/// The channel is locked by another operation.
pub const CTAP1_ERR_CHANNEL_BUSY: u8 = 0x0B;

/// CBOR item had an unexpected major type.
pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
/// CBOR payload was not well-formed.
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
/// A required parameter is missing.
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
/// An internal size/count limit was exceeded.
pub const CTAP2_ERR_LIMIT_EXCEEDED: u8 = 0x15;
/// The authenticator does not support the requested extension.
pub const CTAP2_ERR_UNSUPPORTED_EXTENSION: u8 = 0x16;
/// The credential is on the exclude list.
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
/// The authenticator is busy processing.
pub const CTAP2_ERR_PROCESSING: u8 = 0x21;
/// The credential ID does not identify a credential on this
/// authenticator (or its RP does not match).
pub const CTAP2_ERR_INVALID_CREDENTIAL: u8 = 0x22;
/// Waiting for a user action (touch) to complete.
pub const CTAP2_ERR_USER_ACTION_PENDING: u8 = 0x23;
/// Another operation is still pending.
pub const CTAP2_ERR_OPERATION_PENDING: u8 = 0x24;
/// No operation is pending (for getNextAssertion).
pub const CTAP2_ERR_NO_OPERATIONS: u8 = 0x25;
/// None of the requested algorithms are supported.
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
/// The operation was denied (e.g. user declined, policy refused).
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
/// Credential storage is full.
pub const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
/// The requested operation is not supported on this authenticator.
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
/// An option value was invalid for this authenticator.
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
/// The pending operation was cancelled by a keepalive-cancel.
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
/// No credential matches the request (empty allow list case, or
/// discoverable-credential lookup found none).
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
/// The user did not arrive in time.
pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
/// The operation is not allowed in the current state.
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
/// The supplied PIN was wrong; the retry counter decremented.
pub const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
/// The PIN is blocked until the authenticator is power-cycled.
pub const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
/// A pinUvAuthParam did not verify against the pinUvAuthToken.
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
/// PIN authentication is blocked until power cycle (too many
/// failed token *uses*, as opposed to failed PIN entries).
pub const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
/// No PIN is set on this authenticator.
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
/// A PIN is required for this operation.
pub const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
/// The new PIN violates the authenticator's PIN policy.
pub const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
/// The pinUvAuthToken has expired (authenticator power cycle or
/// timeout); obtain a fresh one.
pub const CTAP2_ERR_PIN_TOKEN_EXPIRED: u8 = 0x38;
/// The request exceeded the authenticator's message-size limit.
pub const CTAP2_ERR_REQUEST_TOO_LARGE: u8 = 0x39;
/// The operation timed out after user-action processing began.
pub const CTAP2_ERR_ACTION_TIMEOUT: u8 = 0x3A;
/// User presence is required but was not provided.
pub const CTAP2_ERR_UP_REQUIRED: u8 = 0x3B;

/// Human-readable name for logs/diagnostics.
pub fn name(code: u8) -> &'static str {
    match code {
        CTAP1_ERR_SUCCESS => "CTAP1_ERR_SUCCESS",
        CTAP1_ERR_INVALID_COMMAND => "CTAP1_ERR_INVALID_COMMAND",
        CTAP1_ERR_INVALID_PARAMETER => "CTAP1_ERR_INVALID_PARAMETER",
        CTAP1_ERR_INVALID_LENGTH => "CTAP1_ERR_INVALID_LENGTH",
        CTAP1_ERR_INVALID_SEQ => "CTAP1_ERR_INVALID_SEQ",
        CTAP1_ERR_TIMEOUT => "CTAP1_ERR_TIMEOUT",
        CTAP1_ERR_CHANNEL_BUSY => "CTAP1_ERR_CHANNEL_BUSY",
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        CTAP2_ERR_INVALID_CBOR => "CTAP2_ERR_INVALID_CBOR",
        CTAP2_ERR_MISSING_PARAMETER => "CTAP2_ERR_MISSING_PARAMETER",
        CTAP2_ERR_LIMIT_EXCEEDED => "CTAP2_ERR_LIMIT_EXCEEDED",
        CTAP2_ERR_UNSUPPORTED_EXTENSION => "CTAP2_ERR_UNSUPPORTED_EXTENSION",
        CTAP2_ERR_CREDENTIAL_EXCLUDED => "CTAP2_ERR_CREDENTIAL_EXCLUDED",
        CTAP2_ERR_PROCESSING => "CTAP2_ERR_PROCESSING",
        CTAP2_ERR_INVALID_CREDENTIAL => "CTAP2_ERR_INVALID_CREDENTIAL",
        CTAP2_ERR_USER_ACTION_PENDING => "CTAP2_ERR_USER_ACTION_PENDING",
        CTAP2_ERR_OPERATION_PENDING => "CTAP2_ERR_OPERATION_PENDING",
        CTAP2_ERR_NO_OPERATIONS => "CTAP2_ERR_NO_OPERATIONS",
        CTAP2_ERR_UNSUPPORTED_ALGORITHM => "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        CTAP2_ERR_OPERATION_DENIED => "CTAP2_ERR_OPERATION_DENIED",
        CTAP2_ERR_KEY_STORE_FULL => "CTAP2_ERR_KEY_STORE_FULL",
        CTAP2_ERR_UNSUPPORTED_OPTION => "CTAP2_ERR_UNSUPPORTED_OPTION",
        CTAP2_ERR_INVALID_OPTION => "CTAP2_ERR_INVALID_OPTION",
        CTAP2_ERR_KEEPALIVE_CANCEL => "CTAP2_ERR_KEEPALIVE_CANCEL",
        CTAP2_ERR_NO_CREDENTIALS => "CTAP2_ERR_NO_CREDENTIALS",
        CTAP2_ERR_USER_ACTION_TIMEOUT => "CTAP2_ERR_USER_ACTION_TIMEOUT",
        CTAP2_ERR_NOT_ALLOWED => "CTAP2_ERR_NOT_ALLOWED",
        CTAP2_ERR_PIN_INVALID => "CTAP2_ERR_PIN_INVALID",
        CTAP2_ERR_PIN_BLOCKED => "CTAP2_ERR_PIN_BLOCKED",
        CTAP2_ERR_PIN_AUTH_INVALID => "CTAP2_ERR_PIN_AUTH_INVALID",
        CTAP2_ERR_PIN_AUTH_BLOCKED => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        CTAP2_ERR_PIN_NOT_SET => "CTAP2_ERR_PIN_NOT_SET",
        CTAP2_ERR_PIN_REQUIRED => "CTAP2_ERR_PIN_REQUIRED",
        CTAP2_ERR_PIN_POLICY_VIOLATION => "CTAP2_ERR_PIN_POLICY_VIOLATION",
        CTAP2_ERR_PIN_TOKEN_EXPIRED => "CTAP2_ERR_PIN_TOKEN_EXPIRED",
        CTAP2_ERR_REQUEST_TOO_LARGE => "CTAP2_ERR_REQUEST_TOO_LARGE",
        CTAP2_ERR_ACTION_TIMEOUT => "CTAP2_ERR_ACTION_TIMEOUT",
        CTAP2_ERR_UP_REQUIRED => "CTAP2_ERR_UP_REQUIRED",
        _ => "CTAP_ERR_UNKNOWN",
    }
}

/// The status type the rest of the crate re-exports for matches!.
pub type CtapStatus = u8;

//! TPM 2.0 command surface — Stage-4 structural shape.
//!
//! Spec: `crypto/specification/spec.md` (Stage-4 TPM 2.0 integration
//! for measured-boot chain). The real implementation needs a TIS
//! (TPM Interface Specification) or CRB transport, event-log
//! parsing, and PCR-extend coordination with `boot/`'s measured-boot
//! chain.
//!
//! Landed here: command/response opcode tables and the
//! `Tpm2Command` enum covering PCR_Extend / PCR_Read / GetRandom —
//! the minimum set a measured-boot chain + attestation flow
//! exercises. Once `arch/` exposes a memory-mapped TPM transport,
//! the handler bodies go here.

use alloc::vec::Vec;

/// TPM 2.0 command code. Values from TCG TPM 2.0 Library Part 2.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmCc {
    PcrExtend = 0x0000_0182,
    PcrRead = 0x0000_017E,
    GetRandom = 0x0000_017B,
    StartAuthSession = 0x0000_0176,
    FlushContext = 0x0000_0165,
    Startup = 0x0000_0144,
    Shutdown = 0x0000_0145,
    SelfTest = 0x0000_0143,
    GetCapability = 0x0000_017A,
}

/// TPM hash algorithm — only the widely-deployed subset.
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmAlgHash {
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Sm3_256 = 0x0012,
}

/// High-level command wrapper. Each variant carries the fields the
/// transport needs to assemble the TPM packet.
#[derive(Clone, Debug)]
pub enum Tpm2Command {
    /// Extend `pcr_index` with a hash over `digest`.
    PcrExtend {
        pcr_index: u32,
        alg: TpmAlgHash,
        digest: Vec<u8>,
    },
    /// Read `pcr_index` with `alg`.
    PcrRead { pcr_index: u32, alg: TpmAlgHash },
    /// Read `bytes` of TPM-generated random data.
    GetRandom { bytes: u16 },
    /// TPM self-test. `full` = full self-test vs incremental.
    SelfTest { full: bool },
    /// Start the TPM; `clear` = TPM2_SU_CLEAR vs STATE.
    Startup { clear: bool },
}

/// TPM 2.0 response status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tpm2Status {
    Ok,
    NotImplemented,
    Unavailable,
    Failure,
}

/// Stub submit entry. Returns `NotImplemented` until the TIS / CRB
/// transport lands in `arch/`.
pub fn submit(_cmd: &Tpm2Command) -> Tpm2Status {
    Tpm2Status::NotImplemented
}

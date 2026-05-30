//! TPM 2.0 PCR (Platform Configuration Register) bank model.
//!
//! PCRs hold cumulative measurements of the platform boot sequence.
//! Each PCR is extended by hashing: `new = H(old || data)`. A set of
//! 24 PCRs per algorithm bank is typical (PCRs 0–23). Multiple banks
//! (SHA-1, SHA-256, SHA-384, SHA-512) may coexist; SHA-256 is the
//! baseline for TPM 2.0 profiles.
//!
//! ## PCR allocation (pcrSelect bitmask)
//!
//! `TPM2_GetCapability(TPM_CAP_PCRS, …)` returns a
//! `TPML_PCR_SELECTION` listing which algorithm banks are active and
//! which PCRs are allocated in each. The `PcrSelection` type here
//! mirrors `TPMS_PCR_SELECTION` on the wire.
//!
//! ## Extend model
//!
//! Measured boot: each boot stage extends a PCR with a hash of the
//! component it just loaded. The final PCR value is a summary of
//! the entire boot chain.
//!
//! ```text
//! PCR[n] ← H(PCR[n] || extend_value)
//! ```
//!
//! ## Reference
//!
//! - TCG TPM Library Spec Part 1 §17.4 (PCR definitions).
//! - TCG PC Client Platform Firmware Profile Spec §3.3 (PCR usage).

/// Number of PCRs per bank on PC-client platforms (TCG PC Client FW §3.3.4).
pub const PCR_COUNT: u32 = 24;

/// Maximum number of bytes in a sizeofSelect bitmask (3 bytes covers 24 PCRs).
pub const PCR_SELECT_BYTES: u8 = 3;

// ── Hash bank sizes (digest bytes) ───────────────────────────────────

/// SHA-1 digest size in bytes.
pub const SHA1_DIGEST_SIZE: usize = 20;
/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;
/// SHA-384 digest size in bytes.
pub const SHA384_DIGEST_SIZE: usize = 48;
/// SHA-512 digest size in bytes.
pub const SHA512_DIGEST_SIZE: usize = 64;

// ── Algorithm-bank selector ───────────────────────────────────────────

/// Hash algorithm bank identifier, mirroring `TPM_ALG_ID` values for
/// hash algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HashBank {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashBank {
    /// The `TPM_ALG_ID` wire value for this bank.
    pub fn alg_id(&self) -> u16 {
        match self {
            HashBank::Sha1 => 0x0004,
            HashBank::Sha256 => 0x000B,
            HashBank::Sha384 => 0x000C,
            HashBank::Sha512 => 0x000D,
        }
    }

    /// Number of bytes in a digest for this bank.
    pub fn digest_size(&self) -> usize {
        match self {
            HashBank::Sha1 => SHA1_DIGEST_SIZE,
            HashBank::Sha256 => SHA256_DIGEST_SIZE,
            HashBank::Sha384 => SHA384_DIGEST_SIZE,
            HashBank::Sha512 => SHA512_DIGEST_SIZE,
        }
    }
}

// ── PCR selection bitmask ─────────────────────────────────────────────

/// `TPMS_PCR_SELECTION` — wire-format PCR selector for one bank.
///
/// `bitmap[0]` covers PCRs 0–7; `bitmap[1]` covers PCRs 8–15;
/// `bitmap[2]` covers PCRs 16–23.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash_alg: u16,
    pub bitmap: [u8; 3],
}

impl PcrSelection {
    /// Create a new selection for a single PCR in the given bank.
    pub fn single(bank: HashBank, pcr: u32) -> Self {
        let mut bitmap = [0u8; 3];
        if pcr < PCR_COUNT {
            bitmap[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        Self {
            hash_alg: bank.alg_id(),
            bitmap,
        }
    }

    /// Create a selection covering all 24 PCRs in the given bank.
    pub fn all(bank: HashBank) -> Self {
        Self {
            hash_alg: bank.alg_id(),
            bitmap: [0xFF, 0xFF, 0xFF],
        }
    }

    /// Create an empty selection (no PCRs selected).
    pub fn none(bank: HashBank) -> Self {
        Self {
            hash_alg: bank.alg_id(),
            bitmap: [0, 0, 0],
        }
    }

    /// Returns `true` if `pcr` is selected in this bitmap.
    pub fn contains(&self, pcr: u32) -> bool {
        if pcr >= PCR_COUNT {
            return false;
        }
        self.bitmap[(pcr / 8) as usize] & (1 << (pcr % 8)) != 0
    }

    /// Encode as a `TPMS_PCR_SELECTION` on the wire:
    /// hashAlg(u16) + sizeofSelect(u8=3) + bitmap(3 bytes).
    pub fn encode(&self) -> [u8; 6] {
        let [h0, h1] = self.hash_alg.to_be_bytes();
        [h0, h1, PCR_SELECT_BYTES, self.bitmap[0], self.bitmap[1], self.bitmap[2]]
    }
}

// ── PCR extend helper ─────────────────────────────────────────────────

/// Build the `TPM2_PCR_Extend` command for a single PCR in the
/// SHA-256 bank. Delegates to `commands::pcr_extend_sha256`.
///
/// This is the primary measured-boot primitive: after loading a
/// component, call `pcr_extend(bank, pcr_index, H(component))` to
/// commit the measurement.
pub fn build_extend_cmd(bank: HashBank, pcr: u32, digest: &[u8]) -> alloc::vec::Vec<u8> {
    super::commands::pcr_extend(pcr, bank.alg_id(), digest)
}

/// Build the `TPM2_PCR_Read` command for one PCR in a given bank.
pub fn build_read_cmd(bank: HashBank, pcr: u32) -> alloc::vec::Vec<u8> {
    let sel = PcrSelection::single(bank, pcr);
    super::commands::pcr_read(sel.hash_alg, &sel.bitmap)
}

/// Build a `TPM2_PCR_Read` command for all 24 PCRs in `bank` using
/// the 3-byte full-coverage bitmask.
pub fn build_read_all_cmd(bank: HashBank) -> alloc::vec::Vec<u8> {
    let sel = PcrSelection::all(bank);
    super::commands::pcr_read(sel.hash_alg, &sel.bitmap)
}
